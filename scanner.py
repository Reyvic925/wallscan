import os
import time
import logging
import asyncio
import aiohttp
import json
import hashlib
import base58
import secrets
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from mnemonic import Mnemonic
from bip32utils import BIP32Key
from eth_keys import keys as EthKeys
from bech32 import bech32_encode, convertbits

# ---------- Configuration from environment ----------
BLOCKCHAIN = os.environ.get("BLOCKCHAIN", "ethereum")        # "bitcoin", "ethereum", "bsc"
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "5"))        # lower to avoid rate limits
MIN_BALANCE = float(os.environ.get("MIN_BALANCE", "0.001"))  # minimum balance to alert
CACHE_TTL = int(os.environ.get("CACHE_TTL", "300"))          # seconds to cache balance

# API keys (optional, free)
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_KEY", "")
BSCSCAN_KEY = os.environ.get("BSCSCAN_KEY", "")

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---------- API Endpoints ----------
BTC_ENDPOINTS = [
    ("mempool", "https://mempool.space/api"),
    ("blockstream", "https://blockstream.info/api"),
    ("blockchain", "https://blockchain.info"),
    ("btc_com", "https://chain.api.btc.com/v3"),
]

ETH_ENDPOINTS = [
    ("etherscan", "https://api.etherscan.io/api"),
    ("blockscout", "https://eth.blockscout.com/api/v1"),
    ("cloudflare", "https://cloudflare-eth.com"),
    ("llama", "https://eth.llamarpc.com"),
    ("publicnode", "https://ethereum.publicnode.com"),
]

BSC_ENDPOINTS = [
    ("bscscan", "https://api.bscscan.com/api"),
    ("blockscout_bsc", "https://bsc.blockscout.com/api/v1"),
    ("binance_rpc", "https://bsc-dataseed.binance.org/"),
    ("binance_rpc2", "https://bsc-dataseed1.binance.org/"),
]

# ---------- API Rotator ----------
class APIRotator:
    def __init__(self, endpoints: List[Tuple[str, str]], failure_cooldown: int = 60):
        self.endpoints = endpoints
        self.failure_cooldown = failure_cooldown
        self.failures = {}  # name -> last_fail_time

    async def get(self, path: str, params: Optional[dict] = None, json_payload: Optional[dict] = None) -> Optional[dict]:
        """
        Try each endpoint in order. Return JSON response on success, else None.
        """
        for name, base in self.endpoints:
            # skip if in cooldown
            if name in self.failures:
                if time.time() - self.failures[name] < self.failure_cooldown:
                    continue
                else:
                    del self.failures[name]

            url = base + path
            try:
                async with aiohttp.ClientSession() as session:
                    if json_payload is not None:
                        async with session.post(url, json=json_payload, timeout=10) as resp:
                            if resp.status == 200:
                                return await resp.json()
                    else:
                        async with session.get(url, params=params, timeout=10) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                # Check for error responses (e.g., Etherscan status=0)
                                if isinstance(data, dict) and data.get('status') == '0':
                                    continue
                                return data
                    self.failures[name] = time.time()
            except Exception:
                self.failures[name] = time.time()
        return None

# ---------- Balance checking functions ----------
async def get_btc_balance(address: str) -> float:
    """Try multiple BTC APIs, return balance in BTC."""
    rotator = APIRotator(BTC_ENDPOINTS)
    for name, base in BTC_ENDPOINTS:
        if name in ("mempool", "blockstream"):
            data = await rotator.get(f"/address/{address}")
            if data:
                return data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8
        elif name == "blockchain":
            data = await rotator.get(f"/rawaddr/{address}")
            if data:
                return data.get('final_balance', 0) / 1e8
        elif name == "btc_com":
            data = await rotator.get(f"/address/{address}")
            if data and data.get('data'):
                return data['data'].get('balance', 0) / 1e8
    return 0.0

async def get_evm_balance(address: str, blockchain: str, api_key: str = "") -> float:
    """Try multiple EVM endpoints, return native balance (ETH/BNB)."""
    if blockchain == "ethereum":
        endpoints = ETH_ENDPOINTS
        symbol = "ETH"
    else:
        endpoints = BSC_ENDPOINTS
        symbol = "BNB"

    rotator = APIRotator(endpoints)
    for name, base in endpoints:
        if name in ("etherscan", "bscscan"):
            params = {
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest",
                "apikey": api_key
            }
            data = await rotator.get("", params=params)
            if data and data.get('status') == '1':
                return int(data['result']) / 1e18
        elif name in ("blockscout", "blockscout_bsc"):
            data = await rotator.get(f"/addresses/{address}/balances")
            if data and isinstance(data, list):
                for item in data:
                    if item.get('token', {}).get('symbol') == symbol:
                        return float(item.get('value', 0)) / 1e18
        elif name in ("cloudflare", "llama", "publicnode", "binance_rpc", "binance_rpc2"):
            payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1}
            data = await rotator.get("", json_payload=payload)
            if data and 'result' in data:
                return int(data['result'], 16) / 1e18
    return 0.0

# ---------- Scanner class ----------
class SimpleWalletScanner:
    def __init__(self):
        self.mnemo = Mnemonic("english")
        self.semaphore = asyncio.Semaphore(MAX_WORKERS)
        self.seen_cache = set()
        self.balance_cache = {}  # address -> (balance, timestamp)
        self.stats = {"checked": 0, "funded": 0}

    def generate_mnemonic(self, strength=128) -> str:
        entropy = secrets.token_bytes(strength // 8)
        return self.mnemo.to_mnemonic(entropy)

    async def derive_addresses(self, mnemonic: str, blockchain: str) -> List[str]:
        try:
            seed = self.mnemo.to_seed(mnemonic)
            root_key = BIP32Key.fromEntropy(seed)
            coin_type = 0 if blockchain == "bitcoin" else (60 if blockchain == "ethereum" else 714)
            addresses = []
            for change in [0]:
                for index in range(20):  # gap limit
                    path_key = root_key \
                        .ChildKey(44 + 0x80000000) \
                        .ChildKey(coin_type + 0x80000000) \
                        .ChildKey(0 + 0x80000000) \
                        .ChildKey(change) \
                        .ChildKey(index)
                    pubkey = path_key.PublicKey()
                    if blockchain == "bitcoin":
                        legacy = self._legacy_address(pubkey)
                        nested = self._nested_segwit_address(pubkey)
                        native = self._native_segwit_address(pubkey)
                        addresses.extend([legacy, nested, native])
                    else:
                        priv = EthKeys.PrivateKey(path_key.PrivateKey())
                        addr = priv.public_key.to_checksum_address()
                        addresses.append(addr)
            return list(set(addresses))  # deduplicate
        except Exception as e:
            logger.error(f"Derivation failed for {mnemonic[:10]}: {e}")
            return []

    # Bitcoin address helpers
    def _legacy_address(self, pubkey):
        sha = hashlib.sha256(pubkey).digest()
        rip = hashlib.new('ripemd160', sha).digest()
        return base58.b58encode_check(b'\x00' + rip).decode('utf-8')

    def _nested_segwit_address(self, pubkey):
        sha = hashlib.sha256(pubkey).digest()
        rip = hashlib.new('ripemd160', sha).digest()
        redeem = b'\x00\x14' + rip
        sha_redeem = hashlib.sha256(redeem).digest()
        rip_redeem = hashlib.new('ripemd160', sha_redeem).digest()
        return base58.b58encode_check(b'\x05' + rip_redeem).decode('utf-8')

    def _native_segwit_address(self, pubkey):
        sha = hashlib.sha256(pubkey).digest()
        rip = hashlib.new('ripemd160', sha).digest()
        data = convertbits(rip, 8, 5)
        return bech32_encode("bc", [0] + data)

    async def get_balances(self, addresses: List[str], blockchain: str) -> Dict[str, float]:
        """Check cache then external API for each address."""
        balances = {}
        to_fetch = []
        now = time.time()
        for addr in addresses:
            if addr in self.balance_cache:
                bal, ts = self.balance_cache[addr]
                if now - ts < CACHE_TTL:
                    balances[addr] = bal
                    continue
            to_fetch.append(addr)

        # Fetch uncached addresses with throttling
        if to_fetch:
            async with self.semaphore:
                for addr in to_fetch:
                    try:
                        if blockchain == "bitcoin":
                            bal = await get_btc_balance(addr)
                        else:
                            api_key = ETHERSCAN_KEY if blockchain == "ethereum" else BSCSCAN_KEY
                            bal = await get_evm_balance(addr, blockchain, api_key)
                        self.balance_cache[addr] = (bal, time.time())
                        balances[addr] = bal
                        await asyncio.sleep(0.05)  # rate limit
                    except Exception as e:
                        logger.debug(f"Balance check failed for {addr}: {e}")
                        balances[addr] = 0.0
        return balances

    async def send_discord_alert(self, mnemonic: str, balances: Dict[str, float], total: float):
        if not DISCORD_WEBHOOK:
            return
        embed = {
            "title": f"💰 Funded Wallet Found! ({BLOCKCHAIN.upper()})",
            "color": 0x00ff00,
            "fields": [
                {"name": "Mnemonic", "value": f"`{mnemonic}`", "inline": False},
                {"name": "Total Balance", "value": f"{total:.8f} {BLOCKCHAIN.upper()}", "inline": True},
                {"name": "Addresses (Top 5)", "value": "\n".join([f"{k}: {v:.8f}" for k, v in list(balances.items())[:5]]), "inline": False},
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
        payload = {"embeds": [embed]}
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(DISCORD_WEBHOOK, json=payload)
            logger.info(f"✅ Discord alert sent for balance {total}")
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")

    async def scan_loop(self):
        while True:
            mnemonic = self.generate_mnemonic()
            if mnemonic in self.seen_cache:
                continue
            self.seen_cache.add(mnemonic)

            addresses = await self.derive_addresses(mnemonic, BLOCKCHAIN)
            if not addresses:
                continue

            balances = await self.get_balances(addresses, BLOCKCHAIN)
            total = sum(balances.values())

            self.stats["checked"] += 1
            if total > MIN_BALANCE:
                self.stats["funded"] += 1
                await self.send_discord_alert(mnemonic, balances, total)
                logger.info(f"💎 Funded! Mnemonic: {mnemonic} | Total: {total} {BLOCKCHAIN.upper()}")

            if self.stats["checked"] % 100 == 0:
                hit_rate = self.stats["funded"] / max(self.stats["checked"], 1) * 1e6
                logger.info(f"📊 {BLOCKCHAIN.upper()} | Checked: {self.stats['checked']} | Funded: {self.stats['funded']} | Rate: {hit_rate:.2f}/M")

            await asyncio.sleep(0.02)

    def start_http_server(self):
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            class HealthHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
            port = int(os.environ.get("PORT", 10000))
            server = HTTPServer(('0.0.0.0', port), HealthHandler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            logger.info(f"🌐 HTTP keep‑alive server on port {port}")
        except Exception as e:
            logger.warning(f"Could not start HTTP server: {e}")

# ---------- Main ----------
async def main():
    scanner = SimpleWalletScanner()
    scanner.start_http_server()

    logger.info(f"🚀 Starting {BLOCKCHAIN.upper()} scanner with {MAX_WORKERS} workers")
    tasks = [asyncio.create_task(scanner.scan_loop()) for _ in range(MAX_WORKERS)]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())