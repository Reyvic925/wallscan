import os
import time
import logging
import asyncio
import aiohttp
import hashlib
import base58
import secrets
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict, deque
from http.server import HTTPServer, BaseHTTPRequestHandler

from mnemonic import Mnemonic
from bip32utils import BIP32Key
from eth_keys import keys as EthKeys
from bech32 import bech32_encode, convertbits

# ---------- Configuration ----------
BLOCKCHAIN = os.environ.get("BLOCKCHAIN", "ethereum").lower()
if BLOCKCHAIN not in ["bitcoin", "ethereum", "bsc"]:
    raise ValueError("BLOCKCHAIN must be 'bitcoin', 'ethereum', or 'bsc'")

DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")
if not DISCORD_WEBHOOK:
    raise ValueError("DISCORD_WEBHOOK environment variable is required")
if not DISCORD_WEBHOOK.startswith("https://discord.com/api/webhooks/"):
    raise ValueError("Invalid DISCORD_WEBHOOK URL")

ALERT_MIN_BALANCE = float(os.environ.get("ALERT_MIN_BALANCE", "0.001"))
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN", "300"))
ALERT_MAX_PER_HOUR = int(os.environ.get("ALERT_MAX_PER_HOUR", "5"))

MAX_WORKERS = max(1, int(os.environ.get("MAX_WORKERS", "3")))
CACHE_TTL = int(os.environ.get("CACHE_TTL", "300"))

# API keys – support multiple keys
def parse_keys(env_var: str) -> List[str]:
    return [k.strip() for k in env_var.split(",") if k.strip()]

if BLOCKCHAIN == "ethereum":
    ETHERSCAN_KEYS = parse_keys(os.environ.get("ETHERSCAN_KEYS", "")) or (
        [os.environ.get("ETHERSCAN_KEY", "")] if os.environ.get("ETHERSCAN_KEY", "") else []
    )
    if not ETHERSCAN_KEYS:
        logging.warning("No Etherscan API keys provided. Rate limits will be strict.")
elif BLOCKCHAIN == "bsc":
    BSCSCAN_KEYS = parse_keys(os.environ.get("BSCSCAN_KEYS", "")) or (
        [os.environ.get("BSCSCAN_KEY", "")] if os.environ.get("BSCSCAN_KEY", "") else []
    )
    if not BSCSCAN_KEYS:
        logging.warning("No BscScan API keys provided. Rate limits will be strict.")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ---------- LRU Cache ----------
class LRUCache:
    def __init__(self, max_size=10000):
        self.cache = OrderedDict()
        self.max_size = max_size

    def get(self, key):
        if key in self.cache:
            value, ts = self.cache[key]
            self.cache.move_to_end(key)
            return value, ts
        return None, None

    def set(self, key, value, ts=None):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = (value, ts or time.time())
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    def clear_expired(self, ttl):
        now = time.time()
        for k in list(self.cache.keys()):
            if now - self.cache[k][1] > ttl:
                del self.cache[k]

# ---------- Key Rotator ----------
class KeyRotator:
    def __init__(self, keys: List[str]):
        self.keys = keys
        self.index = 0
        self._lock = asyncio.Lock()

    async def get_key(self) -> Optional[str]:
        if not self.keys:
            return None
        async with self._lock:
            key = self.keys[self.index]
            self.index = (self.index + 1) % len(self.keys)
            return key

# ---------- Alert Manager (Discord only, in-memory) ----------
class AlertManager:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.running = True
        self.rate_limit = []
        self.last_alerted = {}

    async def start(self):
        asyncio.create_task(self._worker())

    async def stop(self):
        self.running = False

    def _check_rate_limit(self) -> bool:
        now = time.time()
        self.rate_limit = [t for t in self.rate_limit if now - t < 3600]
        if len(self.rate_limit) >= ALERT_MAX_PER_HOUR:
            return False
        self.rate_limit.append(now)
        return True

    def _check_cooldown(self, wallet_id: int) -> bool:
        if wallet_id in self.last_alerted:
            if time.time() - self.last_alerted[wallet_id] < ALERT_COOLDOWN:
                return False
        return True

    async def send_alert(self, mnemonic: str, balances: Dict[str, float], total: float, wallet_id: int):
        await self.queue.put((mnemonic, balances, total, wallet_id))

    async def _worker(self):
        while self.running:
            try:
                mnemonic, balances, total, wallet_id = await asyncio.wait_for(self.queue.get(), timeout=1)
                if not self._check_cooldown(wallet_id):
                    self.queue.task_done()
                    continue
                if not self._check_rate_limit():
                    logger.warning("Alert rate limit reached, skipping")
                    self.queue.task_done()
                    continue
                try:
                    await self._send_discord(mnemonic, balances, total, wallet_id)
                    self.last_alerted[wallet_id] = time.time()
                except Exception as e:
                    logger.error(f"Discord alert failed: {e}")
                self.queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Alert worker error: {e}")
                await asyncio.sleep(1)

    async def _send_discord(self, mnemonic: str, balances: Dict[str, float], total: float, wallet_id: int):
        funded = {k: v for k, v in balances.items() if v > 0}
        embed = {
            "title": f"💰 FUNDED WALLET FOUND! ({BLOCKCHAIN.upper()})",
            "color": 0x00ff00,
            "fields": [
                {"name": "🔑 Mnemonic", "value": f"`{mnemonic}`", "inline": False},
                {"name": "💰 Total Balance", "value": f"{total:.8f} {BLOCKCHAIN.upper()}", "inline": True},
                {"name": "🪙 Addresses with Balance",
                 "value": "\n".join([f"`{addr}`: {bal:.8f}" for addr, bal in list(funded.items())[:10]]),
                 "inline": False},
                {"name": "🆔 Wallet ID", "value": str(wallet_id), "inline": True},
                {"name": "🕐 Found At", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), "inline": True}
            ],
            "footer": {"text": f"Scanner v2.0 | {BLOCKCHAIN.upper()}"},
            "timestamp": datetime.utcnow().isoformat()
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10) as resp:
                if resp.status not in (200, 204):
                    raise Exception(f"Discord returned {resp.status}")

# ---------- API rotator ----------
class APIRotator:
    def __init__(self, endpoints, cooldown=60):
        self.endpoints = endpoints
        self.cooldown = cooldown
        self.failures = {}

    async def get(self, path, params=None, json_payload=None):
        for name, base in self.endpoints:
            if name in self.failures and time.time() - self.failures[name] < self.cooldown:
                continue
            url = base + path
            for attempt in range(3):
                try:
                    async with aiohttp.ClientSession() as session:
                        if json_payload:
                            async with session.post(url, json=json_payload, timeout=15) as resp:
                                if resp.status == 200:
                                    return await resp.json()
                                elif resp.status == 429:
                                    await asyncio.sleep(2 ** attempt)
                                    continue
                        else:
                            async with session.get(url, params=params, timeout=15) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    if isinstance(data, dict) and data.get('status') == '0':
                                        continue
                                    return data
                                elif resp.status == 429:
                                    await asyncio.sleep(2 ** attempt)
                                    continue
                        self.failures[name] = time.time()
                except Exception:
                    self.failures[name] = time.time()
        return None

# ---------- Scanner ----------
class WalletScanner:
    def __init__(self):
        self.mnemo = Mnemonic("english")
        self.semaphore = asyncio.Semaphore(MAX_WORKERS)
        self.alert_mgr = AlertManager()
        self.seen_cache = LRUCache(10000)
        self.balance_cache = LRUCache(5000)
        self.stats = {"checked": 0, "funded": 0, "alerts": 0, "start_time": time.time()}
        self._shutdown = False
        self.wallet_counter = 0

        if BLOCKCHAIN == "ethereum":
            self.key_rotator = KeyRotator(ETHERSCAN_KEYS if 'ETHERSCAN_KEYS' in globals() else [])
        elif BLOCKCHAIN == "bsc":
            self.key_rotator = KeyRotator(BSCSCAN_KEYS if 'BSCSCAN_KEYS' in globals() else [])
        else:
            self.key_rotator = None

    def generate_mnemonic(self):
        try:
            entropy = secrets.token_bytes(16)
            return self.mnemo.to_mnemonic(entropy)
        except Exception as e:
            logger.error(f"Mnemonic gen error: {e}")
            return None

    async def derive_addresses(self, mnemonic: str):
        try:
            seed = self.mnemo.to_seed(mnemonic)
            root_key = BIP32Key.fromEntropy(seed)
            coin_type = 0 if BLOCKCHAIN == "bitcoin" else (60 if BLOCKCHAIN == "ethereum" else 714)
            addresses = []
            for change in (0,):
                for idx in range(20):
                    try:
                        child_key = root_key \
                            .ChildKey(44 + 0x80000000) \
                            .ChildKey(coin_type + 0x80000000) \
                            .ChildKey(0 + 0x80000000) \
                            .ChildKey(change) \
                            .ChildKey(idx)
                        pubkey = child_key.PublicKey()
                        if BLOCKCHAIN == "bitcoin":
                            addr = self._native_segwit_address(pubkey)
                            if addr:
                                addresses.append(addr)
                        else:
                            priv = EthKeys.PrivateKey(child_key.PrivateKey())
                            addr = priv.public_key.to_checksum_address()
                            addresses.append(addr)
                    except Exception as e:
                        logger.debug(f"Failed to derive address at index {idx}: {e}")
                        continue
            return list(set(addresses))
        except Exception as e:
            logger.error(f"Derivation error: {e}")
            return []

    def _native_segwit_address(self, pubkey):
        try:
            sha = hashlib.sha256(pubkey).digest()
            rip = hashlib.new('ripemd160', sha).digest()
            data = convertbits(rip, 8, 5)
            return bech32_encode("bc", [0] + data)
        except:
            return None

    async def get_balances(self, addresses):
        balances = {}
        to_fetch = []
        now = time.time()
        for addr in addresses:
            bal, ts = self.balance_cache.get(addr)
            if bal is not None and now - ts < CACHE_TTL:
                balances[addr] = bal
            else:
                to_fetch.append(addr)

        if to_fetch:
            async with self.semaphore:
                for addr in to_fetch:
                    try:
                        if BLOCKCHAIN == "bitcoin":
                            bal = await self._btc_balance(addr)
                        else:
                            key = await self.key_rotator.get_key() if self.key_rotator else ""
                            bal = await self._evm_balance(addr, key)
                        self.balance_cache.set(addr, bal, time.time())
                        balances[addr] = bal
                        await asyncio.sleep(0.1)
                    except Exception as e:
                        logger.debug(f"Balance check failed for {addr}: {e}")
                        balances[addr] = 0.0
        return balances

    async def _btc_balance(self, addr):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://mempool.space/api/address/{addr}", timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8
        except:
            pass
        return 0.0

    async def _evm_balance(self, addr, key):
        base = "https://api.etherscan.io/api" if BLOCKCHAIN == "ethereum" else "https://api.bscscan.com/api"
        params = {
            "module": "account",
            "action": "balance",
            "address": addr,
            "tag": "latest",
            "apikey": key
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(base, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('status') == '1':
                            return int(data['result']) / 1e18
        except:
            pass
        return 0.0

    async def scan_loop(self):
        errors = 0
        while not self._shutdown:
            try:
                mnemonic = self.generate_mnemonic()
                if not mnemonic:
                    errors += 1
                    if errors > 5:
                        await asyncio.sleep(10)
                        errors = 0
                    continue
                cached, _ = self.seen_cache.get(mnemonic)
                if cached:
                    continue
                self.seen_cache.set(mnemonic, True)
                addresses = await self.derive_addresses(mnemonic)
                if not addresses:
                    errors += 1
                    if errors > 5:
                        await asyncio.sleep(5)
                        errors = 0
                    continue
                balances = await self.get_balances(addresses)
                total = sum(balances.values())
                self.stats['checked'] += 1
                errors = 0
                funded = total > ALERT_MIN_BALANCE
                if funded:
                    self.wallet_counter += 1
                    wallet_id = self.wallet_counter
                    self.stats['funded'] += 1
                    logger.info(f"💎 FUNDED! ID:{wallet_id} | Total:{total:.8f} {BLOCKCHAIN.upper()}")
                    await self.alert_mgr.send_alert(mnemonic, balances, total, wallet_id)
                    self.stats['alerts'] += 1
                if self.stats['checked'] % 100 == 0:
                    rate = self.stats['funded'] / max(self.stats['checked'], 1) * 1e6
                    logger.info(f"📊 Checked:{self.stats['checked']} | Funded:{self.stats['funded']} | Rate:{rate:.2f}/M")
                await asyncio.sleep(0.02)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scan loop error: {e}")
                errors += 1
                if errors > 10:
                    await asyncio.sleep(30)
                    errors = 0

    async def monitor(self):
        while not self._shutdown:
            await asyncio.sleep(300)
            logger.info(f"📊 Health: Checked={self.stats['checked']}, Funded={self.stats['funded']}, Alerts={self.stats['alerts']}")
            self.balance_cache.clear_expired(CACHE_TTL)
            self.seen_cache.clear_expired(86400)

    def stop(self):
        self._shutdown = True

# ---------- Simple HTTP Server (for Render health checks) ----------
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, format, *args):
        pass  # suppress logs

def start_http_server(port: int):
    server = HTTPServer(('0.0.0.0', port), HealthHandler)
    server.serve_forever()

# ---------- Main ----------
async def main():
    # Start HTTP server in a background thread
    port = int(os.environ.get("PORT", 10000))
    http_thread = threading.Thread(target=start_http_server, args=(port,), daemon=True)
    http_thread.start()
    logger.info(f"🌐 HTTP health server running on port {port}")

    scanner = WalletScanner()
    logger.info(f"🚀 Starting {BLOCKCHAIN.upper()} scanner with Discord alerts (in-memory)")
    if scanner.key_rotator:
        logger.info(f"🔑 Loaded {len(scanner.key_rotator.keys)} API keys for rotation")
    else:
        logger.info("ℹ️  No API keys loaded (Bitcoin mode or keys missing)")
    logger.info(f"📊 Workers:{MAX_WORKERS} | Min Balance:{ALERT_MIN_BALANCE} | Cooldown:{ALERT_COOLDOWN}s")
    await scanner.alert_mgr.start()
    monitor_task = asyncio.create_task(scanner.monitor())
    tasks = [asyncio.create_task(scanner.scan_loop()) for _ in range(MAX_WORKERS)]
    try:
        await asyncio.gather(*tasks, monitor_task)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        scanner.stop()
        await scanner.alert_mgr.stop()
        for t in tasks + [monitor_task]:
            t.cancel()
        await asyncio.gather(*tasks + [monitor_task], return_exceptions=True)

if __name__ == "__main__":
    asyncio.run(main())
