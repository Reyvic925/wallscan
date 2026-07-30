import os
import time
import logging
import asyncio
import aiohttp
import hashlib
import secrets
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

from mnemonic import Mnemonic
from bip32utils import BIP32Key
from eth_keys import keys as EthKeys
from bech32 import bech32_encode, convertbits
from eth_account import Account

Account.enable_unaudited_hdwallet_features()

# ---------- Configuration ----------
BLOCKCHAIN = os.environ.get("BLOCKCHAIN", "ethereum").lower()
SUPPORTED_EVM = [
    "ethereum", "bsc", "polygon", "avalanche", "arbitrum", "optimism",
    "base", "gnosis", "cronos", "fantom", "metis", "moonbeam", "moonriver",
    "celo", "scroll", "linea", "blast", "mantle", "kava", "zksync", "zkevm"
]
if BLOCKCHAIN not in SUPPORTED_EVM and BLOCKCHAIN != "bitcoin":
    raise ValueError(f"BLOCKCHAIN must be one of {SUPPORTED_EVM} or 'bitcoin'")

DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")
if not DISCORD_WEBHOOK:
    raise ValueError("DISCORD_WEBHOOK environment variable is required")

ALERT_MIN_BALANCE = float(os.environ.get("ALERT_MIN_BALANCE", "0.001"))
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN", "300"))
ALERT_MAX_PER_HOUR = int(os.environ.get("ALERT_MAX_PER_HOUR", "5"))

MAX_WORKERS = max(1, int(os.environ.get("MAX_WORKERS", "1")))
CACHE_TTL = int(os.environ.get("CACHE_TTL", "300"))
NUM_ADDRESSES = int(os.environ.get("NUM_ADDRESSES", "1"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))   # new: addresses per batch

# ----- PublicNode RPC endpoints for EVM chains -----
RPC_ENDPOINTS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "bsc":      "https://bsc-rpc.publicnode.com",
    "polygon":  "https://polygon-rpc.publicnode.com",
    "avalanche":"https://avalanche-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "base":     "https://base-rpc.publicnode.com",
    "gnosis":   "https://gnosis-rpc.publicnode.com",
    "cronos":   "https://cronos-rpc.publicnode.com",
    "fantom":   "https://fantom-rpc.publicnode.com",
    "metis":    "https://metis-rpc.publicnode.com",
    "moonbeam": "https://moonbeam-rpc.publicnode.com",
    "moonriver":"https://moonriver-rpc.publicnode.com",
    "celo":     "https://celo-rpc.publicnode.com",
    "scroll":   "https://scroll-rpc.publicnode.com",
    "linea":    "https://linea-rpc.publicnode.com",
    "blast":    "https://blast-rpc.publicnode.com",
    "mantle":   "https://mantle-rpc.publicnode.com",
    "kava":     "https://kava-rpc.publicnode.com",
    "zksync":   "https://zksync-era-rpc.publicnode.com",
    "zkevm":    "https://polygon-zkevm-rpc.publicnode.com",
    # Add more from https://www.publicnode.com/ as needed
}

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

# ---------- Alert Manager ----------
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
            "footer": {"text": f"Scanner v4.0 | {BLOCKCHAIN.upper()}"},
            "timestamp": datetime.utcnow().isoformat()
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10) as resp:
                if resp.status not in (200, 204):
                    raise Exception(f"Discord returned {resp.status}")

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

        # Thread pool for CPU‑bound derivation
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS * 2)

        if BLOCKCHAIN == "bitcoin":
            self.rpc_url = None
        else:
            self.rpc_url = RPC_ENDPOINTS.get(BLOCKCHAIN)
            if not self.rpc_url:
                raise ValueError(f"No RPC endpoint defined for {BLOCKCHAIN}")
            self.coin_type = 60

    def generate_mnemonic(self):
        try:
            entropy = secrets.token_bytes(16)
            return self.mnemo.to_mnemonic(entropy)
        except Exception as e:
            logger.error(f"Mnemonic gen error: {e}")
            return None

    # ---- Synchronous derivation (runs in thread pool) ----
    def _derive_addresses_sync(self, mnemonic: str) -> List[str]:
        addresses = []
        if BLOCKCHAIN == "bitcoin":
            try:
                seed = self.mnemo.to_seed(mnemonic)
                root_key = BIP32Key.fromEntropy(seed)
                for change in (0,):
                    for idx in range(NUM_ADDRESSES):
                        try:
                            child_key = root_key \
                                .ChildKey(44 + 0x80000000) \
                                .ChildKey(0 + 0x80000000) \
                                .ChildKey(0 + 0x80000000) \
                                .ChildKey(change) \
                                .ChildKey(idx)
                            pubkey = child_key.PublicKey()
                            addr = self._native_segwit_address(pubkey)
                            if addr:
                                addresses.append(addr)
                        except Exception as e:
                            logger.error(f"BTC deriv failed idx {idx}: {e}")
                            continue
                return list(set(addresses))
            except Exception as e:
                logger.error(f"BTC derivation error: {e}")
                return []
        else:
            try:
                for change in (0,):
                    for idx in range(NUM_ADDRESSES):
                        path = f"m/44'/{self.coin_type}'/0'/{change}/{idx}"
                        try:
                            account = Account.from_mnemonic(mnemonic, account_path=path)
                            addresses.append(account.address)
                        except Exception as e:
                            logger.error(f"EVM deriv failed at {path}: {e}")
                            continue
                return list(set(addresses))
            except Exception as e:
                logger.error(f"EVM derivation error: {e}")
                return []

    async def derive_addresses(self, mnemonic: str) -> List[str]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, self._derive_addresses_sync, mnemonic)

    def _native_segwit_address(self, pubkey):
        try:
            sha = hashlib.sha256(pubkey).digest()
            rip = hashlib.new('ripemd160', sha).digest()
            data = convertbits(rip, 8, 5)
            return bech32_encode("bc", [0] + data)
        except:
            return None

    # ----- Batch balance fetch (EVM only) -----
    async def _fetch_balances_batch(self, addresses: List[str]) -> Dict[str, float]:
        """Fetch balances for a list of addresses using one JSON-RPC batch request."""
        if not addresses:
            return {}
        # Build batch payload
        payload = []
        for i, addr in enumerate(addresses):
            payload.append({
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [addr, "latest"],
                "id": i
            })
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.rpc_url, json=payload, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        balances = {}
                        for item in data:
                            if 'result' in item and item['id'] < len(addresses):
                                addr = addresses[item['id']]
                                balances[addr] = int(item['result'], 16) / 1e18
                        return balances
                    elif resp.status == 429:
                        # Rate limit – wait and retry once
                        await asyncio.sleep(2)
                        async with session.post(self.rpc_url, json=payload, timeout=10) as retry_resp:
                            if retry_resp.status == 200:
                                data = await retry_resp.json()
                                balances = {}
                                for item in data:
                                    if 'result' in item and item['id'] < len(addresses):
                                        addr = addresses[item['id']]
                                        balances[addr] = int(item['result'], 16) / 1e18
                                return balances
        except Exception as e:
            logger.debug(f"Batch balance error: {e}")
        # On failure, return zero for all
        return {addr: 0.0 for addr in addresses}

    # ----- Get balances with caching and batch fallback -----
    async def get_balances_batch(self, addresses: List[str]) -> Dict[str, float]:
        """Get balances, using cache for known ones, batch-fetch the rest."""
        now = time.time()
        result = {}
        to_fetch = []
        for addr in addresses:
            bal, ts = self.balance_cache.get(addr)
            if bal is not None and now - ts < CACHE_TTL:
                result[addr] = bal
            else:
                to_fetch.append(addr)

        if to_fetch:
            # Fetch uncached addresses in one batch
            fetched = await self._fetch_balances_batch(to_fetch)
            for addr, bal in fetched.items():
                self.balance_cache.set(addr, bal, time.time())
                result[addr] = bal
        return result

    # ----- Bitcoin balance (unchanged, single-address API) -----
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

    # ----- Main scan loop with batching -----
    async def scan_loop(self):
        errors = 0
        pending = []   # list of (mnemonic, addresses_list)
        while not self._shutdown:
            try:
                # Generate a new wallet
                mnemonic = self.generate_mnemonic()
                if not mnemonic:
                    errors += 1
                    if errors > 5:
                        await asyncio.sleep(10)
                        errors = 0
                    continue

                # Check if we've seen this mnemonic before (to avoid duplicates)
                cached, _ = self.seen_cache.get(mnemonic)
                if cached:
                    continue
                self.seen_cache.set(mnemonic, True)

                # Derive addresses (CPU-bound, offloaded)
                try:
                    addresses = await asyncio.wait_for(
                        self.derive_addresses(mnemonic),
                        timeout=15.0
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"⏰ Derivation timeout for {mnemonic[:10]}...")
                    continue

                if not addresses:
                    logger.warning(f"⚠️ No addresses derived for {mnemonic[:10]}...")
                    errors += 1
                    if errors > 5:
                        await asyncio.sleep(5)
                        errors = 0
                    continue

                # Store pending item
                pending.append((mnemonic, addresses))
                errors = 0

                # If we have enough addresses, process the batch
                total_pending_addrs = sum(len(addr_list) for _, addr_list in pending)
                if total_pending_addrs >= BATCH_SIZE:
                    # Collect all unique addresses from pending items
                    all_addrs = []
                    item_map = []   # list of (mnemonic, address_index_start, address_count)
                    for mnemonic, addr_list in pending:
                        start = len(all_addrs)
                        all_addrs.extend(addr_list)
                        item_map.append((mnemonic, start, len(addr_list)))

                    # Fetch balances in one batch
                    balance_map = await self.get_balances_batch(all_addrs)

                    # Process each pending item
                    for mnemonic, start, count in item_map:
                        addr_slice = all_addrs[start:start+count]
                        balances = {addr: balance_map.get(addr, 0.0) for addr in addr_slice}
                        total = sum(balances.values())

                        self.stats['checked'] += 1

                        if total > ALERT_MIN_BALANCE:
                            self.wallet_counter += 1
                            wallet_id = self.wallet_counter
                            self.stats['funded'] += 1
                            logger.info(f"💎 FUNDED! ID:{wallet_id} | Total:{total:.8f} {BLOCKCHAIN.upper()}")
                            await self.alert_mgr.send_alert(mnemonic, balances, total, wallet_id)
                            self.stats['alerts'] += 1

                        # Log progress every 10 wallets
                        if self.stats['checked'] % 10 == 0:
                            rate = self.stats['funded'] / max(self.stats['checked'], 1) * 1e6
                            elapsed = time.time() - self.stats['start_time']
                            logger.info(f"📊 Checked:{self.stats['checked']} | Funded:{self.stats['funded']} | Rate:{rate:.2f}/M | {elapsed:.0f}s elapsed")

                    # Clear pending
                    pending = []

                # Small yield to allow other tasks
                await asyncio.sleep(0.001)

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
        self.executor.shutdown(wait=False)

# ---------- HTTP Server ----------
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, format, *args):
        pass

def start_http_server(port: int):
    server = HTTPServer(('0.0.0.0', port), HealthHandler)
    server.serve_forever()

# ---------- Main ----------
async def main():
    port = int(os.environ.get("PORT", 10000))
    http_thread = threading.Thread(target=start_http_server, args=(port,), daemon=True)
    http_thread.start()
    logger.info(f"🌐 HTTP health server running on port {port}")

    scanner = WalletScanner()
    logger.info(f"🚀 Starting {BLOCKCHAIN.upper()} scanner with Discord alerts")
    logger.info(f"📊 Workers:{MAX_WORKERS} | Min Balance:{ALERT_MIN_BALANCE} | Addresses per wallet:{NUM_ADDRESSES} | Batch size:{BATCH_SIZE}")
    if BLOCKCHAIN != "bitcoin":
        logger.info(f"🔗 Using RPC endpoint: {scanner.rpc_url}")
    else:
        logger.info("🔗 Using mempool.space for Bitcoin")

    # Startup test
    logger.info("🧪 Running startup test...")
    test_mnemonic = scanner.generate_mnemonic()
    if test_mnemonic:
        logger.info(f"✅ Mnemonic generated: {test_mnemonic[:20]}...")
        test_addresses = await scanner.derive_addresses(test_mnemonic)
        logger.info(f"✅ Derived {len(test_addresses)} addresses")
    else:
        logger.error("❌ Failed to generate test mnemonic!")

    if BLOCKCHAIN != "bitcoin":
        test_addr = "0x0000000000000000000000000000000000000000"
        # Test batch endpoint with single address
        balances = await scanner._fetch_balances_batch([test_addr])
        if balances and balances.get(test_addr) is not None:
            logger.info(f"✅ Batch RPC works (balance of null address: {balances[test_addr]:.18f} {BLOCKCHAIN.upper()})")
        else:
            logger.warning("⚠️  Batch RPC failed – check endpoint")

    logger.info("🧪 Startup test complete – starting main loop")

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
