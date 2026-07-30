import os
import time
import logging
import asyncio
import aiohttp
import json
import hashlib
import base58
import secrets
import sqlite3
import threading
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict
from contextlib import contextmanager

from mnemonic import Mnemonic
from bip32 import BIP32
from eth_keys import keys as EthKeys
from bech32 import bech32_encode, convertbits

# ---------- Configuration ----------
BLOCKCHAIN = os.environ.get("BLOCKCHAIN", "ethereum").lower()
if BLOCKCHAIN not in ["bitcoin", "ethereum", "bsc"]:
    raise ValueError("BLOCKCHAIN must be 'bitcoin', 'ethereum', or 'bsc'")

# Discord alert (required)
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")
if not DISCORD_WEBHOOK:
    raise ValueError("DISCORD_WEBHOOK environment variable is required")
if not DISCORD_WEBHOOK.startswith("https://discord.com/api/webhooks/"):
    raise ValueError("Invalid DISCORD_WEBHOOK URL")

# Alert settings
ALERT_MIN_BALANCE = float(os.environ.get("ALERT_MIN_BALANCE", "0.001"))
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN", "300"))      # seconds
ALERT_MAX_PER_HOUR = int(os.environ.get("ALERT_MAX_PER_HOUR", "5"))

# Performance
MAX_WORKERS = max(1, int(os.environ.get("MAX_WORKERS", "3")))
CACHE_TTL = int(os.environ.get("CACHE_TTL", "300"))

# API Keys
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_KEY", "")
BSCSCAN_KEY = os.environ.get("BSCSCAN_KEY", "")
if BLOCKCHAIN in ["ethereum", "bsc"] and not (ETHERSCAN_KEY if BLOCKCHAIN == "ethereum" else BSCSCAN_KEY):
    logging.warning(f"No API key provided for {BLOCKCHAIN}. Rate limits will be strict.")

# Database
DATABASE_PATH = os.environ.get("DATABASE_PATH", "wallet_scanner.db")
MONITORING_INTERVAL = int(os.environ.get("MONITORING_INTERVAL", "300"))

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('scanner.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ---------- Database ----------
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def get_connection(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def _init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mnemonic TEXT UNIQUE NOT NULL,
                    blockchain TEXT NOT NULL,
                    total_balance REAL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    check_count INTEGER DEFAULT 1,
                    is_funded BOOLEAN DEFAULT 0,
                    last_alerted TIMESTAMP,
                    alert_count INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    balance REAL DEFAULT 0,
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE CASCADE,
                    UNIQUE(wallet_id, address)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet_id INTEGER NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1,
                    error_message TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_checked INTEGER DEFAULT 0,
                    total_funded INTEGER DEFAULT 0,
                    total_alerts_sent INTEGER DEFAULT 0,
                    scan_rate REAL DEFAULT 0,
                    error_rate REAL DEFAULT 0,
                    memory_usage_mb REAL DEFAULT 0,
                    cpu_percent REAL DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    error_type TEXT NOT NULL,
                    error_message TEXT,
                    stack_trace TEXT,
                    context TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallets_funded ON wallets(is_funded)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallets_last_alerted ON wallets(last_alerted)")

    def save_wallet(self, mnemonic: str, balances: Dict[str, float], total: float, is_funded: bool):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO wallets (mnemonic, blockchain, total_balance, last_checked, check_count, is_funded)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, 1, ?)
                ON CONFLICT(mnemonic) DO UPDATE SET
                    total_balance = excluded.total_balance,
                    last_checked = CURRENT_TIMESTAMP,
                    check_count = check_count + 1,
                    is_funded = excluded.is_funded
            """, (mnemonic, BLOCKCHAIN, total, 1 if is_funded else 0))
            wallet_id = cursor.lastrowid
            if not wallet_id:
                cursor.execute("SELECT id FROM wallets WHERE mnemonic = ?", (mnemonic,))
                row = cursor.fetchone()
                wallet_id = row['id'] if row else None
            if wallet_id:
                for address, balance in balances.items():
                    cursor.execute("""
                        INSERT INTO addresses (wallet_id, address, balance, last_checked)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(wallet_id, address) DO UPDATE SET
                            balance = excluded.balance,
                            last_checked = CURRENT_TIMESTAMP
                    """, (wallet_id, address, balance))
            return wallet_id

    def update_alert_record(self, wallet_id: int, success: bool, error_msg: str = ""):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (wallet_id, success, error_message)
                VALUES (?, ?, ?)
            """, (wallet_id, success, error_msg))
            if success:
                cursor.execute("""
                    UPDATE wallets SET last_alerted = CURRENT_TIMESTAMP, alert_count = alert_count + 1
                    WHERE id = ?
                """, (wallet_id,))

    def should_alert_wallet(self, wallet_id: int) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT last_alerted FROM wallets WHERE id = ?", (wallet_id,))
            row = cursor.fetchone()
            if row and row['last_alerted']:
                last_alert = datetime.fromisoformat(row['last_alerted'])
                if (datetime.now() - last_alert).seconds < ALERT_COOLDOWN:
                    return False
            return True

    def get_recent_alerts(self, limit: int = 5):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT w.mnemonic, w.total_balance, a.timestamp
                FROM alerts a JOIN wallets w ON a.wallet_id = w.id
                WHERE a.success = 1
                ORDER BY a.timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_alert_count_last_hour(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count FROM alerts
                WHERE timestamp > datetime('now', '-1 hour')
            """)
            row = cursor.fetchone()
            return row['count'] if row else 0

    def log_error(self, error_type: str, message: str, stack: str = "", context: str = ""):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO errors (error_type, error_message, stack_trace, context)
                VALUES (?, ?, ?, ?)
            """, (error_type, message, stack, context))

# ---------- Alert Manager (Discord only) ----------
class AlertManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.queue = asyncio.Queue()
        self.running = True
        self.rate_limit = []   # timestamps of sent alerts in last hour

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

    async def send_alert(self, mnemonic: str, balances: Dict[str, float], total: float, wallet_id: int):
        await self.queue.put((mnemonic, balances, total, wallet_id))

    async def _worker(self):
        while self.running:
            try:
                mnemonic, balances, total, wallet_id = await asyncio.wait_for(self.queue.get(), timeout=1)
                if not self.db.should_alert_wallet(wallet_id):
                    self.queue.task_done()
                    continue
                if not self._check_rate_limit():
                    logger.warning("Alert rate limit reached, skipping")
                    self.queue.task_done()
                    continue
                # Send Discord
                try:
                    await self._send_discord(mnemonic, balances, total, wallet_id)
                    self.db.update_alert_record(wallet_id, True)
                except Exception as e:
                    logger.error(f"Discord alert failed: {e}")
                    self.db.update_alert_record(wallet_id, False, str(e))
                self.queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Alert worker error: {e}")
                await asyncio.sleep(1)

    async def _send_discord(self, mnemonic: str, balances: Dict[str, float], total: float, wallet_id: int):
        funded = {k: v for k, v in balances.items() if v > 0}
        recent = self.db.get_recent_alerts(5)
        recent_text = "\n".join([
            f"• {w['mnemonic'][:20]}... ({w['total_balance']:.8f} {BLOCKCHAIN.upper()})"
            for w in recent
        ]) if recent else "None"

        embed = {
            "title": f"💰 FUNDED WALLET FOUND! ({BLOCKCHAIN.upper()})",
            "color": 0x00ff00,
            "fields": [
                {"name": "🔑 Mnemonic", "value": f"`{mnemonic}`", "inline": False},
                {"name": "💰 Total Balance", "value": f"{total:.8f} {BLOCKCHAIN.upper()}", "inline": True},
                {"name": "🪙 Addresses with Balance",
                 "value": "\n".join([f"`{addr}`: {bal:.8f}" for addr, bal in list(funded.items())[:10]]),
                 "inline": False},
                {"name": "📊 Recent Alerts", "value": recent_text, "inline": False},
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

# ---------- API rotator (simplified) ----------
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
        self.db = DatabaseManager(DATABASE_PATH)
        self.alert_mgr = AlertManager(self.db)
        self.seen_cache = LRUCache(10000)
        self.balance_cache = LRUCache(5000)
        self.stats = {"checked": 0, "funded": 0, "alerts": 0, "start_time": time.time()}
        self._stats_lock = threading.Lock()
        self._shutdown = False
        self.last_monitoring = time.time()
        self.last_checked = 0

    def _update_stats(self, **kwargs):
        with self._stats_lock:
            for k, v in kwargs.items():
                if k in self.stats:
                    self.stats[k] += v

    def _get_stats(self):
        with self._stats_lock:
            return self.stats.copy()

    def generate_mnemonic(self):
        try:
            entropy = secrets.token_bytes(16)
            return self.mnemo.to_mnemonic(entropy)
        except Exception as e:
            self.db.log_error("MnemonicGen", str(e))
            return None

    async def derive_addresses(self, mnemonic: str):
        try:
            seed = self.mnemo.to_seed(mnemonic)
            root = BIP32.from_seed(seed)
            coin_type = 0 if BLOCKCHAIN == "bitcoin" else (60 if BLOCKCHAIN == "ethereum" else 714)
            addresses = []
            for change in (0,):
                for idx in range(20):
                    path = f"m/44'/{coin_type}'/0'/{change}/{idx}"
                    child = root.derive_path(path)
                    pub = child.public_key
                    if BLOCKCHAIN == "bitcoin":
                        addr = self._native_segwit(pub)
                        if addr:
                            addresses.append(addr)
                    else:
                        priv = EthKeys.PrivateKey(child.private_key)
                        addresses.append(priv.public_key.to_checksum_address())
            return list(set(addresses))
        except Exception as e:
            self.db.log_error("Derivation", str(e), context=f"mnemonic: {mnemonic[:20]}...")
            return []

    def _native_segwit(self, pubkey):
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
                            key = ETHERSCAN_KEY if BLOCKCHAIN == "ethereum" else BSCSCAN_KEY
                            bal = await self._evm_balance(addr, key)
                        self.balance_cache.set(addr, bal, time.time())
                        balances[addr] = bal
                        await asyncio.sleep(0.1)
                    except Exception as e:
                        self.db.log_error("BalanceCheck", str(e), context=f"addr:{addr}")
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
        params = {"module":"account","action":"balance","address":addr,"tag":"latest","apikey":key}
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
                self._update_stats(checked=1)
                errors = 0
                funded = total > ALERT_MIN_BALANCE
                wallet_id = self.db.save_wallet(mnemonic, balances, total, funded)
                if funded and wallet_id:
                    self._update_stats(funded=1)
                    logger.info(f"💎 FUNDED! ID:{wallet_id} | Total:{total:.8f} {BLOCKCHAIN.upper()}")
                    await self.alert_mgr.send_alert(mnemonic, balances, total, wallet_id)
                    self._update_stats(alerts=1)
                if self.stats['checked'] % 100 == 0:
                    rate = self.stats['funded'] / max(self.stats['checked'],1) * 1e6
                    logger.info(f"📊 Checked:{self.stats['checked']} | Funded:{self.stats['funded']} | Rate:{rate:.2f}/M")
                await asyncio.sleep(0.02)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scan loop error: {e}")
                self.db.log_error("ScanLoop", str(e))
                errors += 1
                if errors > 10:
                    await asyncio.sleep(30)
                    errors = 0

    async def monitor(self):
        while not self._shutdown:
            await asyncio.sleep(MONITORING_INTERVAL)
            try:
                now = time.time()
                dt = now - self.last_monitoring
                if dt > 0:
                    rate = (self.stats['checked'] - self.last_checked) / dt
                else:
                    rate = 0
                mem = psutil.Process().memory_info().rss / 1024 / 1024
                cpu = psutil.Process().cpu_percent()
                logger.info(f"📊 Health: {self.stats['checked']} checked, {rate:.2f}/s, {mem:.1f}MB, CPU:{cpu:.1f}%")
                self.last_monitoring = now
                self.last_checked = self.stats['checked']
                self.balance_cache.clear_expired(CACHE_TTL)
                self.seen_cache.clear_expired(86400)
            except Exception as e:
                logger.error(f"Monitor error: {e}")

    def stop(self):
        self._shutdown = True

# ---------- Main ----------
async def main():
    scanner = WalletScanner()
    logger.info(f"🚀 Starting {BLOCKCHAIN.upper()} scanner with Discord alerts only")
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
