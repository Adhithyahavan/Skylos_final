"""
AI-SIEM Guardian — System Log Agent
Generates or collects system logs and sends them to the backend.
Caches logs locally when the backend is unreachable and syncs on reconnect.
"""

import json
import os
import random
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

from typing import List, Dict

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")
logger = logging.getLogger("log-agent")

# ── Configuration ────────────────────────────────────────────────
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
INGEST_ENDPOINT = f"{BACKEND_URL}/api/logs/ingest"
BATCH_ENDPOINT = f"{BACKEND_URL}/api/logs/ingest/batch"
CACHE_FILE = Path(__file__).parent / "logs_cache.json"
SEND_INTERVAL = int(os.getenv("LOG_INTERVAL", "5"))  # seconds between log batches

# ── Request headers ──────────────────────────────────────────────
HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": AGENT_API_KEY
}

# ── Simulated data pools ────────────────────────────────────────
USERS = ["admin", "jsmith", "analyst01", "devops", "svc_account", "root", "guest", "dbadmin"]
IPS = [f"192.168.1.{i}" for i in range(1, 60)] + ["10.0.0.5", "172.16.0.99"]
EVENT_TYPES = ["login", "logout", "file_access", "config_change", "error", "security"]


def generate_log() -> Dict:
    """Generate a single simulated log entry."""
    event_type = random.choice(EVENT_TYPES)
    failed = 0
    if event_type == "login":
        # Occasionally generate suspicious logins
        failed = random.choices([0, 1, 2, 3, 5, 8, 12], weights=[40, 20, 15, 10, 8, 5, 2])[0]

    return {
        "user": random.choice(USERS),
        "ip": random.choice(IPS),
        "event_type": event_type,
        "failed_attempts": failed,
        "login_frequency": round(random.uniform(0, 30), 2),
        "ip_activity_rate": round(random.uniform(0, 60), 2),
    }


def load_cache() -> List[Dict]:
    """Load cached logs from disk."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def save_cache(logs: List[Dict]):
    """Persist logs to the local cache file."""
    with open(CACHE_FILE, "w") as f:
        json.dump(logs, f)


def clear_cache():
    """Clear the cache file after successful sync."""
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()


def send_log(log: Dict) -> bool:
    """Send a single log to the backend. Returns True on success."""
    try:
        resp = requests.post(INGEST_ENDPOINT, json=log, headers=HEADERS, timeout=5)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


def send_batch(logs: List[Dict]) -> bool:
    """Send a batch of logs to the backend. Returns True on success."""
    try:
        resp = requests.post(BATCH_ENDPOINT, json=logs, headers=HEADERS, timeout=10)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


def sync_cached_logs():
    """Attempt to send all cached logs to the backend."""
    cached = load_cache()
    if not cached:
        return
    logger.info(f"📤  Syncing {len(cached)} cached logs …")
    if send_batch(cached):
        clear_cache()
        logger.info("✅  Cached logs synced successfully")
    else:
        logger.warning("⚠️  Failed to sync cached logs — will retry later")


def run():
    """Main agent loop: generate → send → cache if needed."""
    logger.info(f"🚀  System Log Agent started (interval={SEND_INTERVAL}s)")
    logger.info(f"📡  Backend: {BACKEND_URL}")

    while True:
        # First, try to sync any cached logs
        sync_cached_logs()

        # Generate a small batch of logs
        batch_size = random.randint(1, 5)
        logs = [generate_log() for _ in range(batch_size)]

        success = True
        for log in logs:
            if not send_log(log):
                success = False
                break

        if success:
            logger.info(f"📨  Sent {batch_size} log(s) to backend")
        else:
            # Cache logs for later
            cached = load_cache()
            cached.extend(logs)
            save_cache(cached)
            logger.warning(f"⚠️  Backend unreachable — cached {len(logs)} log(s) ({len(cached)} total)")

        time.sleep(SEND_INTERVAL)


if __name__ == "__main__":
    run()
