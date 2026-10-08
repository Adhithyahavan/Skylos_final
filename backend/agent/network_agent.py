"""
AI-SIEM Guardian — Network Agent
Periodically runs network analysis and sends results to the backend.
"""

import os
import time
import logging
import json

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")
logger = logging.getLogger("network-agent")

# ── Configuration ────────────────────────────────────────────────
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
CAPTURE_ENDPOINT = f"{BACKEND_URL}/api/network/capture"
CAPTURE_INTERVAL = int(os.getenv("CAPTURE_INTERVAL", "15"))  # seconds
PACKET_COUNT = int(os.getenv("PACKET_COUNT", "50"))

# ── Request headers ──────────────────────────────────────────────
HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": AGENT_API_KEY
}


def run_capture():
    """Trigger a network capture via the backend API."""
    try:
        resp = requests.post(
            CAPTURE_ENDPOINT,
            params={"count": PACKET_COUNT},
            headers=HEADERS,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            logger.info(f"📡  Captured {data.get('captured', 0)} network events")
            # Log any suspicious activity
            activities = data.get("activities", [])
            suspicious = [a for a in activities if a.get("suspicious")]
            if suspicious:
                logger.warning(f"🚨  {len(suspicious)} suspicious network event(s) detected!")
                for s in suspicious[:5]:
                    logger.warning(f"    → {s['ip']} ({s.get('packets', 0)} packets)")
        else:
            logger.error(f"❌  Capture failed: HTTP {resp.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"❌  Cannot reach backend: {e}")


def run():
    """Main agent loop: capture network data periodically."""
    logger.info(f"🚀  Network Agent started (interval={CAPTURE_INTERVAL}s)")
    logger.info(f"📡  Backend: {BACKEND_URL}")

    while True:
        run_capture()
        time.sleep(CAPTURE_INTERVAL)


if __name__ == "__main__":
    run()
