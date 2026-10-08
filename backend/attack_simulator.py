"""
AI-SIEM Guardian — Attack Simulator
Simulates various cyber attacks for testing the detection pipeline.
"""

import random
import logging
from datetime import datetime, timezone
from typing import List, Dict

logger = logging.getLogger(__name__)

# ── IP pools for simulation ──────────────────────────────────────
ATTACKER_IPS = [
    "10.0.0.5", "10.0.0.77", "172.16.0.99", "203.0.113.42",
    "198.51.100.23", "45.33.32.156", "185.220.101.1",
]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(1, 50)]
USERS = ["admin", "root", "jsmith", "analyst01", "svc_account", "devops", "guest"]
LOCATIONS = ["US", "RU", "CN", "DE", "BR", "IN", "KR", "NG"]


def simulate_brute_force(num_attempts: int = 10) -> List[Dict]:
    """
    Simulate a brute-force login attack:
    Multiple failed attempts from the same IP targeting the same user.
    """
    ip = random.choice(ATTACKER_IPS)
    target_user = random.choice(["admin", "root"])
    logs = []
    for i in range(num_attempts):
        logs.append({
            "user": target_user,
            "ip": ip,
            "event_type": "login",
            "failed_attempts": i + 1,
            "login_frequency": num_attempts * 2,
            "ip_activity_rate": num_attempts * 5,
            "raw_data": f"Brute-force attempt {i + 1}/{num_attempts}",
        })
    logger.info(f"Simulated brute-force: {num_attempts} attempts from {ip}")
    return logs


def simulate_port_scan() -> List[Dict]:
    """
    Simulate a port scanning attack:
    Rapid connections to many ports from a single IP.
    """
    ip = random.choice(ATTACKER_IPS)
    ports = random.sample(range(1, 65535), random.randint(20, 50))
    logs = []
    for port in ports:
        logs.append({
            "user": None,
            "ip": ip,
            "event_type": "port_scan",
            "failed_attempts": 0,
            "login_frequency": 0,
            "ip_activity_rate": len(ports) * 3,
            "raw_data": f"Port scan on port {port}",
        })
    logger.info(f"Simulated port scan: {len(ports)} ports from {ip}")
    return logs


def simulate_credential_stuffing(num_attempts: int = 15) -> List[Dict]:
    """
    Simulate credential stuffing:
    Many login attempts with different usernames from the same IP.
    """
    ip = random.choice(ATTACKER_IPS)
    logs = []
    for _ in range(num_attempts):
        logs.append({
            "user": random.choice(USERS),
            "ip": ip,
            "event_type": "login",
            "failed_attempts": random.randint(1, 3),
            "login_frequency": num_attempts,
            "ip_activity_rate": num_attempts * 4,
            "raw_data": "Credential stuffing attempt",
        })
    logger.info(f"Simulated credential stuffing: {num_attempts} attempts from {ip}")
    return logs


def simulate_geo_anomaly() -> List[Dict]:
    """
    Simulate suspicious location change:
    Same user logging in from drastically different locations in a short time.
    """
    user = random.choice(USERS)
    loc1, loc2 = random.sample(LOCATIONS, 2)
    logs = [
        {
            "user": user,
            "ip": random.choice(NORMAL_IPS),
            "event_type": "geo_anomaly",
            "failed_attempts": 0,
            "login_frequency": 5,
            "ip_activity_rate": 10,
            "raw_data": f"Login from {loc1}",
        },
        {
            "user": user,
            "ip": random.choice(ATTACKER_IPS),
            "event_type": "geo_anomaly",
            "failed_attempts": 0,
            "login_frequency": 5,
            "ip_activity_rate": 10,
            "raw_data": f"Login from {loc2} (impossible travel)",
        },
    ]
    logger.info(f"Simulated geo anomaly: {user} from {loc1} → {loc2}")
    return logs


def simulate_high_frequency(num_attempts: int = 25) -> List[Dict]:
    """
    Simulate high-frequency login attempts:
    Abnormally rapid login requests from a single source.
    """
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(USERS)
    logs = []
    for _ in range(num_attempts):
        logs.append({
            "user": user,
            "ip": ip,
            "event_type": "login",
            "failed_attempts": random.randint(0, 2),
            "login_frequency": num_attempts * 3,
            "ip_activity_rate": num_attempts * 6,
            "raw_data": "High frequency login attempt",
        })
    logger.info(f"Simulated high-frequency: {num_attempts} rapid logins from {ip}")
    return logs


def run_random_attack() -> List[Dict]:
    """Run a random attack simulation and return the generated logs."""
    attack_fn = random.choice([
        simulate_brute_force,
        simulate_port_scan,
        simulate_credential_stuffing,
        simulate_geo_anomaly,
        simulate_high_frequency,
    ])
    return attack_fn()


def run_all_attacks() -> List[Dict]:
    """Run all attack types and return combined logs."""
    all_logs = []
    all_logs.extend(simulate_brute_force())
    all_logs.extend(simulate_port_scan())
    all_logs.extend(simulate_credential_stuffing())
    all_logs.extend(simulate_geo_anomaly())
    all_logs.extend(simulate_high_frequency())
    return all_logs
