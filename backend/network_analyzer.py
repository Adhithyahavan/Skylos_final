"""
AI-SIEM Guardian — Network Analyzer
Scapy-based packet capture with simulation fallback for Windows/no-Npcap.
"""

import logging
import random
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Set
from collections import defaultdict

from config import settings

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """
    Monitors network traffic and detects suspicious patterns.
    Falls back to simulated data when Scapy real capture is unavailable.
    """

    def __init__(self):
        self.ip_packet_count: Dict[str, int] = defaultdict(int)
        self.ip_bytes: Dict[str, int] = defaultdict(int)
        self.suspicious_ips: Set[str] = set()
        self.capture_available: bool = False
        self._check_capture()

    def _check_capture(self):
        """Check if real packet capture is available."""
        if not settings.ENABLE_REAL_CAPTURE:
            logger.info("Real packet capture disabled — using simulation mode")
            return
        try:
            from scapy.all import sniff
            self.capture_available = True
            logger.info("Scapy real capture available")
        except Exception as e:
            logger.warning(f"Scapy capture not available ({e}) — using simulation mode")
            self.capture_available = False

    def capture_packets(self, count: Optional[int] = None) -> List[Dict]:
        """
        Capture or simulate network packets and return activity summaries.
        """
        count = count or settings.PACKET_COUNT
        if self.capture_available:
            return self._real_capture(count)
        return self._simulate_capture(count)

    def _real_capture(self, count: int) -> List[Dict]:
        """Capture real packets using Scapy."""
        try:
            from scapy.all import sniff, IP, TCP, UDP
            packets = sniff(
                iface=settings.CAPTURE_INTERFACE,
                count=count,
                timeout=10,
            )
            results = []
            for pkt in packets:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
                    size = len(pkt)

                    self.ip_packet_count[src_ip] += 1
                    self.ip_bytes[src_ip] += size

                    results.append({
                        "ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": proto,
                        "packets": self.ip_packet_count[src_ip],
                        "bytes_transferred": size,
                        "suspicious": self._is_suspicious(src_ip),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
            return results
        except Exception as e:
            logger.error(f"Real capture failed: {e}")
            return self._simulate_capture(count)

    def _simulate_capture(self, count: int) -> List[Dict]:
        """Generate simulated network activity for demo purposes."""
        # Simulated IP pool: mix of normal and suspicious IPs
        normal_ips = [f"192.168.1.{i}" for i in range(1, 20)]
        suspicious_source_ips = ["10.0.0.5", "172.16.0.99", "10.0.0.77", "203.0.113.42"]
        all_ips = normal_ips + suspicious_source_ips

        protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
        results = []

        for _ in range(count):
            ip = random.choice(all_ips)
            is_suspicious_ip = ip in suspicious_source_ips

            # Suspicious IPs generate more packets
            pkt_count = random.randint(50, 500) if is_suspicious_ip else random.randint(1, 30)
            byte_count = pkt_count * random.randint(64, 1500)

            self.ip_packet_count[ip] += pkt_count
            self.ip_bytes[ip] += byte_count

            suspicious = is_suspicious_ip or self._is_suspicious(ip)
            if suspicious:
                self.suspicious_ips.add(ip)

            results.append({
                "ip": ip,
                "packets": pkt_count,
                "bytes_transferred": byte_count,
                "protocol": random.choice(protocols),
                "suspicious": suspicious,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return results

    def _is_suspicious(self, ip: str) -> bool:
        """Determine if an IP is suspicious based on activity thresholds."""
        total_packets = self.ip_packet_count.get(ip, 0)
        # Flag IPs with unusually high packet counts
        if total_packets > 1000:
            self.suspicious_ips.add(ip)
            return True
        return ip in self.suspicious_ips

    def get_top_ips(self, limit: int = 10) -> List[Dict]:
        """Return the top IPs ranked by packet count."""
        sorted_ips = sorted(
            self.ip_packet_count.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:limit]
        return [
            {
                "ip": ip,
                "packets": count,
                "bytes": self.ip_bytes.get(ip, 0),
                "suspicious": ip in self.suspicious_ips,
            }
            for ip, count in sorted_ips
        ]

    def get_stats(self) -> Dict:
        """Summary statistics for network activity."""
        total_packets = sum(self.ip_packet_count.values())
        total_bytes = sum(self.ip_bytes.values())
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "unique_ips": len(self.ip_packet_count),
            "suspicious_ips": list(self.suspicious_ips),
            "suspicious_count": len(self.suspicious_ips),
        }

    def reset(self):
        """Reset all counters (useful between capture sessions)."""
        self.ip_packet_count.clear()
        self.ip_bytes.clear()
        self.suspicious_ips.clear()


# Global singleton
network_analyzer = NetworkAnalyzer()
