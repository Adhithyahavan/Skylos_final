"""
Skylos — Event Normalization

Converts source-specific telemetry into the canonical SecurityEvent model.
Normalizers are pure: they validate and build objects but never write to the
database; the ingestion pipeline owns the transaction.

Current sources:
  * agent_log         — system-log agents via POST /api/logs/ingest[/batch]
  * attack_simulator  — synthetic attack logs (always marked simulated)

Honesty rules for the agent log format (`skylos.agent_log.v1`):
  * It carries no event time, so `timestamp` is the ingestion time and
    attributes.timestamp_source = "ingestion".
  * It carries no explicit success/failure field, so `outcome` is "unknown";
    `failed_attempts` is preserved in attributes rather than interpreted.
  * It carries no stable event identifier, so retries cannot be recognized by
    source ID. Uniqueness is enforced per raw record (raw_event_reference).
"""

import ipaddress
import math
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from models import Log, SecurityEvent

AGENT_LOG_FORMAT = "skylos.agent_log.v1"

SOURCE_AGENT_LOG = "agent_log"
SOURCE_ATTACK_SIMULATOR = "attack_simulator"

# Agent event_type → (normalized event_type, action). Unmapped types fall back to
# ("system_event", <original>) and the original is always kept in attributes.
AGENT_EVENT_TYPE_MAP = {
    "login": ("authentication", "login"),
    "logout": ("authentication", "logout"),
    "file_access": ("file_access", "access"),
    "config_change": ("configuration_change", "modify"),
    "error": ("system_error", "error"),
    "security": ("security_notice", "notice"),
}

_NUMERIC_FIELDS = ("failed_attempts", "login_frequency", "ip_activity_rate")


class EventNormalizationError(ValueError):
    """Input could not be normalized. Message is safe to return to the client."""


@dataclass(frozen=True)
class IngestionSource:
    """Who delivered the telemetry and how (provenance, not event content)."""
    source_type: str
    channel: str
    simulated: bool = False
    source_id: Optional[str] = None      # no per-agent identity exists yet (shared agent key)
    peer_address: Optional[str] = None   # network peer that delivered the request


def agent_source(peer_address: Optional[str]) -> IngestionSource:
    return IngestionSource(source_type=SOURCE_AGENT_LOG, channel="agent_api", peer_address=peer_address)


def simulator_source() -> IngestionSource:
    return IngestionSource(source_type=SOURCE_ATTACK_SIMULATOR, channel="attack_simulator", simulated=True)


def _validated_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise EventNormalizationError("field 'ip' is not a valid IP address") from None


def _validated_number(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EventNormalizationError(f"field '{name}' must be a number")
    if not math.isfinite(value) or value < 0:
        raise EventNormalizationError(f"field '{name}' must be a finite, non-negative number")
    return value


def normalize_agent_log(log: Log, source: IngestionSource, ingested_at: datetime) -> SecurityEvent:
    """
    Build the SecurityEvent for a Log row that has been flushed (has an id).
    Raises EventNormalizationError for malformed values; nothing is written.
    """
    if log.id is None:
        raise EventNormalizationError("log must be flushed before normalization")

    raw_type = log.event_type
    if not isinstance(raw_type, str) or not raw_type.strip() or len(raw_type) > 50:
        raise EventNormalizationError("field 'event_type' must be a non-empty string of at most 50 characters")
    raw_type = raw_type.strip()

    source_address = _validated_ip(log.ip)
    numbers = {name: _validated_number(name, getattr(log, name) or 0) for name in _NUMERIC_FIELDS}

    actor = log.user if log.user else None
    if actor is not None and (not isinstance(actor, str) or len(actor) > 255):
        raise EventNormalizationError("field 'user' must be a string of at most 255 characters")

    event_type, action = AGENT_EVENT_TYPE_MAP.get(raw_type.lower(), ("system_event", raw_type.lower()[:50]))

    attributes: Dict[str, Any] = {
        "source_format": AGENT_LOG_FORMAT,
        "original_event_type": raw_type,
        "failed_attempts": numbers["failed_attempts"],
        "login_frequency": numbers["login_frequency"],
        "ip_activity_rate": numbers["ip_activity_rate"],
        "has_raw_data": bool(log.raw_data),   # raw payload stays on the Log row (raw_event_reference)
        "timestamp_source": "ingestion",
        "simulated": source.simulated,
        "ingestion": {"channel": source.channel, "peer_address": source.peer_address},
    }

    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=log.timestamp or ingested_at,
        ingestion_timestamp=ingested_at,
        source_type=source.source_type,
        source_id=source.source_id,
        asset_id=None,
        device_id=None,
        actor=actor,
        actor_type="user" if actor else None,
        source_address=source_address,
        destination_address=None,
        action=action,
        object_type=None,
        object_name=None,
        outcome="unknown",
        severity_hint=None,
        raw_event_reference=f"logs:{log.id}",
        attributes=attributes,
        correlation_key=f"actor:{actor or '-'}|src:{source_address}",
    )
