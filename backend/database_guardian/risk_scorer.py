"""
Risk Scorer - explainable database risk scoring (Skylos Database Guardian).

Scoring model
-------------
Every contribution is a `Signal`: one underlying observation (a burst of failed
logins, or an unacknowledged Database Guardian alert) mapped to a rule weight
from the specification (RISK_WEIGHTS). `score_signals` is a pure function, so
the rules are testable without a database:

1. Duplicate prevention - the same underlying event is counted once, and the
   same rule for the same actor/source/object is counted once per 30 minutes.
2. Maintenance windows - configured per asset; matching categories are
   excluded (or reduced by a multiplier) but stay visible in the explanation.
3. Category cap - at most +40 points per category in any 30-minute window.
4. Correlation - related suspicious events from two or more categories inside
   30 minutes add +15 once per cluster.
5. Severity - 0-19 Low, 20-39 Medium, 40-69 High, 70+ Critical. The total is
   not capped, because the specification defines no maximum.

Approval workflows (approved/unapproved admins, privilege changes, schema
changes, exports) are not implemented yet, so every such signal is treated as
unapproved unless a maintenance window suppresses it.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

from models import DatabaseAlert, DatabaseAsset, DatabaseLoginEvent, DatabaseRiskSnapshot

logger = logging.getLogger(__name__)

SCORING_VERSION = "1"

# Risk score weights (from the Skylos specification)
RISK_WEIGHTS = {
    "failed_logins_3_4": 5,
    "failed_logins_5_9": 15,
    "failed_logins_10_plus": 25,
    "new_admin": 25,
    "privilege_escalation": 30,
    "audit_disabled": 40,
    "missing_backup": 20,
    "failed_backup": 25,
    "schema_change": 5,
    "sensitive_access": 15,
    "large_export": 30,
    "out_of_hours": 5,
    "unknown_ip": 10,
    "multiple_events": 15,
}

FAILED_LOGIN_WINDOW = timedelta(minutes=10)
CATEGORY_WINDOW = timedelta(minutes=30)   # cap, duplicate and correlation window
CATEGORY_CAP = 40                          # max points per category per window
DEFAULT_LOOKBACK = timedelta(hours=24)

# rule -> category (the category is what the cap applies to)
RULE_CATEGORIES = {
    "failed_logins_3_4": "authentication",
    "failed_logins_5_9": "authentication",
    "failed_logins_10_plus": "authentication",
    "new_admin": "privilege",
    "privilege_escalation": "privilege",
    "audit_disabled": "audit",
    "missing_backup": "backup",
    "failed_backup": "backup",
    "schema_change": "schema",
    "sensitive_access": "data_access",
    "large_export": "data_access",
    "out_of_hours": "time_source",
    "unknown_ip": "time_source",
    "multiple_events": "correlation",
}
CATEGORIES = ("authentication", "privilege", "schema", "audit", "backup",
              "data_access", "time_source", "correlation")

# Database Guardian alert type -> scoring rule. Alert types not listed here
# (db_brute_force, db_new_user, db_privilege_change, db_high_query_volume)
# carry no weight in the specification. db_brute_force is scored from the
# login events themselves so a burst is not counted twice.
ALERT_TYPE_RULES = {
    "db_new_admin": "new_admin",
    "db_privilege_escalation": "privilege_escalation",
    "db_audit_disabled": "audit_disabled",
    "db_missing_backup": "missing_backup",
    "db_failed_backup": "failed_backup",
    "db_schema_change": "schema_change",
    "db_sensitive_access": "sensitive_access",
    "db_large_export": "large_export",
    "db_out_of_hours": "out_of_hours",
    "db_unknown_source": "unknown_ip",
}

# Legacy response fields kept for API compatibility.
LEGACY_FIELDS = {
    "authentication": "failed_logins_score",
    "privilege": "privilege_changes_score",
    "schema": "schema_changes_score",
    "audit": "audit_disabled_score",
    "backup": "backup_issues_score",
    "data_access": "sensitive_access_score",
}

DEFAULT_MAINTENANCE_CATEGORIES = ("schema", "time_source")


def failed_login_rule(count: int) -> Optional[str]:
    """Rule for a number of failed logins inside one 10-minute window."""
    if count >= 10:
        return "failed_logins_10_plus"
    if count >= 5:
        return "failed_logins_5_9"
    if count >= 3:
        return "failed_logins_3_4"
    return None


def severity_for_score(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def alert_risk_impact(alert_type: str, evidence: Optional[dict] = None) -> int:
    """Specification weight an alert contributes (0 for types with no weight)."""
    if alert_type == "db_brute_force":
        rule = failed_login_rule(int((evidence or {}).get("failed_logins_count", 0) or 0))
    else:
        rule = ALERT_TYPE_RULES.get(alert_type)
    return RISK_WEIGHTS.get(rule, 0) if rule else 0


def _utc(value: datetime) -> datetime:
    """Database drivers may return naive timestamps; Skylos stores UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


@dataclass(frozen=True)
class MaintenanceWindow:
    start: datetime
    end: datetime
    categories: Tuple[str, ...] = DEFAULT_MAINTENANCE_CATEGORIES
    multiplier: float = 0.0      # 0 excludes the points; 0.5 halves them

    def covers(self, when: datetime, category: str) -> bool:
        return category in self.categories and self.start <= when <= self.end


@dataclass(frozen=True)
class Signal:
    """One underlying observation that may add points."""
    key: str                      # identity of the underlying event, e.g. "alert:12"
    rule: str
    timestamp: datetime
    reason: str
    entity: Tuple = ()            # (actor, source, object) for duplicate suppression
    event_refs: Tuple[str, ...] = ()

    @property
    def category(self) -> str:
        return RULE_CATEGORIES[self.rule]

    @property
    def weight(self) -> int:
        return RISK_WEIGHTS[self.rule]


@dataclass
class Contribution:
    rule: str
    category: str
    timestamp: datetime
    reason: str
    base_points: int
    applied_points: int
    status: str                   # counted, capped, duplicate, maintenance
    note: str = ""
    event_refs: Tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "category": self.category,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "base_points": self.base_points,
            "applied_points": self.applied_points,
            "status": self.status,
            "note": self.note,
            "event_refs": list(self.event_refs),
        }


@dataclass
class ScoreResult:
    total: int
    severity: str
    contributions: List[Contribution] = field(default_factory=list)
    category_totals: Dict[str, int] = field(default_factory=dict)

    @property
    def counted(self) -> List[Contribution]:
        return [c for c in self.contributions if c.applied_points > 0]


def score_signals(signals: Sequence[Signal],
                  maintenance_windows: Sequence[MaintenanceWindow] = ()) -> ScoreResult:
    """Apply duplicate prevention, maintenance, caps and correlation."""
    contributions: List[Contribution] = []
    seen_keys = set()
    last_counted: Dict[Tuple, datetime] = {}
    accepted: Dict[str, List[Tuple[datetime, int]]] = {c: [] for c in CATEGORIES}

    def make(sig: Signal, applied: int, status: str, note: str = "") -> Contribution:
        return Contribution(sig.rule, sig.category, sig.timestamp, sig.reason, sig.weight,
                            applied, status, note, sig.event_refs)

    for sig in sorted(signals, key=lambda s: (s.timestamp, s.key)):
        if sig.key in seen_keys:
            continue        # the same underlying event is never counted twice
        seen_keys.add(sig.key)
        dup_id = (sig.rule, sig.entity)
        previous = last_counted.get(dup_id)
        if previous is not None and sig.timestamp - previous < CATEGORY_WINDOW:
            contributions.append(make(sig, 0, "duplicate",
                                      "Same rule for the same actor/source/object within 30 minutes"))
            continue

        points = sig.weight
        status, note = "counted", ""
        for window in maintenance_windows:
            if window.covers(sig.timestamp, sig.category):
                points = int(round(points * window.multiplier))
                status, note = "maintenance", "Inside a configured maintenance window"
                break

        cap_left = CATEGORY_CAP - sum(
            p for t, p in accepted[sig.category] if sig.timestamp - t < CATEGORY_WINDOW)
        if points > cap_left:
            points = max(cap_left, 0)
            status, note = "capped", f"Category cap of +{CATEGORY_CAP} per 30 minutes reached"

        last_counted[dup_id] = sig.timestamp
        if points > 0:
            accepted[sig.category].append((sig.timestamp, points))
        contributions.append(make(sig, points, status, note))

    # Related suspicious events: two or more categories within 30 minutes.
    scored = sorted((c for c in contributions if c.applied_points > 0), key=lambda c: c.timestamp)
    i = 0
    while i < len(scored):
        window_end = scored[i].timestamp + CATEGORY_WINDOW
        cluster = [c for c in scored[i:] if c.timestamp <= window_end]
        categories, award_time = set(), None
        for c in cluster:
            categories.add(c.category)
            if len(categories) >= 2:
                award_time = c.timestamp
                break
        if award_time is None:
            i += 1
            continue
        refs = tuple(ref for c in cluster for ref in c.event_refs)
        contributions.append(Contribution(
            "multiple_events", "correlation", award_time,
            f"Related suspicious events from {', '.join(sorted(categories))} within 30 minutes",
            RISK_WEIGHTS["multiple_events"], RISK_WEIGHTS["multiple_events"], "counted",
            "", refs))
        i += len(cluster)

    contributions.sort(key=lambda c: c.timestamp)
    category_totals = {cat: 0 for cat in CATEGORIES}
    for c in contributions:
        category_totals[c.category] += c.applied_points
    total = sum(category_totals.values())
    return ScoreResult(total, severity_for_score(total), contributions, category_totals)


# ── Database-backed signal collection ───────────────────────────────────────

def parse_maintenance_windows(metadata_json: Optional[str]) -> List[MaintenanceWindow]:
    """Read validated maintenance windows from an asset's metadata; ignore bad entries."""
    if not metadata_json:
        return []
    try:
        raw = json.loads(metadata_json).get("maintenance_windows", [])
    except (ValueError, AttributeError):
        return []
    windows = []
    for item in raw if isinstance(raw, list) else []:
        try:
            categories = tuple(c for c in item.get("categories", DEFAULT_MAINTENANCE_CATEGORIES)
                               if c in CATEGORIES and c != "correlation")
            windows.append(MaintenanceWindow(
                _utc(datetime.fromisoformat(item["start"])),
                _utc(datetime.fromisoformat(item["end"])),
                categories or DEFAULT_MAINTENANCE_CATEGORIES,
                min(max(float(item.get("multiplier", 0.0)), 0.0), 1.0)))
        except (AttributeError, KeyError, TypeError, ValueError):
            logger.warning("Ignoring invalid maintenance window in asset metadata")
    return windows


def _failed_login_signals(db: Session, database_id: int, since: datetime) -> List[Signal]:
    """Group failed logins into 10-minute bursts; each burst is one signal."""
    events = (
        db.query(DatabaseLoginEvent)
        .filter(DatabaseLoginEvent.database_id == database_id,
                DatabaseLoginEvent.success == False,  # noqa: E712
                DatabaseLoginEvent.timestamp >= since)
        .order_by(DatabaseLoginEvent.timestamp, DatabaseLoginEvent.id)
        .all()
    )
    signals, i = [], 0
    while i < len(events):
        start = _utc(events[i].timestamp)
        burst = [e for e in events[i:] if _utc(e.timestamp) < start + FAILED_LOGIN_WINDOW]
        rule = failed_login_rule(len(burst))
        if rule:
            signals.append(Signal(
                key=f"failed_logins:{burst[0].id}-{burst[-1].id}",
                rule=rule,
                timestamp=_utc(burst[-1].timestamp),
                reason=f"{len(burst)} failed logins within 10 minutes",
                event_refs=tuple(f"database_login_events:{e.id}" for e in burst),
            ))
        i += len(burst)
    return signals


def _alert_signals(db: Session, database_id: int, since: datetime) -> List[Signal]:
    alerts = (
        db.query(DatabaseAlert)
        .filter(DatabaseAlert.database_id == database_id,
                DatabaseAlert.acknowledged == False,  # noqa: E712
                DatabaseAlert.timestamp >= since)
        .order_by(DatabaseAlert.timestamp, DatabaseAlert.id)
        .all()
    )
    signals = []
    for alert in alerts:
        rule = ALERT_TYPE_RULES.get(alert.alert_type)
        if rule:
            signals.append(Signal(
                key=f"alert:{alert.id}",
                rule=rule,
                timestamp=_utc(alert.timestamp),
                reason=alert.title,
                entity=(alert.username, alert.source_ip, alert.affected_table),
                event_refs=(f"database_alerts:{alert.id}",),
            ))
    return signals


def evaluate_database_risk(db: Session, database_id: int, now: Optional[datetime] = None,
                           lookback: timedelta = DEFAULT_LOOKBACK) -> ScoreResult:
    """Score one database from its stored events and unacknowledged alerts."""
    now = _utc(now) if now else datetime.now(timezone.utc)
    since = now - lookback
    asset = db.query(DatabaseAsset).filter(DatabaseAsset.id == database_id).first()
    windows = parse_maintenance_windows(asset.metadata_json) if asset else []
    signals = _failed_login_signals(db, database_id, since) + _alert_signals(db, database_id, since)
    return score_signals(signals, windows)


def calculate_database_risk_score(db: Session, database_id: int) -> dict:
    """
    Score a database and return the breakdown. The legacy per-category fields
    are kept so existing clients keep working; `severity` and `contributions`
    carry the explanation.
    """
    result = evaluate_database_risk(db, database_id)
    breakdown = {field_name: 0 for field_name in LEGACY_FIELDS.values()}
    breakdown["other_score"] = 0
    for category, points in result.category_totals.items():
        breakdown[LEGACY_FIELDS.get(category, "other_score")] += points
    return {
        "total_risk_score": result.total,
        **breakdown,
        "severity": result.severity,
        "contributions": [c.as_dict() for c in result.contributions],
        "scoring_version": SCORING_VERSION,
    }


def record_risk_snapshot(db: Session, database_id: int,
                         result: Optional[ScoreResult] = None) -> Optional[DatabaseRiskSnapshot]:
    """
    Persist the score, severity, reasons and event references when they differ
    from the latest snapshot. Returns the new snapshot, or None if unchanged.
    The caller commits.
    """
    result = result or evaluate_database_risk(db, database_id)
    contributions = [c.as_dict() for c in result.contributions]
    latest = (db.query(DatabaseRiskSnapshot)
              .filter(DatabaseRiskSnapshot.database_id == database_id)
              .order_by(DatabaseRiskSnapshot.id.desc()).first())
    if latest and latest.total_score == result.total and latest.contributions_json == json.dumps(contributions):
        return None
    snapshot = DatabaseRiskSnapshot(
        database_id=database_id,
        calculated_at=datetime.now(timezone.utc),
        total_score=result.total,
        severity=result.severity,
        contributions_json=json.dumps(contributions),
        scoring_version=SCORING_VERSION,
    )
    db.add(snapshot)
    return snapshot
