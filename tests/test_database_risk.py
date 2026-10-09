"""
Database Guardian risk scoring: specification boundaries, duplicate prevention,
category caps, correlation, severity bands, maintenance windows, persistence,
alert weights/deduplication and the API surface. All data is synthetic.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from database_guardian import risk_scorer as rs
from database_guardian.risk_scorer import (
    MaintenanceWindow, Signal, score_signals, severity_for_score,
)

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def sig(rule, minutes=0, key=None, entity=(), reason="r"):
    return Signal(key=key or f"{rule}:{minutes}:{entity}", rule=rule,
                  timestamp=T0 + timedelta(minutes=minutes), reason=reason, entity=entity)


# ── Specification weights and bands ───────────────────────────────────────

SPEC_WEIGHTS = {
    "failed_logins_3_4": 5, "failed_logins_5_9": 15, "failed_logins_10_plus": 25,
    "new_admin": 25, "privilege_escalation": 30, "audit_disabled": 40,
    "missing_backup": 20, "failed_backup": 25, "schema_change": 5,
    "sensitive_access": 15, "large_export": 30, "out_of_hours": 5,
    "unknown_ip": 10, "multiple_events": 15,
}


def test_weights_match_specification():
    assert rs.RISK_WEIGHTS == SPEC_WEIGHTS


@pytest.mark.parametrize("score,band", [
    (0, "low"), (19, "low"), (20, "medium"), (39, "medium"),
    (40, "high"), (69, "high"), (70, "critical"), (250, "critical"),
])
def test_severity_band_boundaries(score, band):
    assert severity_for_score(score) == band


@pytest.mark.parametrize("count,rule", [
    (0, None), (2, None), (3, "failed_logins_3_4"), (4, "failed_logins_3_4"),
    (5, "failed_logins_5_9"), (9, "failed_logins_5_9"), (10, "failed_logins_10_plus"),
    (500, "failed_logins_10_plus"),
])
def test_failed_login_tier_boundaries(count, rule):
    assert rs.failed_login_rule(count) == rule


@pytest.mark.parametrize("rule", sorted(r for r in SPEC_WEIGHTS if r != "multiple_events"))
def test_single_signal_scores_its_spec_weight(rule):
    result = score_signals([sig(rule)])
    assert result.total == SPEC_WEIGHTS[rule]
    assert result.contributions[0].status == "counted"


def test_total_is_not_capped_at_100():
    signals = [sig("audit_disabled", m, entity=(m,)) for m in (0, 31, 62, 93)]
    signals += [sig("privilege_escalation", m, entity=(m,)) for m in (0, 31, 62, 93)]
    assert score_signals(signals).total > 100


# ── Duplicate prevention ──────────────────────────────────────────────────

def test_same_underlying_event_counted_once():
    a = sig("schema_change", 0, key="alert:1")
    assert score_signals([a, a, a]).total == 5


def test_same_rule_actor_within_30_minutes_is_duplicate():
    result = score_signals([sig("new_admin", 0, entity=("bob",)),
                            sig("new_admin", 10, entity=("bob",))])
    assert result.total == 25
    assert [c.status for c in result.contributions] == ["counted", "duplicate"]


def test_same_rule_after_30_minutes_counts_again():
    result = score_signals([sig("new_admin", 0, entity=("bob",)),
                            sig("new_admin", 30, entity=("bob",))])
    assert result.total == 50


def test_same_rule_different_actor_is_not_duplicate():
    result = score_signals([sig("new_admin", 0, entity=("bob",)),
                            sig("new_admin", 1, entity=("eve",))])
    assert "duplicate" not in [c.status for c in result.contributions]
    assert result.total == 40  # 25 + 25 limited by the +40 category cap


# ── Category cap ──────────────────────────────────────────────────────────

def test_category_cap_is_40_per_30_minutes():
    # large_export (30) + sensitive_access (15) in one category = 45 -> 40
    result = score_signals([sig("large_export", 0, entity=("a",)),
                            sig("sensitive_access", 1, entity=("b",))])
    assert result.category_totals["data_access"] == 40
    assert [c.status for c in result.contributions if c.category == "data_access"] == ["counted", "capped"]
    assert [c.applied_points for c in result.contributions if c.category == "data_access"] == [30, 10]


def test_cap_resets_after_the_window():
    result = score_signals([sig("large_export", 0, entity=("a",)),
                            sig("large_export", 31, entity=("b",))])
    assert result.category_totals["data_access"] == 60


def test_cap_is_per_category():
    result = score_signals([sig("audit_disabled", 0), sig("large_export", 40)])
    assert result.category_totals["audit"] == 40
    assert result.category_totals["data_access"] == 30


def test_cap_holds_for_every_30_minute_window():
    signals = [sig("large_export", m, entity=(m,)) for m in range(0, 120, 7)]
    scored = [c for c in score_signals(signals).contributions if c.category == "data_access"]
    for anchor in scored:
        window = [c.applied_points for c in scored
                  if timedelta(0) <= c.timestamp - anchor.timestamp < rs.CATEGORY_WINDOW]
        assert sum(window) <= rs.CATEGORY_CAP


# ── Correlation ───────────────────────────────────────────────────────────

def test_related_events_in_two_categories_add_correlation_points():
    result = score_signals([sig("schema_change", 0), sig("unknown_ip", 20)])
    assert result.total == 5 + 10 + 15
    assert result.category_totals["correlation"] == 15


def test_events_in_one_category_do_not_correlate():
    result = score_signals([sig("schema_change", 0, entity=("a",)),
                            sig("schema_change", 5, entity=("b",))])
    assert result.category_totals["correlation"] == 0


def test_events_more_than_30_minutes_apart_do_not_correlate():
    result = score_signals([sig("schema_change", 0), sig("unknown_ip", 31)])
    assert result.category_totals["correlation"] == 0


def test_correlation_awarded_once_per_cluster():
    result = score_signals([sig("schema_change", 0), sig("unknown_ip", 5),
                            sig("sensitive_access", 10)])
    assert result.category_totals["correlation"] == 15


def test_separate_clusters_each_correlate():
    result = score_signals([sig("schema_change", 0), sig("unknown_ip", 5),
                            sig("schema_change", 200), sig("unknown_ip", 205)])
    assert result.category_totals["correlation"] == 30


def test_correlation_lists_its_evidence():
    a = Signal("alert:1", "schema_change", T0, "s", event_refs=("database_alerts:1",))
    b = Signal("alert:2", "unknown_ip", T0 + timedelta(minutes=1), "u", event_refs=("database_alerts:2",))
    corr = [c for c in score_signals([a, b]).contributions if c.rule == "multiple_events"][0]
    assert set(corr.event_refs) == {"database_alerts:1", "database_alerts:2"}


# ── Maintenance windows ───────────────────────────────────────────────────

def window(**kw):
    return MaintenanceWindow(T0 - timedelta(minutes=5), T0 + timedelta(minutes=5), **kw)


def test_maintenance_window_excludes_default_categories_but_keeps_the_explanation():
    result = score_signals([sig("schema_change", 0)], [window()])
    assert result.total == 0
    assert result.contributions[0].status == "maintenance"
    assert result.contributions[0].base_points == 5


def test_maintenance_window_does_not_exclude_other_categories():
    assert score_signals([sig("privilege_escalation", 0)], [window()]).total == 30


def test_maintenance_window_only_applies_inside_its_period():
    assert score_signals([sig("schema_change", 10)], [window()]).total == 5


def test_maintenance_window_can_reduce_instead_of_exclude():
    result = score_signals([sig("unknown_ip", 0)], [window(multiplier=0.5)])
    assert result.total == 5


def test_maintenance_window_for_explicit_category():
    result = score_signals([sig("audit_disabled", 0)], [window(categories=("audit",))])
    assert result.total == 0


def test_excluded_events_do_not_correlate():
    result = score_signals([sig("schema_change", 0), sig("unknown_ip", 1)],
                           [MaintenanceWindow(T0 - timedelta(minutes=5), T0 + timedelta(minutes=5),
                                              ("schema",), 0.0)])
    assert result.category_totals["correlation"] == 0
    assert result.total == 10


def test_parse_maintenance_windows_ignores_invalid_entries():
    meta = json.dumps({"maintenance_windows": [
        {"start": T0.isoformat(), "end": (T0 + timedelta(hours=1)).isoformat(),
         "categories": ["schema", "bogus", "correlation"], "multiplier": 9},
        {"start": "garbage", "end": "x"},
        "not-a-dict",
    ]})
    windows = rs.parse_maintenance_windows(meta)
    assert len(windows) == 1
    assert windows[0].categories == ("schema",)
    assert windows[0].multiplier == 1.0
    assert rs.parse_maintenance_windows("not json") == []
    assert rs.parse_maintenance_windows(None) == []


# ── Database-backed scoring ───────────────────────────────────────────────

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def asset(db_session):
    from models import DatabaseAsset
    row = DatabaseAsset(name="synthetic-pg", db_type="postgresql", host="db.invalid", port=5432,
                        database_name="app", username="svc", encrypted_password="x")
    db_session.add(row)
    db_session.commit()
    return row


def add_failed_logins(db, asset, count, start, spacing_seconds=10, success=False):
    from models import DatabaseLoginEvent
    ids = []
    for i in range(count):
        ev = DatabaseLoginEvent(database_id=asset.id, username="u", source_ip="10.0.0.9",
                                success=success, timestamp=start + timedelta(seconds=i * spacing_seconds))
        db.add(ev)
        db.flush()
        ids.append(ev.id)
    db.commit()
    return ids


def add_alert(db, asset, alert_type, when, **kw):
    from models import DatabaseAlert
    row = DatabaseAlert(database_id=asset.id, alert_type=alert_type, severity="high",
                        title=kw.pop("title", alert_type), description="d",
                        timestamp=when, **kw)
    db.add(row)
    db.commit()
    return row


@pytest.mark.parametrize("count,expected", [(2, 0), (3, 5), (4, 5), (5, 15), (9, 15), (10, 25), (30, 25)])
def test_failed_logins_in_one_burst_use_spec_tiers(db_session, asset, count, expected):
    add_failed_logins(db_session, asset, count, NOW - timedelta(minutes=2), spacing_seconds=1)
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == expected


def test_successful_logins_never_score(db_session, asset):
    add_failed_logins(db_session, asset, 12, NOW - timedelta(minutes=2), success=True)
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 0


def test_failed_logins_spread_over_more_than_10_minutes_do_not_reach_a_tier(db_session, asset):
    # 4 failures, 4 minutes apart: 0,4,8 fall in one window (3 -> +5); 12 starts another (1)
    add_failed_logins(db_session, asset, 4, NOW - timedelta(minutes=20), spacing_seconds=240)
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 5


def test_two_separate_bursts_are_scored_separately(db_session, asset):
    add_failed_logins(db_session, asset, 5, NOW - timedelta(hours=3), spacing_seconds=1)
    add_failed_logins(db_session, asset, 5, NOW - timedelta(minutes=5), spacing_seconds=1)
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).category_totals["authentication"] == 30


def test_login_burst_lists_its_events_as_evidence(db_session, asset):
    ids = add_failed_logins(db_session, asset, 5, NOW - timedelta(minutes=2), spacing_seconds=1)
    contribution = rs.evaluate_database_risk(db_session, asset.id, NOW).contributions[0]
    assert list(contribution.event_refs) == [f"database_login_events:{i}" for i in ids]


def test_failed_logins_outside_lookback_are_ignored(db_session, asset):
    add_failed_logins(db_session, asset, 10, NOW - timedelta(hours=30), spacing_seconds=1)
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 0


def test_brute_force_alert_is_not_counted_on_top_of_its_login_events(db_session, asset):
    add_failed_logins(db_session, asset, 10, NOW - timedelta(minutes=2), spacing_seconds=1)
    add_alert(db_session, asset, "db_brute_force", NOW - timedelta(minutes=1))
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 25


def test_alerts_score_by_type_and_unweighted_types_score_zero(db_session, asset):
    add_alert(db_session, asset, "db_missing_backup", NOW - timedelta(minutes=50))
    for unweighted in ("db_new_user", "db_privilege_change", "db_high_query_volume"):
        add_alert(db_session, asset, unweighted, NOW - timedelta(minutes=1))
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 20


def test_acknowledged_alerts_do_not_score(db_session, asset):
    row = add_alert(db_session, asset, "db_audit_disabled", NOW - timedelta(minutes=1))
    row.acknowledged = True
    db_session.commit()
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 0


def test_alert_contribution_names_the_alert_as_evidence(db_session, asset):
    row = add_alert(db_session, asset, "db_new_admin", NOW - timedelta(minutes=1), title="New admin eve")
    contribution = rs.evaluate_database_risk(db_session, asset.id, NOW).contributions[0]
    assert contribution.reason == "New admin eve"
    assert list(contribution.event_refs) == [f"database_alerts:{row.id}"]


def test_database_maintenance_window_from_asset_metadata(db_session, asset):
    asset.metadata_json = json.dumps({"maintenance_windows": [{
        "start": (NOW - timedelta(hours=1)).isoformat(), "end": (NOW + timedelta(hours=1)).isoformat(),
        "categories": ["schema"]}]})
    db_session.commit()
    add_alert(db_session, asset, "db_schema_change", NOW - timedelta(minutes=10))
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 0


def test_naive_database_timestamps_are_treated_as_utc(db_session, asset):
    add_alert(db_session, asset, "db_audit_disabled", (NOW - timedelta(minutes=1)).replace(tzinfo=None))
    assert rs.evaluate_database_risk(db_session, asset.id, NOW).total == 40


def test_legacy_breakdown_fields_remain(db_session, asset):
    add_alert(db_session, asset, "db_new_admin", NOW - timedelta(minutes=1))
    now_alert = add_alert(db_session, asset, "db_audit_disabled", datetime.now(timezone.utc))
    breakdown = rs.calculate_database_risk_score(db_session, asset.id)
    for name in ("total_risk_score", "failed_logins_score", "privilege_changes_score",
                 "schema_changes_score", "audit_disabled_score", "backup_issues_score",
                 "sensitive_access_score", "other_score", "severity", "contributions"):
        assert name in breakdown
    assert breakdown["audit_disabled_score"] == 40 and now_alert.id


# ── Snapshots ─────────────────────────────────────────────────────────────

def test_snapshot_stores_score_reasons_and_references(db_session, asset):
    from models import DatabaseRiskSnapshot
    row = add_alert(db_session, asset, "db_audit_disabled", NOW - timedelta(minutes=1))
    snap = rs.record_risk_snapshot(db_session, asset.id, rs.evaluate_database_risk(db_session, asset.id, NOW))
    db_session.commit()
    stored = db_session.query(DatabaseRiskSnapshot).one()
    assert stored.total_score == 40 and stored.severity == "high" and stored.scoring_version == rs.SCORING_VERSION
    contribution = json.loads(stored.contributions_json)[0]
    assert contribution["rule"] == "audit_disabled"
    assert contribution["event_refs"] == [f"database_alerts:{row.id}"]
    assert snap is stored


def test_unchanged_score_does_not_create_another_snapshot(db_session, asset):
    from models import DatabaseRiskSnapshot
    add_alert(db_session, asset, "db_audit_disabled", NOW - timedelta(minutes=1))
    result = rs.evaluate_database_risk(db_session, asset.id, NOW)
    assert rs.record_risk_snapshot(db_session, asset.id, result) is not None
    db_session.commit()
    assert rs.record_risk_snapshot(db_session, asset.id, result) is None
    assert db_session.query(DatabaseRiskSnapshot).count() == 1


def test_health_monitor_risk_helper_imports_and_stores(db_session, asset):
    # Regression: the helper used a bare `from risk_scorer import`, which raised
    # ModuleNotFoundError and made every successful health check record "offline".
    from database_guardian.health_monitor import calculate_risk_score
    add_alert(db_session, asset, "db_audit_disabled", datetime.now(timezone.utc))
    assert calculate_risk_score(db_session, asset.id) == 40
    db_session.commit()
    from models import DatabaseRiskSnapshot
    assert db_session.query(DatabaseRiskSnapshot).count() == 1


# ── Alert generator ───────────────────────────────────────────────────────

@pytest.mark.parametrize("alert_type,evidence,impact", [
    ("db_new_admin", None, 25), ("db_privilege_escalation", None, 30),
    ("db_audit_disabled", None, 40), ("db_missing_backup", None, 20),
    ("db_failed_backup", None, 25), ("db_schema_change", None, 5),
    ("db_sensitive_access", None, 15), ("db_large_export", None, 30),
    ("db_brute_force", {"failed_logins_count": 3}, 5),
    ("db_brute_force", {"failed_logins_count": 7}, 15),
    ("db_brute_force", {"failed_logins_count": 12}, 25),
    ("db_brute_force", {"failed_logins_count": 2}, 0),
    ("db_new_user", None, 0), ("db_unknown_type", None, 0),
])
def test_alert_impact_follows_specification(alert_type, evidence, impact):
    assert rs.alert_risk_impact(alert_type, evidence) == impact


@pytest.mark.asyncio
async def test_create_database_alert_sets_spec_impact_and_suppresses_duplicates(db_session, asset):
    from database_guardian.alert_generator import create_database_alert
    from models import DatabaseAlert
    kwargs = dict(db=db_session, database_id=asset.id, alert_type="db_audit_disabled", severity="critical",
                  title="Audit disabled", description="d", username="bob")
    first = await create_database_alert(**kwargs)
    second = await create_database_alert(**kwargs)
    assert first.id == second.id
    assert first.risk_score_impact == 40
    assert db_session.query(DatabaseAlert).count() == 1
    other = await create_database_alert(**{**kwargs, "username": "eve"})
    assert other.id != first.id


@pytest.mark.asyncio
async def test_acknowledged_or_stale_alerts_do_not_suppress_new_ones(db_session, asset):
    from database_guardian.alert_generator import create_database_alert
    kwargs = dict(db=db_session, database_id=asset.id, alert_type="db_new_admin", severity="high",
                  title="t", description="d")
    first = await create_database_alert(**kwargs)
    first.acknowledged = True
    db_session.commit()
    assert (await create_database_alert(**kwargs)).id != first.id


@pytest.mark.asyncio
async def test_severity_escalation_creates_a_new_alert(db_session, asset):
    from database_guardian.alert_generator import create_database_alert
    base = dict(db=db_session, database_id=asset.id, alert_type="db_brute_force", title="t", description="d")
    medium = await create_database_alert(severity="medium", evidence={"failed_logins_count": 3}, **base)
    critical = await create_database_alert(severity="critical", evidence={"failed_logins_count": 11}, **base)
    assert medium.id != critical.id
    assert (medium.risk_score_impact, critical.risk_score_impact) == (5, 25)


# ── API ───────────────────────────────────────────────────────────────────

def test_risk_score_endpoint_explains_the_score(client, auth_headers, db_session, asset):
    add_alert(db_session, asset, "db_audit_disabled", datetime.now(timezone.utc) - timedelta(minutes=1))
    for role in ("viewer", "analyst", "admin"):
        r = client.get(f"/api/databases/{asset.id}/risk-score", headers=auth_headers[role])
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total_risk_score"] == 40 and body["severity"] == "high"
        assert body["audit_disabled_score"] == 40
        assert body["contributions"][0]["rule"] == "audit_disabled"
        assert "password" not in json.dumps(body).lower()


def test_risk_score_requires_authentication(client, asset):
    assert client.get(f"/api/databases/{asset.id}/risk-score").status_code == 401
    assert client.get(f"/api/databases/{asset.id}/risk-history").status_code == 401


def test_risk_history_returns_stored_snapshots(client, auth_headers, db_session, asset):
    add_alert(db_session, asset, "db_new_admin", datetime.now(timezone.utc) - timedelta(minutes=1))
    rs.record_risk_snapshot(db_session, asset.id)
    db_session.commit()
    r = client.get(f"/api/databases/{asset.id}/risk-history", headers=auth_headers["viewer"])
    assert r.status_code == 200
    assert r.json()[0]["total_score"] == 25
    assert r.json()[0]["contributions"][0]["rule"] == "new_admin"
    assert client.get("/api/databases/99999/risk-history", headers=auth_headers["viewer"]).status_code == 404
    assert client.get(f"/api/databases/{asset.id}/risk-history?limit=0", headers=auth_headers["viewer"]).status_code == 422


WINDOW = {"start": "2026-03-01T01:00:00Z", "end": "2026-03-01T03:00:00Z",
          "categories": ["schema"], "multiplier": 0.0}


def test_only_admin_can_configure_maintenance_windows(client, auth_headers, asset):
    url = f"/api/databases/{asset.id}"
    for role in ("viewer", "analyst"):
        assert client.patch(url, json={"maintenance_windows": [WINDOW]}, headers=auth_headers[role]).status_code == 403
    r = client.patch(url, json={"maintenance_windows": [WINDOW]}, headers=auth_headers["admin"])
    assert r.status_code == 200, r.text
    assert r.json()["maintenance_windows"][0]["categories"] == ["schema"]
    assert client.get(url, headers=auth_headers["viewer"]).json()["maintenance_windows"][0]["multiplier"] == 0.0


def test_maintenance_window_configuration_is_audited_and_applied(client, auth_headers, db_session, asset):
    from models import AuditLog
    now = datetime.now(timezone.utc)
    window = {"start": (now - timedelta(hours=1)).isoformat(), "end": (now + timedelta(hours=1)).isoformat(),
              "categories": ["schema"]}
    r = client.patch(f"/api/databases/{asset.id}", json={"maintenance_windows": [window]},
                     headers=auth_headers["admin"])
    assert r.status_code == 200
    assert db_session.query(AuditLog).filter(AuditLog.action == "database_updated").count() == 1
    add_alert(db_session, asset, "db_schema_change", now - timedelta(minutes=5))
    body = client.get(f"/api/databases/{asset.id}/risk-score", headers=auth_headers["viewer"]).json()
    assert body["total_risk_score"] == 0
    assert body["contributions"][0]["status"] == "maintenance"


@pytest.mark.parametrize("bad", [
    {**WINDOW, "end": WINDOW["start"]},
    {**WINDOW, "categories": ["nonsense"]},
    {**WINDOW, "categories": []},
    {**WINDOW, "multiplier": 2},
    {**WINDOW, "start": "not-a-date"},
    {"start": WINDOW["start"]},
])
def test_invalid_maintenance_windows_rejected(client, auth_headers, asset, bad):
    r = client.patch(f"/api/databases/{asset.id}", json={"maintenance_windows": [bad]},
                     headers=auth_headers["admin"])
    assert r.status_code == 422


def test_clearing_maintenance_windows_and_other_updates_keep_metadata(client, auth_headers, db_session, asset):
    asset.metadata_json = json.dumps({"keep": "me"})
    db_session.commit()
    url = f"/api/databases/{asset.id}"
    client.patch(url, json={"maintenance_windows": [WINDOW]}, headers=auth_headers["admin"])
    client.patch(url, json={"name": "renamed"}, headers=auth_headers["admin"])
    db_session.expire_all()
    meta = json.loads(db_session.get(type(asset), asset.id).metadata_json)
    assert meta["keep"] == "me" and len(meta["maintenance_windows"]) == 1
    r = client.patch(url, json={"maintenance_windows": []}, headers=auth_headers["admin"])
    assert r.status_code == 200 and r.json()["maintenance_windows"] == []
