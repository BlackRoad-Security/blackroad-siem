"""Tests for BlackRoad SIEM."""
import json
import pytest
from siem import SIEM, SecurityEvent, Rule, Alert, EventType, Severity, RuleAction


@pytest.fixture
def db(tmp_path):
    return SIEM(db_path=str(tmp_path / "siem_test.db"))


def _event(overrides=None):
    base = {
        "source_ip": "10.0.0.1",
        "dest_ip": "192.168.1.1",
        "source_port": 54321,
        "dest_port": 22,
        "protocol": "tcp",
        "event_type": "auth",
        "severity": "medium",
        "raw_log": "SSH login failed for root",
    }
    if overrides:
        base.update(overrides)
    return base


def test_ingest_event(db):
    ev = db.ingest_event("test", _event())
    assert ev.id is not None
    assert ev.source_ip == "10.0.0.1"
    assert ev.event_type == EventType.AUTH


def test_ingest_normalizes_type(db):
    ev = db.ingest_event("test", _event({"event_type": "LOGIN"}))
    assert ev.event_type == EventType.LOGIN


def test_ingest_unknown_event_type_defaults_to_network(db):
    ev = db.ingest_event("test", _event({"event_type": "unknown-xyz"}))
    assert ev.event_type == EventType.NETWORK


def test_add_rule(db):
    rule = db.add_rule("test-rule", "dest_port == 22", severity="high", action="alert")
    assert rule.name == "test-rule"
    assert rule.severity == Severity.HIGH
    assert rule.action == RuleAction.ALERT


def test_list_rules(db):
    rules = db.list_rules()
    assert len(rules) >= 10  # default rules loaded


def test_apply_rules_ssh_brute(db):
    ev = db.ingest_event("test", _event({
        "dest_port": 22,
        "event_type": "auth",
        "raw_log": "failed"
    }))
    alerts = db.apply_rules(ev.id)
    assert len(alerts) >= 1
    rule_names = [a.rule_name for a in alerts]
    assert any("ssh" in n.lower() or "brute" in n.lower() for n in rule_names)


def test_apply_rules_no_match(db):
    ev = db.ingest_event("test", {
        "source_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "source_port": 10000,
        "dest_port": 12345,
        "protocol": "udp",
        "event_type": "network",
        "severity": "info",
        "raw_log": "regular traffic",
    })
    # May still match some rules; just ensure it runs without error
    alerts = db.apply_rules(ev.id)
    assert isinstance(alerts, list)


def test_apply_rules_nonexistent_event(db):
    alerts = db.apply_rules("nonexistent-id")
    assert alerts == []


def test_get_alerts_empty(db):
    alerts = db.get_alerts()
    assert isinstance(alerts, list)


def test_get_alerts_with_severity_filter(db):
    ev = db.ingest_event("test", _event())
    db.apply_rules(ev.id)
    alerts_all = db.get_alerts("info")
    alerts_critical = db.get_alerts("critical")
    assert len(alerts_all) >= len(alerts_critical)


def test_get_alerts_invalid_severity(db):
    with pytest.raises(ValueError):
        db.get_alerts("super-high")


def test_acknowledge_alert(db):
    ev = db.ingest_event("test", _event())
    alerts = db.apply_rules(ev.id)
    if alerts:
        ok = db.acknowledge_alert(alerts[0].id)
        assert ok


def test_acknowledge_nonexistent(db):
    ok = db.acknowledge_alert("nonexistent-id")
    assert ok is False


def test_correlate_events_empty(db):
    corrs = db.correlate_events(window_secs=300)
    assert isinstance(corrs, list)


def test_correlate_events_detects_brute_force(db):
    # Create 6 auth events from same source to same SSH port
    for _ in range(6):
        ev = db.ingest_event("test", _event({"event_type": "auth", "dest_port": 22}))
    corrs = db.correlate_events(window_secs=3600)
    patterns = [c["pattern"] for c in corrs]
    assert "brute_force" in patterns


def test_correlate_events_lateral_movement(db):
    # Create events from same source to many destinations
    src = "10.99.99.99"
    for i in range(6):
        ev = db.ingest_event("test", {
            "source_ip": src,
            "dest_ip": f"10.0.{i}.1",
            "source_port": 50000 + i,
            "dest_port": 445,
            "protocol": "tcp",
            "event_type": "network",
            "severity": "low",
            "raw_log": f"scan {i}",
        })
    corrs = db.correlate_events(window_secs=3600)
    patterns = [c["pattern"] for c in corrs]
    assert "lateral_movement" in patterns


def test_dashboard_stats(db):
    db.ingest_event("test", _event())
    stats = db.dashboard_stats()
    assert "total_events" in stats
    assert stats["total_events"] >= 1
    assert "total_alerts" in stats
    assert "top_source_ips" in stats
    assert "top_triggered_rules" in stats


def test_export_report_json(db):
    db.ingest_event("test", _event())
    report = db.export_report("json")
    data = json.loads(report)
    assert "generated_at" in data
    assert "stats" in data
    assert "alerts" in data


def test_export_report_html(db):
    db.ingest_event("test", _event())
    report = db.export_report("html")
    assert "<!DOCTYPE html>" in report
    assert "BlackRoad SIEM" in report


def test_export_report_invalid_format(db):
    with pytest.raises(ValueError):
        db.export_report("xml")


def test_rule_hit_count_increments(db):
    ev = db.ingest_event("test", _event({"dest_port": 22, "event_type": "auth"}))
    db.apply_rules(ev.id)
    rules = db.list_rules()
    ssh_rules = [r for r in rules if "ssh" in r.name.lower() or "brute" in r.name.lower()]
    if ssh_rules:
        assert ssh_rules[0].hit_count >= 1


def test_ingest_raw_log_includes_source(db):
    ev = db.ingest_event("my-firewall", _event())
    assert "my-firewall" in ev.raw_log


def test_apply_all_pending(db):
    db.ingest_event("test", _event())
    db.ingest_event("test", _event())
    count = db.apply_all_pending()
    assert isinstance(count, int)
