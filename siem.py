"""
BlackRoad SIEM - Security Information and Event Management.
Event ingestion, rule evaluation, correlation, alerting, and reporting.
"""

import hashlib
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventType(str, Enum):
    LOGIN = "login"
    NETWORK = "network"
    FILE = "file"
    PROCESS = "process"
    REGISTRY = "registry"
    AUTH = "auth"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleAction(str, Enum):
    ALERT = "alert"
    BLOCK = "block"
    LOG = "log"


SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    event_type: EventType
    severity: Severity
    rule_id: Optional[str]
    raw_log: str
    timestamp: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class Rule:
    id: str
    name: str
    condition_expr: str   # simple DSL expression evaluated against event dict
    severity: Severity
    action: RuleAction
    enabled: bool = True
    hit_count: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["action"] = self.action.value
        return d


@dataclass
class Alert:
    id: str
    event_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    action: RuleAction
    message: str
    timestamp: str
    acknowledged: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["action"] = self.action.value
        return d


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    source_ip TEXT,
    dest_ip TEXT,
    source_port INTEGER,
    dest_port INTEGER,
    protocol TEXT,
    event_type TEXT,
    severity TEXT,
    rule_id TEXT,
    raw_log TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    condition_expr TEXT NOT NULL,
    severity TEXT NOT NULL,
    action TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    hit_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    action TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);

CREATE TABLE IF NOT EXISTS correlations (
    id TEXT PRIMARY KEY,
    event_ids TEXT NOT NULL,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

DEFAULT_RULES = [
    ("brute-force-ssh", "dest_port == 22 and event_type == 'auth'", "high", "alert"),
    ("port-scan", "source_port < 1024 and dest_port > 1024 and protocol == 'tcp'", "medium", "alert"),
    ("failed-login", "event_type == 'login' and 'failed' in raw_log.lower()", "medium", "alert"),
    ("suspicious-process", "event_type == 'process' and 'cmd.exe' in raw_log.lower()", "high", "alert"),
    ("data-exfil", "dest_port == 443 and source_port > 49000", "medium", "log"),
    ("admin-login-offhours", "event_type == 'login' and 'admin' in raw_log.lower()", "high", "alert"),
    ("registry-modification", "event_type == 'registry' and 'HKLM' in raw_log", "medium", "alert"),
    ("critical-port-access", "dest_port in [3306, 5432, 27017, 6379]", "high", "alert"),
    ("icmp-flood", "protocol == 'icmp' and source_ip == source_ip", "low", "log"),
    ("file-deletion", "event_type == 'file' and 'delete' in raw_log.lower()", "medium", "alert"),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_event(row: tuple) -> SecurityEvent:
    id_, src_ip, dst_ip, src_port, dst_port, proto, etype, sev, rule_id, raw, ts = row
    return SecurityEvent(
        id=id_, source_ip=src_ip or "", dest_ip=dst_ip or "",
        source_port=src_port or 0, dest_port=dst_port or 0,
        protocol=proto or "tcp", event_type=EventType(etype),
        severity=Severity(sev), rule_id=rule_id, raw_log=raw or "", timestamp=ts,
    )


def _row_to_rule(row: tuple) -> Rule:
    id_, name, cond, sev, action, enabled, hits = row
    return Rule(id=id_, name=name, condition_expr=cond,
                severity=Severity(sev), action=RuleAction(action),
                enabled=bool(enabled), hit_count=hits)


def _row_to_alert(row: tuple) -> Alert:
    id_, eid, rid, rname, sev, action, msg, ts, ack = row
    return Alert(id=id_, event_id=eid, rule_id=rid, rule_name=rname,
                 severity=Severity(sev), action=RuleAction(action),
                 message=msg, timestamp=ts, acknowledged=bool(ack))


# ---------------------------------------------------------------------------
# Rule evaluator
# ---------------------------------------------------------------------------

def _eval_rule(rule: Rule, event: SecurityEvent) -> bool:
    """Evaluate a rule condition expression against an event. Uses restricted eval."""
    ctx = {
        "source_ip": event.source_ip,
        "dest_ip": event.dest_ip,
        "source_port": event.source_port,
        "dest_port": event.dest_port,
        "protocol": event.protocol,
        "event_type": event.event_type.value,
        "severity": event.severity.value,
        "raw_log": event.raw_log,
        "timestamp": event.timestamp,
    }
    try:
        return bool(eval(rule.condition_expr, {"__builtins__": {}}, ctx))  # noqa: S307
    except Exception:
        return False


# ---------------------------------------------------------------------------
# SIEM
# ---------------------------------------------------------------------------

class SIEM:
    """Core SIEM engine."""

    def __init__(self, db_path: str = "siem.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            # Load default rules if none exist
            count = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
            if count == 0:
                for name, cond, sev, action in DEFAULT_RULES:
                    rid = str(uuid.uuid5(uuid.NAMESPACE_DNS, name))
                    conn.execute(
                        "INSERT INTO rules (id, name, condition_expr, severity, action) VALUES (?,?,?,?,?)",
                        (rid, name, cond, sev, action),
                    )

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, source: str, event_dict: dict) -> SecurityEvent:
        """Ingest a raw event dict and store it."""
        eid = str(uuid.uuid4())
        ts = event_dict.get("timestamp", _now())
        try:
            etype = EventType(event_dict.get("event_type", "network").lower())
        except ValueError:
            etype = EventType.NETWORK
        try:
            sev = Severity(event_dict.get("severity", "info").lower())
        except ValueError:
            sev = Severity.INFO

        raw = event_dict.get("raw_log", json.dumps(event_dict))
        event = SecurityEvent(
            id=eid,
            source_ip=event_dict.get("source_ip", ""),
            dest_ip=event_dict.get("dest_ip", ""),
            source_port=int(event_dict.get("source_port", 0)),
            dest_port=int(event_dict.get("dest_port", 0)),
            protocol=event_dict.get("protocol", "tcp"),
            event_type=etype,
            severity=sev,
            rule_id=None,
            raw_log=f"[{source}] {raw}",
            timestamp=ts,
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO events
                   (id, source_ip, dest_ip, source_port, dest_port, protocol,
                    event_type, severity, rule_id, raw_log, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (event.id, event.source_ip, event.dest_ip,
                 event.source_port, event.dest_port, event.protocol,
                 event.event_type.value, event.severity.value, event.rule_id,
                 event.raw_log, event.timestamp),
            )
        return event

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, name: str, condition_expr: str,
                 severity: str = "medium", action: str = "alert") -> Rule:
        """Add a detection rule."""
        rule = Rule(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, name)),
            name=name,
            condition_expr=condition_expr,
            severity=Severity(severity.lower()),
            action=RuleAction(action.lower()),
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO rules
                   (id, name, condition_expr, severity, action, enabled, hit_count)
                   VALUES (?,?,?,?,?,1,0)""",
                (rule.id, rule.name, rule.condition_expr,
                 rule.severity.value, rule.action.value),
            )
        return rule

    def list_rules(self) -> list:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM rules ORDER BY hit_count DESC").fetchall()
        return [_row_to_rule(r) for r in rows]

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        return _row_to_rule(row) if row else None

    # ------------------------------------------------------------------
    # Rule application
    # ------------------------------------------------------------------

    def apply_rules(self, event_id: str) -> list:
        """Evaluate all enabled rules against the given event. Returns list of Alert."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if not row:
                return []
            event = _row_to_event(row)
            rules = conn.execute("SELECT * FROM rules WHERE enabled=1").fetchall()

        alerts = []
        with self._connect() as conn:
            for rule_row in rules:
                rule = _row_to_rule(rule_row)
                if _eval_rule(rule, event):
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        event_id=event.id,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        action=rule.action,
                        message=f"Rule '{rule.name}' triggered on event {event.id}",
                        timestamp=_now(),
                    )
                    conn.execute(
                        """INSERT INTO alerts
                           (id, event_id, rule_id, rule_name, severity, action, message, timestamp, acknowledged)
                           VALUES (?,?,?,?,?,?,?,?,0)""",
                        (alert.id, alert.event_id, alert.rule_id, alert.rule_name,
                         alert.severity.value, alert.action.value, alert.message, alert.timestamp),
                    )
                    conn.execute(
                        "UPDATE rules SET hit_count = hit_count + 1 WHERE id=?",
                        (rule.id,),
                    )
                    alerts.append(alert)
        return alerts

    def apply_all_pending(self) -> int:
        """Apply rules to all events that have no rule_id set yet. Returns alert count."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM events WHERE rule_id IS NULL LIMIT 500"
            ).fetchall()
        total = 0
        for (eid,) in rows:
            total += len(self.apply_rules(eid))
        return total

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate_events(self, window_secs: int = 300) -> list:
        """
        Correlate events within a time window.
        Detects patterns: brute-force (same source, many auth events),
        lateral movement (same source, multiple dest IPs).
        Returns list of correlation dicts.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_secs)).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp",
                (cutoff,),
            ).fetchall()

        events = [_row_to_event(r) for r in rows]
        correlations = []

        # Pattern 1: brute force - same source IP, many auth/login events
        auth_by_src: dict[str, list] = {}
        for e in events:
            if e.event_type in (EventType.AUTH, EventType.LOGIN):
                auth_by_src.setdefault(e.source_ip, []).append(e.id)
        for src_ip, eids in auth_by_src.items():
            if len(eids) >= 5:
                corr_id = str(uuid.uuid4())
                corr = {
                    "id": corr_id,
                    "pattern": "brute_force",
                    "source_ip": src_ip,
                    "event_count": len(eids),
                    "event_ids": eids,
                    "severity": "high",
                    "created_at": _now(),
                }
                correlations.append(corr)
                with self._connect() as conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO correlations (id, event_ids, pattern, severity, created_at) VALUES (?,?,?,?,?)",
                        (corr_id, json.dumps(eids), "brute_force", "high", _now()),
                    )

        # Pattern 2: lateral movement - same source, multiple destination IPs
        dest_by_src: dict[str, set] = {}
        for e in events:
            if e.source_ip:
                dest_by_src.setdefault(e.source_ip, set()).add(e.dest_ip)
        for src_ip, dests in dest_by_src.items():
            if len(dests) >= 5:
                related_eids = [e.id for e in events if e.source_ip == src_ip]
                corr_id = str(uuid.uuid4())
                corr = {
                    "id": corr_id,
                    "pattern": "lateral_movement",
                    "source_ip": src_ip,
                    "dest_count": len(dests),
                    "event_ids": related_eids,
                    "severity": "critical",
                    "created_at": _now(),
                }
                correlations.append(corr)
                with self._connect() as conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO correlations (id, event_ids, pattern, severity, created_at) VALUES (?,?,?,?,?)",
                        (corr_id, json.dumps(related_eids), "lateral_movement", "critical", _now()),
                    )

        return correlations

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def get_alerts(self, severity_min: str = "low", hours: int = 24) -> list:
        """Fetch alerts at or above given severity in the last N hours."""
        try:
            min_rank = SEVERITY_RANK[Severity(severity_min.lower())]
        except (KeyError, ValueError):
            raise ValueError(f"Unknown severity: {severity_min}")
        sevs = [s.value for s, r in SEVERITY_RANK.items() if r >= min_rank]
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        placeholders = ",".join("?" * len(sevs))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts WHERE severity IN ({placeholders}) AND timestamp >= ? ORDER BY timestamp DESC",
                (*sevs, cutoff),
            ).fetchall()
        return [_row_to_alert(r) for r in rows]

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,)
            )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Dashboard stats
    # ------------------------------------------------------------------

    def dashboard_stats(self) -> dict:
        """Return stats suitable for a security dashboard."""
        with self._connect() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            unacked = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged=0"
            ).fetchone()[0]
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            ).fetchall()
            by_type = conn.execute(
                "SELECT event_type, COUNT(*) FROM events GROUP BY event_type"
            ).fetchall()
            top_sources = conn.execute(
                "SELECT source_ip, COUNT(*) as c FROM events GROUP BY source_ip ORDER BY c DESC LIMIT 10"
            ).fetchall()
            top_rules = conn.execute(
                "SELECT name, hit_count FROM rules ORDER BY hit_count DESC LIMIT 10"
            ).fetchall()
            recent_critical = conn.execute(
                """SELECT * FROM alerts WHERE severity='critical' ORDER BY timestamp DESC LIMIT 5"""
            ).fetchall()
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "unacknowledged_alerts": unacked,
            "alerts_by_severity": dict(by_severity),
            "events_by_type": dict(by_type),
            "top_source_ips": [{"ip": r[0], "count": r[1]} for r in top_sources],
            "top_triggered_rules": [{"rule": r[0], "hits": r[1]} for r in top_rules],
            "recent_critical_alerts": [_row_to_alert(r).to_dict() for r in recent_critical],
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def export_report(self, format: str = "json", hours: int = 24) -> str:
        """Export a security report as JSON or HTML."""
        stats = self.dashboard_stats()
        alerts = self.get_alerts("low", hours)
        correlations = []
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM correlations ORDER BY created_at DESC LIMIT 20").fetchall()
            for r in rows:
                correlations.append({
                    "id": r[0], "event_ids": json.loads(r[1]),
                    "pattern": r[2], "severity": r[3], "created_at": r[4],
                })

        report_data = {
            "generated_at": _now(),
            "period_hours": hours,
            "stats": stats,
            "alerts": [a.to_dict() for a in alerts],
            "correlations": correlations,
        }

        if format.lower() == "json":
            return json.dumps(report_data, indent=2)
        elif format.lower() == "html":
            return self._render_html_report(report_data)
        else:
            raise ValueError(f"Unknown format: {format}")

    def _render_html_report(self, data: dict) -> str:
        stats = data["stats"]
        alerts_html = ""
        for a in data["alerts"][:50]:
            color = {"critical": "#dc3545", "high": "#fd7e14",
                     "medium": "#ffc107", "low": "#0dcaf0", "info": "#6c757d"}.get(a["severity"], "#6c757d")
            alerts_html += f"""
            <tr>
                <td style="color:{color}"><strong>{a['severity'].upper()}</strong></td>
                <td>{a['rule_name']}</td>
                <td>{a['action']}</td>
                <td>{a['message']}</td>
                <td>{a['timestamp'][:19]}</td>
            </tr>"""
        return f"""<!DOCTYPE html>
<html>
<head><title>BlackRoad SIEM Report</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; }} h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th {{ background: #161b22; color: #79c0ff; padding: .5rem; text-align: left; }}
  td {{ padding: .4rem .5rem; border-bottom: 1px solid #21262d; }}
  .stat {{ display: inline-block; background: #161b22; padding: 1rem 2rem; margin: .5rem; border-radius: 8px; }}
  .stat-value {{ font-size: 2rem; color: #58a6ff; }}
</style></head>
<body>
<h1>🛡 BlackRoad SIEM Security Report</h1>
<p>Generated: {data['generated_at']} | Period: last {data['period_hours']}h</p>
<h2>Summary</h2>
<div class="stat"><div class="stat-value">{stats['total_events']}</div>Total Events</div>
<div class="stat"><div class="stat-value">{stats['total_alerts']}</div>Total Alerts</div>
<div class="stat"><div class="stat-value" style="color:#dc3545">{stats['unacknowledged_alerts']}</div>Unacked</div>
<h2>Alerts</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Action</th><th>Message</th><th>Time</th></tr>
{alerts_html}
</table>
</body></html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import sys
    db = SIEM()
    args = sys.argv[1:]

    if not args:
        print("BlackRoad SIEM")
        print("Usage: python siem.py <command> [args]")
        print()
        print("Commands:")
        print("  ingest <source> <json_event>  - Ingest event")
        print("  rules                         - List rules")
        print("  add-rule <name> <expr> [sev] [action]")
        print("  alerts [severity_min] [hours] - Get alerts")
        print("  apply <event_id>              - Apply rules to event")
        print("  apply-all                     - Process all pending events")
        print("  correlate [window_secs]       - Find correlated events")
        print("  stats                         - Dashboard stats")
        print("  report [json|html] [hours]    - Export report")
        print("  demo                          - Load demo events")
        return

    cmd = args[0]

    if cmd == "ingest":
        if len(args) < 3:
            print("Usage: ingest <source> <json_event>")
            return
        event_dict = json.loads(args[2])
        event = db.ingest_event(args[1], event_dict)
        alerts = db.apply_rules(event.id)
        print(f"✓ Event {event.id} ingested from {args[1]}")
        if alerts:
            print(f"  ⚠ {len(alerts)} rule(s) triggered:")
            for a in alerts:
                print(f"    [{a.severity.value.upper()}] {a.rule_name} → {a.action.value}")

    elif cmd == "rules":
        rules = db.list_rules()
        print(f"Detection rules: {len(rules)}")
        for r in rules:
            status = "✓" if r.enabled else "✗"
            print(f"  {status} [{r.severity.value.upper()}] {r.name}")
            print(f"    Action: {r.action.value}  Hits: {r.hit_count}")
            print(f"    Condition: {r.condition_expr}")

    elif cmd == "add-rule":
        if len(args) < 3:
            print("Usage: add-rule <name> <expr> [sev] [action]")
            return
        rule = db.add_rule(
            name=args[1],
            condition_expr=args[2],
            severity=args[3] if len(args) > 3 else "medium",
            action=args[4] if len(args) > 4 else "alert",
        )
        print(f"✓ Rule added: {rule.name} (ID: {rule.id})")

    elif cmd == "alerts":
        sev = args[1] if len(args) > 1 else "low"
        hours = int(args[2]) if len(args) > 2 else 24
        alerts = db.get_alerts(sev, hours)
        print(f"Alerts (>= {sev}, last {hours}h): {len(alerts)}")
        for a in alerts:
            ack = "✓" if a.acknowledged else " "
            print(f"  [{ack}][{a.severity.value.upper()}] {a.rule_name}")
            print(f"    {a.message}  @ {a.timestamp[:19]}")

    elif cmd == "apply":
        if len(args) < 2:
            print("Usage: apply <event_id>")
            return
        alerts = db.apply_rules(args[1])
        print(f"Applied rules to {args[1]}: {len(alerts)} alerts")

    elif cmd == "apply-all":
        count = db.apply_all_pending()
        print(f"✓ Processed pending events, generated {count} alerts")

    elif cmd == "correlate":
        window = int(args[1]) if len(args) > 1 else 300
        corrs = db.correlate_events(window)
        print(f"Correlations found: {len(corrs)}")
        for c in corrs:
            print(f"  [{c['severity'].upper()}] {c['pattern']}")
            if "source_ip" in c:
                print(f"    Source: {c['source_ip']}  Events: {c.get('event_count', c.get('dest_count'))}")

    elif cmd == "stats":
        s = db.dashboard_stats()
        print("SIEM Dashboard Stats:")
        print(f"  Total events: {s['total_events']}")
        print(f"  Total alerts: {s['total_alerts']}")
        print(f"  Unacknowledged: {s['unacknowledged_alerts']}")
        print(f"  By severity: {s['alerts_by_severity']}")
        print(f"  By event type: {s['events_by_type']}")
        print(f"\nTop source IPs:")
        for t in s['top_source_ips'][:5]:
            print(f"  {t['ip']}: {t['count']} events")
        print(f"\nTop triggered rules:")
        for r in s['top_triggered_rules'][:5]:
            print(f"  {r['rule']}: {r['hits']} hits")

    elif cmd == "report":
        fmt = args[1] if len(args) > 1 else "json"
        hours = int(args[2]) if len(args) > 2 else 24
        report = db.export_report(fmt, hours)
        if fmt == "html":
            fname = f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(fname, "w") as f:
                f.write(report)
            print(f"✓ HTML report saved to {fname}")
        else:
            print(report)

    elif cmd == "demo":
        import random
        ips = ["10.0.0.1", "192.168.1.100", "185.220.101.45", "45.33.32.156", "10.0.0.50"]
        events = [
            {"source_ip": "185.220.101.45", "dest_ip": "10.0.0.1",
             "source_port": 54321, "dest_port": 22, "protocol": "tcp",
             "event_type": "auth", "severity": "medium",
             "raw_log": "SSH authentication failed for root from 185.220.101.45"},
            {"source_ip": "185.220.101.45", "dest_ip": "10.0.0.1",
             "source_port": 54322, "dest_port": 22, "protocol": "tcp",
             "event_type": "auth", "severity": "medium",
             "raw_log": "SSH authentication failed for admin from 185.220.101.45"},
            {"source_ip": "10.0.0.100", "dest_ip": "10.0.0.200",
             "source_port": 51000, "dest_port": 3306, "protocol": "tcp",
             "event_type": "network", "severity": "high",
             "raw_log": "Connection to MySQL port 3306 from internal host"},
            {"source_ip": "10.0.0.50", "dest_ip": "8.8.8.8",
             "source_port": 49500, "dest_port": 443, "protocol": "tcp",
             "event_type": "network", "severity": "low",
             "raw_log": "HTTPS connection to external IP, large data transfer"},
            {"source_ip": "10.0.0.1", "dest_ip": "10.0.0.5",
             "source_port": 1025, "dest_port": 80, "protocol": "tcp",
             "event_type": "process", "severity": "high",
             "raw_log": "Suspicious process spawned: cmd.exe /c whoami"},
            {"source_ip": "10.0.0.30", "dest_ip": "10.0.0.1",
             "source_port": 60000, "dest_port": 445, "protocol": "tcp",
             "event_type": "login", "severity": "medium",
             "raw_log": "Failed login for admin@WORKSTATION from 10.0.0.30"},
            {"source_ip": "10.0.0.1", "dest_ip": "10.0.0.1",
             "source_port": 0, "dest_port": 0, "protocol": "tcp",
             "event_type": "registry", "severity": "medium",
             "raw_log": "Registry key modified: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {"source_ip": "10.0.0.99", "dest_ip": "10.0.0.200",
             "source_port": 1024, "dest_port": 5432, "protocol": "tcp",
             "event_type": "network", "severity": "high",
             "raw_log": "PostgreSQL access from unusual host"},
            {"source_ip": "10.0.0.1", "dest_ip": "10.0.0.50",
             "source_port": 500, "dest_port": 600, "protocol": "tcp",
             "event_type": "file", "severity": "medium",
             "raw_log": "File deletion event: /var/log/secure deleted by user root"},
        ]

        ingested = 0
        all_alerts = 0
        for ev in events:
            event = db.ingest_event("demo_source", ev)
            alerts = db.apply_rules(event.id)
            ingested += 1
            all_alerts += len(alerts)
        print(f"✓ Demo: ingested {ingested} events, generated {all_alerts} alerts")
        corrs = db.correlate_events(3600)
        print(f"✓ Demo: found {len(corrs)} correlations")
        s = db.dashboard_stats()
        print(f"✓ Stats: {s['total_events']} events, {s['total_alerts']} alerts, {s['unacknowledged_alerts']} unacked")
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
