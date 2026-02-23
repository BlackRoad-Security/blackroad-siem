# blackroad-siem

> Security Information and Event Management system — BlackRoad Security

[![CI](https://github.com/BlackRoad-Security/blackroad-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackRoad-Security/blackroad-siem/actions/workflows/ci.yml)

Full-featured SIEM: ingest security events, evaluate detection rules, correlate attack patterns, and generate security reports.

## Features

- 📥 **Event Ingestion**: Normalize events from any source (firewall, IDS, EDR, auth logs)
- 🔍 **Detection Rules**: DSL-based conditions evaluated against every event (10 defaults)
- 🔗 **Correlation**: Detect brute-force and lateral movement patterns automatically
- 🚨 **Alerting**: Severity-tiered alerts with acknowledgement workflow
- 📊 **Dashboard Stats**: Top source IPs, most-triggered rules, alert breakdown
- 📄 **Reports**: Export security reports as JSON or HTML
- 💾 **SQLite**: Embedded database, no external services

## Quick Start

```bash
# Load demo events and see alerts fire
python siem.py demo

# View dashboard stats
python siem.py stats

# List all alerts (medium and above, last 24h)
python siem.py alerts medium 24

# Ingest a custom event
python siem.py ingest "firewall" '{"source_ip":"1.2.3.4","dest_port":22,"event_type":"auth","raw_log":"SSH failed"}'

# Detect correlated patterns (brute-force, lateral movement)
python siem.py correlate 3600

# Export HTML report
python siem.py report html 24

# List all detection rules
python siem.py rules

# Add a custom rule
python siem.py add-rule "rdp-access" "dest_port == 3389" high alert
```

## Default Detection Rules

| Rule | Condition | Severity | Action |
|------|-----------|----------|--------|
| brute-force-ssh | SSH auth events | high | alert |
| port-scan | Low src port → high dst port | medium | alert |
| failed-login | Login with "failed" in log | medium | alert |
| suspicious-process | cmd.exe in process log | high | alert |
| data-exfil | Outbound HTTPS from ephemeral port | medium | log |
| admin-login-offhours | "admin" in login log | high | alert |
| registry-modification | HKLM registry change | medium | alert |
| critical-port-access | MySQL/Postgres/Redis/Mongo | high | alert |
| icmp-flood | ICMP traffic | low | log |
| file-deletion | File delete event | medium | alert |

## API

```python
from siem import SIEM

db = SIEM("siem.db")

# Ingest event
event = db.ingest_event("source", {
    "source_ip": "10.0.0.1",
    "dest_port": 22,
    "event_type": "auth",
    "raw_log": "SSH login failed"
})

# Apply rules
alerts = db.apply_rules(event.id)

# Correlation
correlations = db.correlate_events(window_secs=300)

# Get alerts
alerts = db.get_alerts(severity_min="high", hours=24)

# Dashboard
stats = db.dashboard_stats()

# Report
html_report = db.export_report("html", hours=24)
```

## Running Tests

```bash
pip install pytest
pytest test_siem.py -v
```
