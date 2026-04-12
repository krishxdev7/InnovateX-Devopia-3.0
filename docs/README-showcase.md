# The Evidence Protector - Showcase README

> Detect log tampering signals in seconds with automated forensic analysis.

## Why This Project Matters
Modern infrastructure generates massive logs. When attackers delete or manipulate entries, suspicious timeline gaps appear, but manual detection is slow, error-prone, and hard to scale.

The Evidence Protector automates that process and turns raw logs into actionable integrity findings.

## What It Delivers
- 🔍 Detects suspicious timestamp gaps in log sequences
- ⚠️ Identifies error bursts that may indicate incidents
- 🧭 Classifies risk as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- 🔗 Preserves a chain hash across parsed log entries
- 📄 Exports forensic CSV reports for investigation workflows
- 🛡️ Handles malformed lines safely without crashing
- ⚡ Processes large logs efficiently

## Solution Snapshot
1. User uploads a log or runs CLI analysis
2. Python engine parses lines and extracts timestamps
3. Gap and anomaly logic scores forensic risk
4. Reports are generated for operational follow-up

## Tech Stack
- Python (standard library only)
- Node.js backend
- HTML, CSS, JavaScript frontend

## Project Layout
```text
root/
|- index.html
|- assets/
|  |- css/style.css
|  |- js/script.js
|- server/
|- src/
|- tools/
|- data/
|  |- sample/sample.log
|  |- reports/
|- docs/
```

## Quick Start
### Backend
```bash
cd server
npm install
npm start
```

### Python CLI
```bash
python src/log_integrity.py --file data/sample/sample.log --out data/reports/report.csv
```

### Frontend
Open `index.html` in your browser.

## Example CLI Output
```text
[*] Analyzing: data/sample/sample.log

[OK] CSV report generated successfully: data/reports/report.csv

Lines parsed 200
Time gaps detected 3
Error bursts 27
Risk level CRITICAL
```

## Production Notes
- Only one sample log is intentionally tracked: `data/sample/sample.log`
- Other `.log` files are ignored via `.gitignore`
- Architecture is structured for scale-up and forensic workflows

## Next Improvements
- Streaming log ingestion (real-time detection)
- JSON/PDF export options
- Visual timeline of anomalies
- Policy-based scoring per environment

## Contribution
Contributions are welcome via focused pull requests with clear scope and rationale.
