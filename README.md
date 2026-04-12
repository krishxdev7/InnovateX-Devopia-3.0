# The Evidence Protector - Automated Log Integrity Monitor

> Fast, forensic-grade log analysis to detect tampering signals in massive system logs.

![Python](https://img.shields.io/badge/Python-Standard%20Library%20Only-3776AB?logo=python&logoColor=white)
![Backend](https://img.shields.io/badge/Backend-Node.js-339933?logo=node.js&logoColor=white)
![Frontend](https://img.shields.io/badge/Frontend-HTML%20%7C%20CSS%20%7C%20JS-111827)

## Problem
Modern systems generate huge volumes of logs. If attackers delete or manipulate entries, they introduce suspicious time gaps that are difficult to catch manually.

## Solution Overview
The Evidence Protector is a Python-first log integrity monitor with a lightweight web interface and backend bridge.

It scans logs line-by-line, detects anomalies, scores risk, and exports forensic reports for security workflows.

## Key Features
- 🔍 **Gap Detection**: Detects abnormal timestamp gaps that may indicate tampering.
- ⚠️ **Error Burst Detection**: Flags dense clusters of error events.
- 🧭 **Risk Classification**: Labels findings as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- 🔗 **Chain Hashing**: Preserves an integrity chain across parsed log entries.
- 📄 **CSV Report Generation**: Exports structured forensic output for review.
- 🛡️ **Malformed Line Safety**: Handles broken or malformed lines without crashing.
- ⚡ **Large Log Ready**: Designed to process large log files efficiently.

## Tech Stack
- **Python** (standard library only)
- **Node.js** (backend API)
- **HTML, CSS, JavaScript** (frontend)

## Architecture and Project Structure
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

**Component roles**
- `src/`: Core Python integrity analyzer logic.
- `tools/`: Log generation utilities for testing and scale simulation.
- `server/`: Backend endpoint for file upload and analyzer execution.
- `assets/` + `index.html`: Frontend UI for user interaction and results.
- `data/`: Sample input and generated forensic reports.

## How To Run

### 1) Start Backend
```bash
cd server
npm install
npm start
```

### 2) Run Python CLI
```bash
python src/log_integrity.py --file data/sample/sample.log --out data/reports/report.csv
```

### 3) Open Frontend
Open `index.html` in your browser.

## Example Output
```text
[*] Analyzing: data/sample/sample.log

[OK] CSV report generated successfully: data/reports/report.csv

Lines parsed 200
Time gaps detected 3
Error bursts 27
Risk level CRITICAL
```

## What You Get
- Time gap detection
- Risk level classification
- CSV forensic report output

## Special Notes
- Only one sample log is tracked in this repository: `data/sample/sample.log`
- Other `.log` files are ignored via `.gitignore`
- Built for hackathon speed and real-world forensic scalability

## Future Improvements
- Add JSON and PDF forensic report export
- Add timeline visualizations for anomaly exploration
- Support real-time stream monitoring from log sources
- Add pluggable threat scoring policies per environment

## Contributing
Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit focused changes
4. Open a pull request with a clear description
