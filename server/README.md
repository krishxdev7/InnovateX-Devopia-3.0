# Devopia Backend Server

Express.js backend for the Devopia project.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
node index.js
```

The server will run on port 3000.

## API Endpoints

### POST /analyze
Accepts a single file upload with the key `file`.

**Request:**
- Method: POST
- Content-Type: multipart/form-data
- Field: file (single file)

**Response:**
- Success: `{ "success": true, "terminal": "<python output>" }`
- Error: `{ "success": false, "error": "<error message>" }`

The endpoint:
- Logs when request is received
- Logs when Python script starts
- Logs when Python script ends
- Runs: `python ../src/log_integrity.py --file <file_path> --threshold <seconds> --out <csv_path>`
- Captures full stdout and stderr
- Deletes the uploaded file after processing
- Returns terminal output (not parsed JSON from Python)

## Notes

- The backend auto-detects Python from these candidates: `PYTHON` env var, local virtual environments (`../.venv` or `../.venvpy`), then `python3`/`python`/`py` on PATH.
- If port `3000` is already in use, start with a custom port:

```bash
$env:PORT=3001; npm run dev
```

## Directory Structure

```
server/
├── index.js          # Main server file
├── package.json      # Dependencies
├── uploads/          # Temporary file storage
└── node_modules/     # Dependencies (created after npm install)
```
