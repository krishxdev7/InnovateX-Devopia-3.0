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
- Runs: `python ../project-shreya/src/log_integrity.py <file_path>`
- Captures full stdout and stderr
- Deletes the uploaded file after processing
- Returns terminal output (not parsed JSON from Python)

## Directory Structure

```
server/
├── index.js          # Main server file
├── package.json      # Dependencies
├── uploads/          # Temporary file storage
└── node_modules/     # Dependencies (created after npm install)
```
