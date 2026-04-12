// npm install
// node index.js

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn, spawnSync } = require('child_process');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const pythonScript = path.join(__dirname, '..', 'src', 'log_integrity.py');

function resolvePythonCommand() {
  const candidates = [];

  if (process.env.PYTHON) {
    candidates.push(process.env.PYTHON);
  }

  if (process.platform === 'win32') {
    candidates.push(path.join(__dirname, '..', '.venv', 'Scripts', 'python.exe'));
    candidates.push(path.join(__dirname, '..', '.venvpy', 'Scripts', 'python.exe'));
  } else {
    candidates.push(path.join(__dirname, '..', '.venv', 'bin', 'python'));
  }

  candidates.push('python3', 'python', 'py');

  for (const command of candidates) {
    if (path.isAbsolute(command) && !fs.existsSync(command)) {
      continue;
    }

    const result = spawnSync(command, ['--version'], {
      encoding: 'utf-8',
      stdio: 'pipe'
    });

    if (!result.error && result.status === 0) {
      return command;
    }
  }

  return null;
}

const pythonCommand = resolvePythonCommand();

// Ensure uploads folder exists at startup
// NOTE: When the frontend is served via Live Server, writing files inside the workspace can trigger auto-reloads.
// We keep server\uploads for the intended file:// workflow, and use an OS temp folder for http origins.
const uploadsDir = path.join(__dirname, 'uploads');
const tmpUploadsDir = path.join(os.tmpdir(), 'evidence-protector-uploads');
fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(tmpUploadsDir, { recursive: true });

// Enable CORS
app.use(cors());

// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const origin = (req.headers && req.headers.origin) ? String(req.headers.origin) : '';
    const isHttpOrigin = origin && origin !== 'null';
    cb(null, isHttpOrigin ? tmpUploadsDir : uploadsDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

function sanitizePythonError(stderr, stdout, code) {
  const combined = [String(stderr || ''), String(stdout || '')].filter(Boolean).join('\n');
  if (!combined.trim()) return `Analysis failed (exit code ${code}).`;

  const cleaned = combined
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => {
      if (/^Traceback \(most recent call last\):/.test(line)) return false;
      if (/^File ".*", line \d+/.test(line)) return false;
      if (/^During handling of the above exception/.test(line)) return false;
      if (/^[~^\-]+$/.test(line)) return false;
      return true;
    });

  const preferred = cleaned.find((line) =>
    /error|failed|invalid|not found|unexpected|configuration/i.test(line)
  );
  const message = preferred || cleaned[cleaned.length - 1] || `Analysis failed (exit code ${code}).`;
  return message.length > 500 ? `${message.slice(0, 497)}...` : message;
}

// POST /analyze endpoint
app.post('/analyze', upload.single('file'), (req, res) => {
  console.log('[POST] /analyze');

  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded (field name must be "file").' });
  }

  const filePath = req.file.path;

  const thresholdRaw = req.body?.threshold;
  const threshold = Number.isFinite(parseInt(thresholdRaw, 10)) ? parseInt(thresholdRaw, 10) : 300;

  // Write the CSV report to OS temp to avoid triggering any frontend auto-reload (e.g. Live Server).
  const reportOutPath = path.join(os.tmpdir(), `integrity_report_${path.basename(filePath)}.csv`);

  const cleanupUpload = () => {
    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting uploaded file:', err);
    });
    fs.unlink(reportOutPath, () => {
      // ignore
    });
  };

  console.log('Running python:', pythonScript);
  console.log('Uploaded file:', filePath);
  console.log('Threshold:', threshold);
  console.log('Report out:', reportOutPath);

  if (!fs.existsSync(pythonScript)) {
    cleanupUpload();
    return res.status(500).json({
      success: false,
      error: `Analyzer script not found at ${pythonScript}`
    });
  }

  if (!pythonCommand) {
    cleanupUpload();
    return res.status(500).json({
      success: false,
      error: 'Python is not installed or not available on PATH. Install Python 3 and restart the backend.'
    });
  }

  console.log('Python command:', pythonCommand);

  let responded = false;
  const replyOnce = (status, payload) => {
    if (responded) return;
    responded = true;
    res.status(status).json(payload);
  };

  // -u: unbuffered stdout/stderr so the frontend gets full terminal output reliably
  const pythonProcess = spawn(pythonCommand, ['-u', pythonScript, '--file', filePath, '--threshold', String(threshold), '--out', reportOutPath], {
    env: {
      ...process.env,
      PYTHONIOENCODING: 'utf-8'
    }
  });

  let stdout = '';
  let stderr = '';

  pythonProcess.stdout.on('data', (data) => {
    stdout += data.toString('utf-8');
  });

  pythonProcess.stderr.on('data', (data) => {
    stderr += data.toString('utf-8');
  });

  pythonProcess.on('close', (code) => {
    console.log('Python exited with code:', code);
    console.log('Python stdout length:', stdout.length);
    console.log('Python stderr length:', stderr.length);
    if (stderr) console.error('Python stderr:', stderr);

    cleanupUpload();

    if (code === 0 || code === 1 || code === 2) {
      return replyOnce(200, { success: true, terminal: stdout });
    }

    const errorMessage = sanitizePythonError(stderr, stdout, code);
    return replyOnce(500, { success: false, error: errorMessage });
  });

  pythonProcess.on('error', (error) => {
    console.error('Failed to start python process:', error);
    cleanupUpload();
    return replyOnce(500, { success: false, error: error.message });
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled backend error:', err);
  if (res.headersSent) {
    return next(err);
  }
  return res.status(500).json({
    success: false,
    error: err?.message || 'Internal server error.'
  });
});

const server = app.listen(PORT, () => {
  console.log(`Express server listening on port ${PORT}`);
});

server.on('error', (error) => {
  if (error && error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Stop the other process or run with PORT=<port> npm run dev.`);
    process.exit(1);
  }

  console.error('Server failed to start:', error);
  process.exit(1);
});
