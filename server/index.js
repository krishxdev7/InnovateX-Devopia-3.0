// npm install
// node index.js

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const app = express();
const PORT = 3000;

// Ensure uploads folder exists at startup
const uploadsDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

// Enable CORS
app.use(cors());

// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// POST /analyze endpoint
app.post('/analyze', upload.single('file'), (req, res) => {
  console.log('Request received for /analyze');

  if (!req.file) {
    return res.status(400).json({ success: false, error: 'No file uploaded' });
  }

  const filePath = req.file.path;
  const pythonScript = path.join(__dirname, '..', 'project-shreya', 'src', 'log_integrity.py');

  console.log('Python starting');

  const pythonProcess = spawn('python', ["../project-shreya/src/log_integrity.py", "--file", filePath], {
    env: {
      ...process.env,
      PYTHONIOENCODING: "utf-8"
    }
  });

  let stdout = '';
  let stderr = '';

  pythonProcess.stdout.on('data', (data) => {
    stdout += data.toString('utf-8');
  });

  pythonProcess.stderr.on('data', (data) => {
    stderr += data.toString();
  });

  pythonProcess.on('close', (code) => {
    console.log('Python ended');

    // Delete uploaded file
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error('Error deleting file:', err);
      }
    });

    // Check exit code only for success determination
    if (code === 0) {
      res.json({ success: true, terminal: stdout });
    } else {
      const errorMessage = stderr || `Process exited with code ${code}`;
      res.json({ success: false, error: errorMessage });
    }
  });

  pythonProcess.on('error', (error) => {
    console.log('Python ended');
    
    // Delete uploaded file
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error('Error deleting file:', err);
      }
    });

    res.json({ success: false, error: error.message });
  });
});

app.listen(PORT, () => {
  console.log(`Express server listening on port ${PORT}`);
});
