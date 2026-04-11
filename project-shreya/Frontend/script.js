document.addEventListener("DOMContentLoaded", () => {
  // 1. Grab all necessary elements
  const analyzeBtn = document.getElementById("btn-analyze");
  const logFileInput = document.getElementById("logFile");
  const thresholdInput = document.getElementById("threshold");

  const terminalSection = document.getElementById("terminal-section");
  const terminalLoading = document.getElementById("terminal-loading");
  const terminalBody = document.getElementById("terminal-body");

  const statLines = document.getElementById("stat-lines-parsed");
  const statGaps = document.getElementById("stat-gaps");
  const statBursts = document.getElementById("stat-bursts");
  const statRisk = document.getElementById("stat-risk");
  const statsPlaceholder = document.querySelector(".stats-placeholder");

  // 2. Listen for the "Analyze Log" button click
  analyzeBtn.addEventListener('click', async (e) => {
    e.preventDefault();

    // VALIDATION
    if (!logFileInput.files || logFileInput.files.length === 0) {
        alert('⚠️ Action Required: Please select a .log file before starting analysis.');
        return;
    }

    const file = logFileInput.files[0];

    // PREPARE FORM DATA
    const formData = new FormData();
    formData.append("file", file);

    // UI RESET
    terminalSection.classList.remove('hidden');
    terminalLoading.style.display = 'block';
    terminalBody.innerHTML = '';

    if (statsPlaceholder) statsPlaceholder.style.display = 'none';

    statLines.innerText = '...';
    statGaps.innerText = '...';
    statBursts.innerText = '...';
    statRisk.innerText = '...';
    statRisk.className = 'stat-value';

    try {
        // CALL BACKEND
        const response = await fetch("http://localhost:3000/analyze", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        terminalLoading.style.display = 'none';

        if (!data.success) {
            terminalBody.innerHTML = `<div style="color:red;">Error: ${data.error}</div>`;
            return;
        }

        // RENDER TERMINAL OUTPUT (CLEAN + LINE BY LINE)
        terminalBody.innerHTML = '';

        const lines = data.terminal.split('\n');

        lines.forEach(line => {
            const div = document.createElement('div');
            div.textContent = line;
            terminalBody.appendChild(div);
        });

        // BASIC STATS EXTRACTION (SAFE PARSING)
        const text = data.terminal;

        const linesParsedMatch = text.match(/Lines parsed\s+(\d+)/);
        const gapsMatch = text.match(/Time gaps detected\s+(\d+)/);
        const burstsMatch = text.match(/Error bursts\s+(\d+)/);
        const riskMatch = text.match(/CRITICAL|HIGH|MEDIUM|LOW/);

        if (linesParsedMatch) statLines.innerText = linesParsedMatch[1];
        if (gapsMatch) statGaps.innerText = gapsMatch[1];
        if (burstsMatch) statBursts.innerText = burstsMatch[1];

        if (riskMatch) {
            statRisk.innerText = riskMatch[0];
            statRisk.className = 'stat-value';

            if (riskMatch[0] === 'CRITICAL') statRisk.classList.add('text-red');
            else if (riskMatch[0] === 'HIGH') statRisk.classList.add('text-amber');
        }

        // AUTO SCROLL
        terminalSection.scrollIntoView({ behavior: 'smooth' });

    } catch (err) {
        console.error(err);
        terminalLoading.style.display = 'none';
        terminalBody.innerHTML = `<div style="color:red;">Server error. Make sure backend is running.</div>`;
    }
});
});
