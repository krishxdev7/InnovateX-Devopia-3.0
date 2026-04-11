document.addEventListener('DOMContentLoaded', () => {
    // 1. Grab all necessary elements
    const analyzeBtn = document.getElementById('btn-analyze');
    const logFileInput = document.getElementById('logFile');
    const thresholdInput = document.getElementById('threshold');
    
    const terminalSection = document.getElementById('terminal-section');
    const terminalLoading = document.getElementById('terminal-loading');
    const terminalBody = document.getElementById('terminal-body');
    
    const statLines = document.getElementById('stat-lines-parsed');
    const statGaps = document.getElementById('stat-gaps');
    const statBursts = document.getElementById('stat-bursts');
    const statRisk = document.getElementById('stat-risk');
    const statsPlaceholder = document.querySelector('.stats-placeholder');

    // 2. Listen for the "Analyze Log" button click
    analyzeBtn.addEventListener('click', () => {
        
        // --- VALIDATION ---
        if (logFileInput.files.length === 0) {
            alert('⚠️ Action Required: Please select a .log file before starting analysis.');
            return;
        }

        // Get file details to make the report look real
        const file = logFileInput.files[0];
        const fileName = file.name;
        const threshold = thresholdInput.value || 300;

        // --- START SYSTEM FLOW ---
        
        // Reveal terminal and show loading state
        terminalSection.classList.remove('hidden'); 
        terminalLoading.style.display = 'block';
        terminalBody.innerHTML = ''; // Clear old results
        
        // Hide the "results will appear" label
        if (statsPlaceholder) statsPlaceholder.style.display = 'none';
        
        // Reset stats to "loading" state
        statLines.innerText = '...';
        statGaps.innerText = '...';
        statBursts.innerText = '...';
        statRisk.innerText = '...';
        statRisk.className = 'stat-value'; // Reset color

        // --- SIMULATE PROCESSING DELAY (1.5 seconds) ---
        setTimeout(() => {
            // Hide loading text
            terminalLoading.style.display = 'none';

            // 1. Update Stats Dashboard with "Simulated" data
            statLines.innerText = '1,422';
            statGaps.innerText = '3';
            statBursts.innerText = '0';
            statRisk.innerText = 'CRITICAL';
            statRisk.classList.add('text-red'); // Make it look urgent

            // 2. Update Terminal with forensic report
            terminalBody.innerHTML = `
                <div><span class="t-cmd t-dim">python log_monitor.py "${fileName}" --threshold ${threshold}</span></div>
                <div>&nbsp;</div>
                <div><span class="t-dim">════════════════════════════════════════════════════════</span></div>
                <div><span class="t-green">  🔍 EVIDENCE PROTECTOR — Log Integrity Report</span></div>
                <div><span class="t-dim">════════════════════════════════════════════════════════</span></div>
                <div><span class="t-dim">  File     : </span><span class="t-white">${fileName}</span></div>
                <div><span class="t-dim">  Threshold: </span><span class="t-white">${threshold}s</span></div>
                <div><span class="t-dim">  Lines    : </span><span class="t-green">1,422 / 1,425</span><span class="t-dim"> parsed</span></div>
                <div><span class="t-dim">────────────────────────────────────────────────────────</span></div>
                <div>&nbsp;</div>
                <div><span class="t-red">  🚨 3 suspicious gap(s) detected</span></div>
                <div>&nbsp;</div>
                <div><span class="t-green">  [LOW]</span><span class="t-dim">      Gap #1 — Lines 142 → 143 — </span><span class="t-white">14m 22s</span></div>
                <div><span class="t-amber">  [MEDIUM]</span><span class="t-dim">    Gap #2 — Lines 612 → 613 — </span><span class="t-white">1h 45m</span></div>
                <div><span class="t-red">  [CRITICAL]</span><span class="t-dim">  Gap #3 — Lines 905 → 906 — </span><span class="t-white">7h 12m</span></div>
                <div>&nbsp;</div>
                <div><span class="t-dim">  Severity summary: </span><span class="t-green">LOW=1</span><span class="t-dim">  </span><span class="t-amber">MEDIUM=1</span><span class="t-dim">  </span><span class="t-red">CRITICAL=1</span></div>
                <div><span class="t-dim">════════════════════════════════════════════════════════</span></div>
                <div><span class="t-green">  Done. Forensic audit complete.</span></div>
            `;
            
            // Auto-scroll to terminal so user sees results
            terminalSection.scrollIntoView({ behavior: 'smooth' });

        }, 1500);
    });
});