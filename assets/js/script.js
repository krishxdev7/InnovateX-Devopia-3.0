(function () {
  function initEvidenceProtector() {
    var uploadForm = document.getElementById("uploadForm");
    if (!uploadForm) return;

    var analyzeBtn = document.getElementById("btn-analyze");
    var logFileInput = document.getElementById("logFile");
    var thresholdInput = document.getElementById("threshold");

    var terminalSection = document.getElementById("terminal-section");
    var terminalLoading = document.getElementById("terminal-loading");
    var terminalBody = document.getElementById("terminal-body");

    var statLines = document.getElementById("stat-lines-parsed");
    var statGaps = document.getElementById("stat-gaps");
    var statBursts = document.getElementById("stat-bursts");
    var statRisk = document.getElementById("stat-risk");
    var statsPlaceholder = document.getElementById("stats-placeholder");

    if (terminalLoading) terminalLoading.style.display = "none";

    // Visual proof that JS is running (replaces the static demo line)
    if (terminalBody) {
      terminalBody.innerHTML = "<div><span class=\"t-cmd t-dim\">$ ready — choose a file and click Analyze Log</span></div>";
    }

    var isLoading = false;

    function stripAnsi(text) {
      return String(text == null ? "" : text).replace(/\u001b\[[0-9;]*m/g, "");
    }

    function appendTimelineBar(div, text) {
      var run = "";
      var runClass = "";

      function flushRun() {
        if (!run.length) return;
        if (!runClass) {
          div.appendChild(document.createTextNode(run));
        } else {
          var span = document.createElement("span");
          span.className = runClass;
          span.textContent = run;
          div.appendChild(span);
        }
        run = "";
      }

      for (var i = 0; i < text.length; i++) {
        var ch = text.charAt(i);
        var nextClass = "";
        if (ch === "#") nextClass = "timeline-critical";
        else if (ch === ".") nextClass = "timeline-clean";

        if (nextClass !== runClass) {
          flushRun();
          runClass = nextClass;
        }
        run += ch;
      }
      flushRun();
    }

    function appendTerminalLine(text) {
      if (!terminalBody) return;

      var clean = stripAnsi(text);
      var div = document.createElement("div");
      div.className = "terminal-line";

      if (/^\s*[#.]+\s*$/.test(clean)) {
        appendTimelineBar(div, clean);
      } else {
        div.textContent = clean;

        if (/^\s*Timeline:\s*$/i.test(clean)) {
          div.classList.add("term-cyan", "term-bold");
        } else if (/^\s*Most Critical Gap\s*$/i.test(clean)) {
          div.classList.add("term-red", "term-bold");
        } else if (/^\s*Final Risk:\s*/i.test(clean)) {
          var upper = clean.toUpperCase();
          if (/COMPROMISED|HIGH RISK|CRITICAL|HIGH/.test(upper)) {
            div.classList.add("term-red", "term-bold");
          } else if (/MODERATE RISK|LOW RISK|MEDIUM|LOW/.test(upper)) {
            div.classList.add("term-amber", "term-bold");
          } else {
            div.classList.add("term-green", "term-bold");
          }
        } else if (/^\s*Exported reports\s*$/i.test(clean) || /^\s*Structured summary:\s*$/i.test(clean)) {
          div.classList.add("term-cyan", "term-bold");
        } else if (/^\s*(Start:|End\s*:)/i.test(clean)) {
          div.classList.add("term-dim");
        } else if (/\[CRITICAL\]/i.test(clean)) {
          div.classList.add("term-red");
        } else if (/\[SUSPICIOUS\]/i.test(clean)) {
          div.classList.add("term-amber");
        } else if (/\[WARNING\]/i.test(clean)) {
          div.classList.add("term-amber");
        }
      }

      terminalBody.appendChild(div);
      terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    function showTerminalError(msg) {
      if (!terminalBody) return;
      terminalBody.innerHTML = "";
      var div = document.createElement("div");
      div.textContent = "Error: " + msg;
      div.style.color = "#ff4d4d";
      terminalBody.appendChild(div);
    }

    function setLoading(loading) {
      isLoading = loading;
      if (terminalLoading) terminalLoading.style.display = loading ? "block" : "none";
      if (analyzeBtn) {
        analyzeBtn.disabled = loading;
        analyzeBtn.style.opacity = loading ? "0.7" : "1";
      }
    }

    function parseStat(text, re) {
      var m = text.match(re);
      return m ? m[1] : null;
    }

    function updateStatsFromOutput(text) {
      if (!text) text = "";

      var parsed = parseStat(text, /Lines\s+parsed[:\s]+(\d+)/i);
      var gaps = parseStat(text, /Time\s+gaps\s+detected[:\s]+(\d+)/i);
      var bursts = parseStat(text, /Error\s+bursts[:\s]+(\d+)/i);
      var risk = parseStat(
        text,
        /Risk\s+level[:\s]+(COMPROMISED|HIGH\s+RISK|MODERATE\s+RISK|LOW\s+RISK|CLEAN|CRITICAL|HIGH|MEDIUM|LOW)/i
      );

      if (!risk) {
        var anyLevel = text.match(/\b(COMPROMISED|HIGH\s+RISK|MODERATE\s+RISK|LOW\s+RISK|CLEAN|CRITICAL|HIGH|MEDIUM|LOW)\b/i);
        risk = anyLevel ? anyLevel[1] : null;
      }

      if (statLines && parsed !== null) statLines.innerText = parsed;
      if (statGaps && gaps !== null) statGaps.innerText = gaps;
      if (statBursts && bursts !== null) statBursts.innerText = bursts;

      if (statRisk && risk) {
        var level = String(risk).toUpperCase();
        statRisk.innerText = level;
        statRisk.className = "stat-value";
        if (level === "COMPROMISED" || level === "HIGH RISK" || level === "CRITICAL" || level === "HIGH") {
          statRisk.classList.add("text-red");
        } else if (level === "MODERATE RISK" || level === "LOW RISK" || level === "MEDIUM" || level === "LOW") {
          statRisk.classList.add("text-amber");
        }
      }
    }

    function postFormData(url, formData, cb) {
      if (window.fetch) {
        fetch(url, { method: "POST", body: formData })
          .then(function (resp) {
            var status = resp.status;
            return resp
              .json()
              .then(function (json) {
                cb(null, json, status, resp.ok);
              })
              .catch(function () {
                cb("Backend did not return JSON.", null, status, false);
              });
          })
          .catch(function () {
            cb("Server error. Make sure backend is running on http://localhost:3000", null, 0, false);
          });
        return;
      }

      // XHR fallback (older browsers)
      var xhr = new XMLHttpRequest();
      xhr.open("POST", url, true);
      xhr.onreadystatechange = function () {
        if (xhr.readyState !== 4) return;
        var status = xhr.status || 0;
        var json = null;
        try {
          json = JSON.parse(xhr.responseText || "");
        } catch (e) {
          cb("Backend did not return JSON.", null, status, false);
          return;
        }
        cb(null, json, status, status >= 200 && status < 300);
      };
      xhr.onerror = function () {
        cb("Server error. Make sure backend is running on http://localhost:3000", null, 0, false);
      };
      xhr.send(formData);
    }

    function runAnalysis(e) {
      if (e && e.preventDefault) e.preventDefault();
      if (e && e.stopPropagation) e.stopPropagation();
      if (isLoading) return;

      if (!logFileInput || !logFileInput.files || logFileInput.files.length === 0) {
        alert("⚠️ Action Required: Please select a log file before starting analysis.");
        return;
      }

      var file = logFileInput.files[0];
      var thresholdValue = "300";
      if (thresholdInput && thresholdInput.value) thresholdValue = thresholdInput.value;

      if (terminalSection && terminalSection.classList) terminalSection.classList.remove("hidden");
      if (terminalBody) terminalBody.innerHTML = "";

      appendTerminalLine("Selected file: " + file.name + " (" + file.size + " bytes)");
      appendTerminalLine("Threshold: " + thresholdValue + "s");
      appendTerminalLine("Uploading to backend...\n");

      if (statsPlaceholder) statsPlaceholder.style.display = "none";
      if (statLines) statLines.innerText = "...";
      if (statGaps) statGaps.innerText = "...";
      if (statBursts) statBursts.innerText = "...";
      if (statRisk) {
        statRisk.innerText = "...";
        statRisk.className = "stat-value";
      }

      setLoading(true);

      var formData = new FormData();
      formData.append("file", file);
      formData.append("threshold", thresholdValue);

      postFormData("http://localhost:3000/analyze", formData, function (err, data, status, ok) {
        setLoading(false);

        if (err) {
          showTerminalError(err);
          if (terminalSection && terminalSection.scrollIntoView) terminalSection.scrollIntoView({ behavior: "smooth" });
          return;
        }

        if (!ok || !data || !data.success) {
          var msg = (data && data.error) ? data.error : "Request failed (" + status + ")";
          showTerminalError(msg);
          if (terminalSection && terminalSection.scrollIntoView) terminalSection.scrollIntoView({ behavior: "smooth" });
          return;
        }

        if (terminalBody) terminalBody.innerHTML = "";

        var output = (data.terminal != null) ? String(data.terminal) : "";
        if (!output.replace(/\s/g, "").length) {
          appendTerminalLine("(No output received from analyzer.)");
        } else {
          var lines = output.split(/\r?\n/);
          for (var i = 0; i < lines.length; i++) appendTerminalLine(lines[i]);
        }

        updateStatsFromOutput(output);
        if (terminalSection && terminalSection.scrollIntoView) terminalSection.scrollIntoView({ behavior: "smooth" });
      });
    }

    // Prevent page reload even if something else tries to submit
    uploadForm.addEventListener("submit", runAnalysis);
    if (analyzeBtn) analyzeBtn.addEventListener("click", runAnalysis);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initEvidenceProtector);
  } else {
    initEvidenceProtector();
  }
})();
