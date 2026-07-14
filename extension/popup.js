// PhishGuard Extension Popup Controller
// Binds UI controls, pings the backend, handles manual text, URL, and file/zip checks.

const FLASK_SERVER = "https://phishguard-api-fzds.onrender.com";

document.addEventListener("DOMContentLoaded", () => {
  const modelSelect = document.getElementById("extModelSelect");
  const manualText = document.getElementById("manualText");
  const btnAnalyze = document.getElementById("btnAnalyze");
  const connectionStatus = document.getElementById("connectionStatus");
  const resultsBlock = document.getElementById("resultsBlock");
  
  const whitelistInput = document.getElementById("whitelistInput");
  const btnAddWhitelist = document.getElementById("btnAddWhitelist");
  const whitelistList = document.getElementById("whitelistList");

  // URL Tab Controls
  const manualUrlInput = document.getElementById("manualUrlInput");
  const btnScanUrl = document.getElementById("btnScanUrl");

  // File Tab Controls
  const fileDropzone = document.getElementById("fileDropzone");
  const fileInput = document.getElementById("fileInput");
  const dropzoneText = document.getElementById("dropzoneText");
  const selectedFileName = document.getElementById("selectedFileName");
  const btnScanFile = document.getElementById("btnScanFile");

  const resIcon = document.getElementById("resIcon");
  const resTitle = document.getElementById("resTitle");
  const resSub = document.getElementById("resSub");
  const resScore = document.getElementById("resScore");
  const resAction = document.getElementById("resAction");

  // ZIP contents and reasons output containers
  const resFileDetails = document.getElementById("resFileDetails");
  const innerFilesList = document.getElementById("innerFilesList");
  const resReasonsBlock = document.getElementById("resReasonsBlock");
  const resReasonsList = document.getElementById("resReasonsList");

  let selectedFileObj = null;

  // 1. Check server connection status
  pingBackend();

  // 2. Load saved classifier configuration
  chrome.storage.local.get({ selectedModel: "nb" }, (settings) => {
    modelSelect.value = settings.selectedModel;
  });

  // 3. Save classifier configuration changes
  modelSelect.addEventListener("change", () => {
    const selected = modelSelect.value;
    chrome.storage.local.set({ selectedModel: selected });
  });

  // 4. Load and render local whitelisted domains
  loadAndRenderWhitelist();

  // 5. Add custom domain to whitelist
  btnAddWhitelist.addEventListener("click", () => {
    const domain = whitelistInput.value.trim().toLowerCase();
    if (!domain) return;
    if (!domain.includes(".") || domain.length < 4) {
      alert("Please enter a valid domain format (e.g. trusted.com).");
      return;
    }
    chrome.storage.local.get({ whitelistedDomains: [] }, (settings) => {
      const currentList = settings.whitelistedDomains;
      if (!currentList.includes(domain)) {
        currentList.push(domain);
        chrome.storage.local.set({ whitelistedDomains: currentList }, () => {
          whitelistInput.value = "";
          loadAndRenderWhitelist();
        });
      } else {
        alert("Domain is already whitelisted.");
      }
    });
  });

  // 6. Tab Navigation Logic
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      // Deactivate all
      tabBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.style.display = "none");
      
      // Activate clicked
      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      document.getElementById(targetId).style.display = "flex";
      
      // Hide results block on tab switch to keep UI clean
      resultsBlock.classList.add("hidden");
    });
  });

  // 7. Manual URL check
  btnScanUrl.addEventListener("click", async () => {
    const url = manualUrlInput.value.trim();
    if (!url) {
      alert("Please enter a URL first.");
      return;
    }

    btnScanUrl.disabled = true;
    btnScanUrl.textContent = "Scanning URL...";
    resultsBlock.classList.add("hidden");

    try {
      const response = await fetch(`${FLASK_SERVER}/scan/link`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
      });
      const data = await response.json();
      btnScanUrl.disabled = false;
      btnScanUrl.textContent = "Scan URL";

      if (response.ok) {
        displayScanResult(data);
      } else {
        alert("Scan Error: " + (data.error || "Unknown server error"));
      }
    } catch (err) {
      btnScanUrl.disabled = false;
      btnScanUrl.textContent = "Scan URL";
      alert("Failed to connect to backend server: " + err.message);
    }
  });

  // 8. File Picker and Dropzone events
  fileDropzone.addEventListener("click", () => {
    fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });

  // Drag over effects
  fileDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    fileDropzone.classList.add("dragover");
  });

  fileDropzone.addEventListener("dragleave", () => {
    fileDropzone.classList.remove("dragover");
  });

  fileDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    fileDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  function handleFileSelected(file) {
    selectedFileObj = file;
    dropzoneText.textContent = "File Selected";
    selectedFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    selectedFileName.style.color = "var(--color-primary-light)";
  }

  // 9. Manual File Check
  btnScanFile.addEventListener("click", async () => {
    if (!selectedFileObj) {
      alert("Please select or drop a file first.");
      return;
    }

    btnScanFile.disabled = true;
    btnScanFile.textContent = "Uploading & Scanning...";
    resultsBlock.classList.add("hidden");

    const formData = new FormData();
    formData.append("file", selectedFileObj);

    try {
      const response = await fetch(`${FLASK_SERVER}/scan/file`, {
        method: "POST",
        body: formData
      });
      const data = await response.json();
      btnScanFile.disabled = false;
      btnScanFile.textContent = "Scan File";

      if (response.ok) {
        displayScanResult(data);
      } else {
        alert("Scan Error: " + (data.error || "Unknown server error"));
      }
    } catch (err) {
      btnScanFile.disabled = false;
      btnScanFile.textContent = "Scan File";
      alert("Failed to connect to backend server: " + err.message);
    }
  });

  // 10. Handle manual text check (Emails tab)
  btnAnalyze.addEventListener("click", async () => {
    const text = manualText.value.trim();
    if (!text) {
      alert("Please paste some text first.");
      return;
    }

    btnAnalyze.disabled = true;
    btnAnalyze.textContent = "Analyzing...";
    resultsBlock.classList.add("hidden");

    const selectedModel = modelSelect.value;

    chrome.runtime.sendMessage(
      {
        action: "predict",
        email_text: text,
        model: selectedModel
      },
      (response) => {
        btnAnalyze.disabled = false;
        btnAnalyze.textContent = "Analyze Text";

        if (!response) {
          alert("Could not reach backend service worker. Is app.py running?");
          return;
        }

        if (response.success) {
          displayEmailResult(response.data);
        } else {
          alert("Scan Error: " + response.error);
        }
      }
    );
  });

  // Check backend server availability
  async function pingBackend() {
    const dot = connectionStatus.querySelector(".status-dot");
    const label = connectionStatus.querySelector(".status-text");

    try {
      const response = await fetch(`${FLASK_SERVER}/metrics`);
      if (response.ok) {
        dot.className = "status-dot connected";
        label.textContent = "Connected to Render server";
      } else {
        throw new Error("HTTP connection check failed.");
      }
    } catch (err) {
      dot.className = "status-dot disconnected";
      label.textContent = "Disconnected (Backend server offline)";
    }
  }

  // Loads storage domains and updates the popup whitelist container
  function loadAndRenderWhitelist() {
    chrome.storage.local.get({ whitelistedDomains: [] }, (settings) => {
      whitelistList.innerHTML = "";
      if (settings.whitelistedDomains.length === 0) {
        whitelistList.innerHTML = `<li style="color:#64748b; font-size:10px; text-align:center; padding: 4px 0;">No whitelisted domains.</li>`;
        return;
      }
      settings.whitelistedDomains.forEach(domain => {
        const li = document.createElement("li");
        li.className = "whitelist-item";
        li.innerHTML = `
          <span>${domain}</span>
          <button class="whitelist-del-btn" data-domain="${domain}">&times;</button>
        `;
        whitelistList.appendChild(li);
      });

      // Bind delete button events
      whitelistList.querySelectorAll(".whitelist-del-btn").forEach(btn => {
        btn.addEventListener("click", () => {
          const domToRemove = btn.getAttribute("data-domain");
          chrome.storage.local.get({ whitelistedDomains: [] }, (s) => {
            const updated = s.whitelistedDomains.filter(d => d !== domToRemove);
            chrome.storage.local.set({ whitelistedDomains: updated }, () => {
              loadAndRenderWhitelist();
            });
          });
        });
      });
    });
  }

  // Renders manual Email prediction payloads onto results card
  function displayEmailResult(data) {
    resFileDetails.classList.add("hidden");
    resReasonsBlock.classList.add("hidden");
    
    resultsBlock.classList.remove("hidden");
    resultsBlock.className = "card result-card"; // Reset styling

    const isDangerous = data.risk_level === "High Risk";
    const isSuspicious = data.risk_level === "Medium Risk";

    if (isDangerous) {
      resultsBlock.classList.add("phish");
      resIcon.textContent = "🚨";
      resTitle.textContent = "Threat Alert: Phishing";
      resTitle.style.color = "#ef4444";
    } else if (isSuspicious) {
      resultsBlock.classList.add("suspicious");
      resIcon.textContent = "⚠️";
      resTitle.textContent = "Security Warning: Suspicious";
      resTitle.style.color = "#f59e0b";
    } else {
      resultsBlock.classList.add("safe");
      resIcon.textContent = "🛡️";
      resTitle.textContent = "Security Log: Safe";
      resTitle.style.color = "#10b981";
    }

    const confidenceVal = data.confidence ? `${(data.confidence * 100).toFixed(1)}%` : "N/A";
    resSub.textContent = `Model: ${data.model_used.toUpperCase()} | Confidence: ${confidenceVal}`;
    resScore.textContent = `${data.risk_score}%`;
    resAction.textContent = data.recommended_action;
  }

  // Renders URL and File Scan payloads onto results card
  function displayScanResult(data) {
    resultsBlock.classList.remove("hidden");
    resultsBlock.className = "card result-card"; // Reset styling

    const isDangerous = data.risk_level === "High Risk";
    const isSuspicious = data.risk_level === "Medium Risk";

    if (isDangerous) {
      resultsBlock.classList.add("phish");
      resIcon.textContent = "🚨";
      resTitle.textContent = data.is_zip ? "Threat Alert: Zipped Malware" : `Threat Alert: Dangerous`;
      resTitle.style.color = "#ef4444";
    } else if (isSuspicious) {
      resultsBlock.classList.add("suspicious");
      resIcon.textContent = "⚠️";
      resTitle.textContent = `Security Warning: Suspicious`;
      resTitle.style.color = "#f59e0b";
    } else {
      resultsBlock.classList.add("safe");
      resIcon.textContent = "🛡️";
      resTitle.textContent = "Audit Clear: Safe";
      resTitle.style.color = "#10b981";
    }

    resSub.textContent = data.filename ? `File: ${data.filename}` : `Link Reputation Checked`;
    resScore.textContent = `${data.risk_score}%`;
    resAction.textContent = data.risk_level || "Low Risk";

    // Show reasons/heuristics
    resReasonsBlock.classList.remove("hidden");
    resReasonsList.innerHTML = "";
    if (data.reasons && data.reasons.length > 0) {
      data.reasons.forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        resReasonsList.appendChild(li);
      });
    }

    // ZIP Inner Files details logic
    if (data.is_zip && data.inner_files && data.inner_files.length > 0) {
      resFileDetails.classList.remove("hidden");
      innerFilesList.innerHTML = "";
      data.inner_files.forEach(f => {
        const li = document.createElement("li");
        const color = f.risk_level === "High Risk" ? "#fca5a5" : "#a7f3d0";
        li.innerHTML = `<span style="color:#cbd5e1;">${f.filename}</span> &mdash; <strong style="color:${color};">${f.risk_level}</strong>`;
        innerFilesList.appendChild(li);
      });
    } else {
      resFileDetails.classList.add("hidden");
    }
  }
});
