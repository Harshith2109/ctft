// PhishGuard Extension Popup Controller
// Binds UI controls, pings the backend, handles manual text checks, and manages whitelisted domains.

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

  const resIcon = document.getElementById("resIcon");
  const resTitle = document.getElementById("resTitle");
  const resSub = document.getElementById("resSub");
  const resScore = document.getElementById("resScore");
  const resAction = document.getElementById("resAction");

  // 1. Check local server connection status
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

  // 6. Handle manual text check
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
          displayResult(response.data);
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
        label.textContent = "Connected to local server";
      } else {
        throw new Error("HTTP connection check failed.");
      }
    } catch (err) {
      dot.className = "status-dot disconnected";
      label.textContent = "Disconnected (Start app.py)";
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

  // Renders the prediction payload onto the results UI card
  function displayResult(data) {
    resultsBlock.classList.remove("hidden");
    resultsBlock.className = "card result-card"; // Reset styling

    const isPhish = data.prediction === "Phishing";

    if (isPhish) {
      resultsBlock.classList.add("phish");
      resIcon.textContent = "🚨";
      resTitle.textContent = "Threat Alert: Phishing";
      resTitle.style.color = "#ef4444";
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
});
