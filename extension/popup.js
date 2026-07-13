// PhishGuard Extension Popup Controller
// Binds UI controls, pings the backend, and handles manual text checks.

const FLASK_SERVER = "https://phishguard-api-fzds.onrender.com";

document.addEventListener("DOMContentLoaded", () => {
  const modelSelect = document.getElementById("extModelSelect");
  const manualText = document.getElementById("manualText");
  const btnAnalyze = document.getElementById("btnAnalyze");
  const connectionStatus = document.getElementById("connectionStatus");
  const resultsBlock = document.getElementById("resultsBlock");

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

  // 4. Handle manual text check
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
