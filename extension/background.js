// PhishGuard Browser Extension Service Worker
// Handles network requests to the local Flask backend to avoid CORS limitations.

const FLASK_SERVER = "https://phishguard-api-fzds.onrender.com";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "predict") {
    fetch(`${FLASK_SERVER}/predict`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email_text: message.email_text,
        model: message.model || "nb"
      })
    })
      .then(response => {
        if (!response.ok) {
          throw new Error(`Server returned status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        sendResponse({ success: true, data: data });
      })
      .catch(error => {
        console.error("PhishGuard background service worker error:", error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep message port open for async sendResponse
  }
});
