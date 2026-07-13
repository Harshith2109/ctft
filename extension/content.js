// PhishGuard content script - Gmail & Outlook DOM Integration
// Intercepts open emails, injects audit buttons, and highlights threat indicators.

let observer = null;

// Injection helper styles
const STYLES = `
  .phishguard-btn {
    background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%) !important;
    border: none !important;
    color: white !important;
    font-family: 'Poppins', sans-serif !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    padding: 6px 14px !important;
    border-radius: 20px !important;
    cursor: pointer !important;
    display: inline-flex !important;
    align-items: center !important;
    gap: 6px !important;
    box-shadow: 0 4px 6px rgba(0,0,0,0.15) !important;
    transition: all 0.2s ease-in-out !important;
    margin: 8px 12px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
  }
  .phishguard-btn:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 10px rgba(59, 130, 246, 0.3) !important;
  }
  .phishguard-alert-banner {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
    background: rgba(30, 41, 59, 0.95) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 12px !important;
    padding: 18px !important;
    margin: 12px !important;
    color: #f1f5f9 !important;
    box-shadow: 0 8px 24px rgba(0,0,0,0.3) !important;
    backdrop-filter: blur(8px) !important;
  }
  .phishguard-alert-banner.phish {
    border-left: 6px solid #ef4444 !important;
  }
  .phishguard-alert-banner.safe {
    border-left: 6px solid #10b981 !important;
  }
  .pg-badge-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 10px;
  }
  .pg-badge {
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
  }
  .pg-badge.danger { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
  .pg-badge.success { background: rgba(16, 185, 129, 0.2); color: #a7f3d0; border: 1px solid rgba(16, 185, 129, 0.3); }
  .pg-badge.warning { background: rgba(245, 158, 11, 0.2); color: #fde047; border: 1px solid rgba(245, 158, 11, 0.3); }
  .pg-badge.secondary { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.3); }
  
  .xai-ext-phish {
    border-bottom: 2px solid #ef4444 !important;
    font-weight: bold !important;
    border-radius: 2px !important;
  }
  .xai-ext-safe {
    border-bottom: 2px solid #10b981 !important;
    font-weight: bold !important;
    border-radius: 2px !important;
  }
`;

// Inject CSS styles into client context
const styleEl = document.createElement("style");
styleEl.textContent = STYLES;
document.head.appendChild(styleEl);

// Initialize scanner
function init() {
  if (observer) observer.disconnect();
  
  // Scans DOM alterations to catch loaded emails
  observer = new MutationObserver(debounce(checkForEmails, 150));
  observer.observe(document.body, { childList: true, subtree: true });
  
  // Fallback periodic poll to prevent starvation by active background mutations
  setInterval(checkForEmails, 1500);
  
  checkForEmails();
}

// Debounce helper to throttle Mutation events
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Checks for open emails in Gmail and Outlook
function checkForEmails() {
  const hostname = window.location.hostname;
  
  if (hostname.includes("mail.google.com")) {
    handleGmail();
  } else if (hostname.includes("outlook") || hostname.includes("office")) {
    handleOutlook();
  }
}

// Gmail DOM Scraper & Button Injector
function handleGmail() {
  // Gmail selectors for thread/message containers
  const messages = document.querySelectorAll(".adn.ads");
  messages.forEach(msg => {
    if (msg.querySelector(".phishguard-container")) return; // Already scanned/injected
    
    // Locates message header container (checks primary buttons first, then fallback to sender area)
    const headerContainer = msg.querySelector(".gE.iv") || 
                            msg.querySelector(".gH") || 
                            msg.querySelector("span.gD")?.parentNode;
    if (!headerContainer) return;
    
    // Inject scan action button
    const container = document.createElement("div");
    container.className = "phishguard-container";
    container.style.display = "inline-block";
    
    const button = document.createElement("button");
    button.className = "phishguard-btn";
    button.innerHTML = "🛡️ Scan Email";
    button.addEventListener("click", () => runGmailAudit(msg, button));
    
    container.appendChild(button);
    headerContainer.appendChild(container);
  });
}

// Outlook DOM Scraper & Button Injector
function handleOutlook() {
  // Outlook selectors for reading messages container
  const readingPanes = document.querySelectorAll("div[role='document']");
  readingPanes.forEach(pane => {
    if (pane.querySelector(".phishguard-container")) return; // Already scanned/injected
    
    // Find subject/header details area (checks conversation header, persona header, or sender title parent)
    const headerContainer = pane.querySelector("div[data-app-section='ConversationReadingPaneHeader']") || 
                            pane.querySelector(".PersonaHeader") ||
                            pane.querySelector("span[title*='@']")?.parentNode ||
                            pane.querySelector("div[role='heading']")?.parentNode;
    if (!headerContainer) return;
    
    const container = document.createElement("div");
    container.className = "phishguard-container";
    container.style.display = "inline-block";
    
    const button = document.createElement("button");
    button.className = "phishguard-btn";
    button.innerHTML = "🛡️ Scan Email";
    button.addEventListener("click", () => runOutlookAudit(pane, button));
    
    container.appendChild(button);
    headerContainer.appendChild(container);
  });
}

// Performs analysis for Gmail messages
async function runGmailAudit(msgNode, btn) {
  btn.disabled = true;
  btn.innerHTML = "⏳ Auditing...";
  
  try {
    // 1. Scrape Sender
    const senderNode = msgNode.querySelector("span.gD");
    const sender = senderNode ? senderNode.getAttribute("email") || senderNode.textContent : "Unknown Sender";
    
    // 2. Scrape Subject
    const subjectNode = document.querySelector("h2.hP");
    const subject = subjectNode ? subjectNode.textContent : "No Subject";
    
    // 3. Scrape Body Text
    const bodyNode = msgNode.querySelector(".a3s.aiL") || msgNode.querySelector(".a3s");
    const bodyText = bodyNode ? bodyNode.innerText : "";
    
    // 4. Scrape Attachments
    const attachmentNodes = msgNode.querySelectorAll(".a5a, .att");
    const attachment = attachmentNodes.length > 0 ? attachmentNodes[0].innerText : "None";
    
    // Assemble text payload
    const textToAnalyze = `From: ${sender}\nSubject: ${subject}\nAttachment: ${attachment}\n\n${bodyText}`;
    
    const result = await requestPrediction(textToAnalyze);
    renderAuditResult(bodyNode, msgNode, result);
    
  } catch (error) {
    alert("PhishGuard Analysis Failed: " + error.message);
  } finally {
    btn.innerHTML = "🛡️ Scan Email";
    btn.disabled = false;
  }
}

// Performs analysis for Outlook reading pane
async function runOutlookAudit(paneNode, btn) {
  btn.disabled = true;
  btn.innerHTML = "⏳ Auditing...";
  
  try {
    // 1. Scrape Sender
    const senderNode = paneNode.querySelector("span[title*='@']") || paneNode.querySelector(".PersonaHeader");
    const sender = senderNode ? senderNode.getAttribute("title") || senderNode.innerText : "Unknown Sender";
    
    // 2. Scrape Subject
    const subjectNode = paneNode.querySelector("div[role='heading']") || document.querySelector(".ReadingPaneContainer [role='heading']");
    const subject = subjectNode ? subjectNode.innerText : "No Subject";
    
    // 3. Scrape Body Text
    const bodyNode = paneNode.querySelector("div[role='document']") || paneNode.querySelector(".elementToProof") || paneNode;
    const bodyText = bodyNode ? bodyNode.innerText : "";
    
    // 4. Scrape Attachments
    const attachmentNodes = paneNode.querySelectorAll("[data-log-name='Attachment']");
    const attachment = attachmentNodes.length > 0 ? attachmentNodes[0].innerText : "None";
    
    // Assemble text payload
    const textToAnalyze = `From: ${sender}\nSubject: ${subject}\nAttachment: ${attachment}\n\n${bodyText}`;
    
    const result = await requestPrediction(textToAnalyze);
    renderAuditResult(bodyNode, paneNode, result);
    
  } catch (error) {
    alert("PhishGuard Analysis Failed: " + error.message);
  } finally {
    btn.innerHTML = "🛡️ Scan Email";
    btn.disabled = false;
  }
}

// Contacts background.js worker to query backend
function requestPrediction(emailText) {
  return new Promise((resolve, reject) => {
    // Get currently selected model configuration
    chrome.storage.local.get({ selectedModel: "nb" }, (settings) => {
      chrome.runtime.sendMessage(
        {
          action: "predict",
          email_text: emailText,
          model: settings.selectedModel
        },
        (response) => {
          if (!response) {
            reject(new Error("No response received from background service worker. Make sure Flask app.py is running."));
          } else if (!response.success) {
            reject(new Error(response.error));
          } else {
            resolve(response.data);
          }
        }
      );
    });
  });
}

// Renders glassmorphism status alerts at the top of the email
function renderAuditResult(bodyNode, parentNode, result) {
  // Remove existing banner if already present
  const existing = parentNode.querySelector(".phishguard-alert-banner");
  if (existing) existing.remove();
  
  const banner = document.createElement("div");
  const isPhish = result.prediction === "Phishing";
  banner.className = `phishguard-alert-banner ${isPhish ? 'phish' : 'safe'}`;
  
  // Format badges
  const spoofBadge = result.domain_spoof 
    ? '<span class="pg-badge danger">❌ Spoofed Domain</span>' 
    : (result.is_verified_brand ? '<span class="pg-badge success">✅ Verified Brand</span>' : '<span class="pg-badge success">Domain OK</span>');
  
  const dkimBadge = result.is_dkim_signed 
    ? '<span class="pg-badge success">🔑 DKIM verified</span>' 
    : (result.dkim_domain ? '<span class="pg-badge warning">🔑 DKIM Domain Unrecognized</span>' : '<span class="pg-badge secondary">No DKIM</span>');
  
  const linkBadge = result.suspicious_url 
    ? '<span class="pg-badge danger">❌ Dangerous Links</span>' 
    : (result.has_url ? '<span class="pg-badge warning">Links Present</span>' : '<span class="pg-badge success">No Links</span>');
  
  const attachmentBadge = result.attachment_risk === "High Risk" 
    ? '<span class="pg-badge danger">⚠ Dangerous Attachment</span>' 
    : (result.attachment_risk === "Low Risk" ? '<span class="pg-badge warning">Attachment Attached</span>' : '<span class="pg-badge success">No Attachments</span>');

  // Build Anomaly List
  const anomalies = [];
  if (result.domain_spoof) {
    anomalies.push(`Sender domain contains lookalikes or mimics a known brand (Detected sender: <code>${result.sender}</code>).`);
  } else if (result.is_verified_brand) {
    anomalies.push("Sender domain is verified as official brand infrastructure (SPF/DKIM aligned).");
  }
  if (result.is_dkim_signed) {
    anomalies.push(`DKIM signature cryptographically verified for domain: <code>${result.dkim_domain}</code>.`);
  } else if (result.dkim_domain) {
    anomalies.push(`DKIM signature is present but signed by an unrecognized domain: <code>${result.dkim_domain}</code>.`);
  }
  if (result.suspicious_url) {
    anomalies.push("Found suspicious URLs (either containing a raw IP address or having a length exceeding 75 characters).");
  }
  if (result.attachment_risk === "High Risk") {
    anomalies.push(`High-risk executable attachment detected: <code>${result.attachment}</code> (potentially executable).`);
  } else if (result.attachment_risk === "Low Risk") {
    anomalies.push(`Low-risk file attachment: <code>${result.attachment}</code>.`);
  }
  if (anomalies.length === 0) {
    anomalies.push("No notable email header anomalies detected.");
  }
  const anomaliesHtml = anomalies.map(a => `<li style="margin-bottom: 4px;">${a}</li>`).join("");

  // Build Top 5 XAI rows
  let xaiRowsHtml = "";
  if (result.xai_weights && result.xai_weights.length > 0) {
    result.xai_weights.slice(0, 5).forEach(w => {
      const isPhishFeature = w.weight > 0;
      const color = isPhishFeature ? "#fca5a5" : "#a7f3d0";
      const label = isPhishFeature ? "Phish Indicator" : "Safe Indicator";
      xaiRowsHtml += `
        <tr>
          <td style="padding: 4px 0; color: #94a3b8; font-family: monospace;">${w.word}</td>
          <td style="padding: 4px 0; color: ${color}; font-weight: 600;">${label}</td>
          <td style="padding: 4px 0; text-align: right; color: #f1f5f9; font-family: monospace;">${w.weight.toFixed(4)}</td>
        </tr>
      `;
    });
  } else {
    xaiRowsHtml = "<tr><td colspan='3' style='color:#94a3b8; text-align:center;'>No words contributed to classifier boundaries.</td></tr>";
  }

  const bannerHtml = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
      <h4 style="margin:0; font-size:14px; font-weight:bold; color:${isPhish ? '#ef4444' : '#10b981'}; display:flex; align-items:center; gap:6px;">
        🛡️ PhishGuard Analysis: ${result.prediction} (${(result.confidence * 100).toFixed(1)}% Confidence)
      </h4>
      <div style="display:flex; align-items:center; gap:8px;">
        <button class="pg-toggle-xai" style="background:transparent; border:1px solid rgba(255,255,255,0.2); border-radius:4px; padding:3px 8px; color:white; font-size:10px; cursor:pointer; font-weight:600;">
          Toggle Highlights
        </button>
        <button class="pg-toggle-details" style="background:transparent; border:1px solid rgba(255,255,255,0.2); border-radius:4px; padding:3px 8px; color:white; font-size:10px; cursor:pointer; font-weight:600;">
          More Details
        </button>
        <button class="pg-close-banner" style="background:transparent; border:none; color:#cbd5e1; font-size:18px; line-height:1; cursor:pointer; font-weight:bold; padding:0 4px;" title="Dismiss Audit Alert">&times;</button>
      </div>
    </div>
    <div style="font-size:12px; margin-bottom:10px; color:#94a3b8;">
      Risk Score: <strong>${result.risk_score}%</strong> | Recommendation: <strong>${result.recommended_action}</strong>
    </div>
    <div class="pg-badge-grid">
      ${spoofBadge}
      ${dkimBadge}
      ${linkBadge}
      ${attachmentBadge}
    </div>
    
    <!-- Collapsible drawer for advanced details -->
    <div class="pg-details-drawer" style="display:none; margin-top:14px; padding-top:12px; border-top:1px solid rgba(255,255,255,0.1); font-size:12px; color:#cbd5e1; animation: fadeIn 0.2s ease-out;">
      <div style="margin-bottom:12px;">
        <strong style="color:#60a5fa; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Anomaly Audit Log:</strong>
        <ul style="margin:6px 0 0 16px; padding:0; list-style-type:disc; color:#94a3b8;">
          ${anomaliesHtml}
        </ul>
      </div>
      <div>
        <strong style="color:#60a5fa; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Top Classifier Features (XAI):</strong>
        <table style="width:100%; border-collapse:collapse; margin-top:6px;">
          <thead>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); text-align:left; font-size:10px; color:#64748b; text-transform:uppercase;">
              <th style="padding-bottom:4px; font-weight:600;">Word</th>
              <th style="padding-bottom:4px; font-weight:600;">Influence</th>
              <th style="padding-bottom:4px; font-weight:600; text-align:right;">Weight</th>
            </tr>
          </thead>
          <tbody>
            ${xaiRowsHtml}
          </tbody>
        </table>
      </div>
    </div>
  `;
  
  banner.innerHTML = bannerHtml;
  
  // Prepend banner to parent container (or at the top of message body)
  parentNode.insertBefore(banner, parentNode.firstChild);
  
  // Wire up close button
  const closeBtn = banner.querySelector(".pg-close-banner");
  closeBtn.addEventListener("click", () => {
    banner.remove();
  });
  
  // Wire up details drawer toggling
  const toggleDetailsBtn = banner.querySelector(".pg-toggle-details");
  const detailsDrawer = banner.querySelector(".pg-details-drawer");
  toggleDetailsBtn.addEventListener("click", () => {
    const isHidden = detailsDrawer.style.display === "none";
    detailsDrawer.style.display = isHidden ? "block" : "none";
    toggleDetailsBtn.textContent = isHidden ? "Hide Details" : "More Details";
  });
  
  // Wire up XAI toggling
  const toggleBtn = banner.querySelector(".pg-toggle-xai");
  toggleBtn.addEventListener("click", () => {
    toggleXaiHighlighting(bodyNode, result.xai_weights);
  });
}

// In-context XAI Highlight Heatmap Engine
function toggleXaiHighlighting(bodyNode, weights) {
  if (!bodyNode || !weights) return;
  
  // Check if highlighted already
  const highlightedSpans = bodyNode.querySelectorAll(".xai-ext-phish, .xai-ext-safe");
  if (highlightedSpans.length > 0) {
    // Revert to plain text
    highlightedSpans.forEach(span => {
      const textNode = document.createTextNode(span.textContent);
      span.parentNode.replaceChild(textNode, span);
    });
    return;
  }
  
  // Walk text nodes and substitute matches
  const walk = document.createTreeWalker(bodyNode, NodeFilter.SHOW_TEXT, null, false);
  let node;
  const nodesToReplace = [];
  
  while (node = walk.nextNode()) {
    // Avoid replacing inside attributes, scripts or pre-existing highlight scripts
    const parent = node.parentNode;
    if (parent.tagName === "SCRIPT" || parent.tagName === "STYLE" || parent.className.includes("xai-ext")) continue;
    
    let text = node.nodeValue;
    let matchesFound = false;
    
    // Sort words by length descending to replace larger phrases first
    const sortedWeights = [...weights].sort((a,b) => b.word.length - a.word.length);
    
    let tempHtml = escapeHtml(text);
    
    sortedWeights.forEach(w => {
      const word = w.word;
      const weight = w.weight;
      if (word.length < 2) return;
      
      const regex = new RegExp(`\\b(${escapeRegExp(word)})\\b`, 'gi');
      
      const opacity = Math.min(Math.abs(weight) * 2.0 + 0.1, 0.6);
      const isPhish = weight > 0;
      const highlightClass = isPhish ? 'xai-ext-phish' : 'xai-ext-safe';
      const bgColor = isPhish ? `rgba(239, 68, 68, ${opacity})` : `rgba(16, 185, 129, ${opacity})`;
      
      if (regex.test(tempHtml)) {
        matchesFound = true;
        tempHtml = tempHtml.replace(regex, `<span class="${highlightClass}" style="background: ${bgColor};" title="Weight: ${weight.toFixed(4)}">$1</span>`);
      }
    });
    
    if (matchesFound) {
      nodesToReplace.push({ textNode: node, html: tempHtml });
    }
  }
  
  // Swap nodes
  nodesToReplace.forEach(item => {
    const tempDiv = document.createElement("div");
    tempDiv.innerHTML = item.html;
    
    const fragment = document.createDocumentFragment();
    while (tempDiv.firstChild) {
      fragment.appendChild(tempDiv.firstChild);
    }
    item.textNode.parentNode.replaceChild(fragment, item.textNode);
  });
}

function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Start content observer
init();
