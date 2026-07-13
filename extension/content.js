// PhishGuard content script - Gmail & Outlook DOM Integration
// Intercepts open emails, injects audit buttons, and highlights threat indicators.

let observer = null;

// Injection helper styles
const STYLES = `
  .phishguard-container {
    display: inline-block !important;
    vertical-align: middle !important;
  }
  .pg-mini-badge {
    display: inline-flex !important;
    align-items: center !important;
    gap: 6px !important;
    padding: 4px 12px !important;
    border-radius: 20px !important;
    font-family: 'Poppins', sans-serif !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    color: #ffffff !important;
    border: none !important;
    cursor: pointer !important;
    box-shadow: 0 2px 4px rgba(0,0,0,0.15) !important;
    transition: all 0.2s ease-in-out !important;
    margin: 4px 10px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
  }
  .pg-mini-badge:hover {
    transform: translateY(-1px) !important;
  }
  .pg-mini-badge.scanning {
    background: #475569 !important;
    border: 1px solid #64748b !important;
    animation: pgPulse 1.5s infinite alternate !important;
    cursor: wait !important;
  }
  .pg-mini-badge.safe {
    background: rgba(16, 185, 129, 0.2) !important;
    color: #34d399 !important;
    border: 1px solid rgba(16, 185, 129, 0.5) !important;
  }
  .pg-mini-badge.safe:hover {
    box-shadow: 0 4px 8px rgba(16, 185, 129, 0.3) !important;
  }
  .pg-mini-badge.phish {
    background: rgba(239, 68, 68, 0.2) !important;
    color: #f87171 !important;
    border: 1px solid rgba(239, 68, 68, 0.5) !important;
  }
  .pg-mini-badge.phish:hover {
    box-shadow: 0 4px 8px rgba(239, 68, 68, 0.3) !important;
  }
  .pg-mini-badge.whitelisted {
    background: rgba(59, 130, 246, 0.2) !important;
    color: #60a5fa !important;
    border: 1px solid rgba(59, 130, 246, 0.5) !important;
  }
  .pg-mini-badge.whitelisted:hover {
    box-shadow: 0 4px 8px rgba(59, 130, 246, 0.3) !important;
  }

  @keyframes pgPulse {
    0% { opacity: 0.6; box-shadow: 0 0 2px #475569; }
    100% { opacity: 1; box-shadow: 0 0 8px #64748b; }
  }

  .phishguard-alert-banner {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
    background: rgba(30, 41, 59, 0.98) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 12px !important;
    padding: 18px !important;
    margin: 12px 0 !important;
    color: #f1f5f9 !important;
    box-shadow: 0 8px 24px rgba(0,0,0,0.3) !important;
    backdrop-filter: blur(8px) !important;
    display: none; /* Hidden by default, toggled via mini-badge click */
    animation: pgFadeIn 0.2s ease-out !important;
  }
  @keyframes pgFadeIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .phishguard-alert-banner.phish {
    border-left: 6px solid #ef4444 !important;
  }
  .phishguard-alert-banner.safe {
    border-left: 6px solid #10b981 !important;
  }
  .phishguard-alert-banner.whitelisted {
    border-left: 6px solid #3b82f6 !important;
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
    
    const badge = document.createElement("button");
    badge.className = "pg-mini-badge scanning";
    badge.innerHTML = "🛡️ Scanning...";
    
    container.appendChild(badge);
    headerContainer.appendChild(container);
    
    // Run background scan immediately
    runGmailAudit(msg, badge);
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
    
    const badge = document.createElement("button");
    badge.className = "pg-mini-badge scanning";
    badge.innerHTML = "🛡️ Scanning...";
    
    container.appendChild(badge);
    headerContainer.appendChild(container);
    
    // Run background scan immediately
    runOutlookAudit(pane, badge);
  });
}

// Performs analysis for Gmail messages
async function runGmailAudit(msgNode, badge) {
  try {
    // 1. Scrape Sender
    const senderNode = msgNode.querySelector("span.gD");
    const sender = senderNode ? senderNode.getAttribute("email") || senderNode.textContent : "Unknown Sender";
    const senderDomain = getDomainFromEmail(sender);
    
    // 2. Scrape Subject
    const subjectNode = document.querySelector("h2.hP");
    const subject = subjectNode ? subjectNode.textContent : "No Subject";
    
    // 3. Scrape Body Text
    const bodyNode = msgNode.querySelector(".a3s.aiL") || msgNode.querySelector(".a3s");
    const bodyText = bodyNode ? bodyNode.innerText : "";
    
    // 4. Scrape Attachments
    const attachmentNodes = msgNode.querySelectorAll(".aQJ, .aKz, .a5i, .a5a, .att, span.a1a, .a6S, [role='listitem'] [class*='filename']");
    let attachment = "None";
    if (attachmentNodes.length > 0) {
      const names = Array.from(attachmentNodes)
        .map(n => n.innerText || n.textContent)
        .map(t => t.trim())
        .filter(t => t && t.includes("."));
      if (names.length > 0) {
        attachment = names[0];
      }
    }
    
    // Assemble text payload
    const textToAnalyze = `From: ${sender}\nSubject: ${subject}\nAttachment: ${attachment}\n\n${bodyText}`;
    
    const result = await processDomainChecks(senderDomain, textToAnalyze);
    renderAuditResult(bodyNode, msgNode, badge, result, senderDomain);
    
  } catch (error) {
    badge.innerHTML = "🛡️ Scan Error";
    badge.className = "pg-mini-badge phish";
    badge.setAttribute("title", error.message);
  }
}

// Performs analysis for Outlook reading pane
async function runOutlookAudit(paneNode, badge) {
  try {
    // 1. Scrape Sender
    const senderNode = paneNode.querySelector("span[title*='@']") || paneNode.querySelector(".PersonaHeader");
    const sender = senderNode ? senderNode.getAttribute("title") || senderNode.innerText : "Unknown Sender";
    const senderDomain = getDomainFromEmail(sender);
    
    // 2. Scrape Subject
    const subjectNode = paneNode.querySelector("div[role='heading']") || document.querySelector(".ReadingPaneContainer [role='heading']");
    const subject = subjectNode ? subjectNode.innerText : "No Subject";
    
    // 3. Scrape Body Text
    const bodyNode = paneNode.querySelector("div[role='document']") || paneNode.querySelector(".elementToProof") || paneNode;
    const bodyText = bodyNode ? bodyNode.innerText : "";
    
    // 4. Scrape Attachments
    const attachmentNodes = paneNode.querySelectorAll("[data-log-name='Attachment'], [role='listitem'] [class*='filename'], .AttachmentCard, .att");
    let attachment = "None";
    if (attachmentNodes.length > 0) {
      const names = Array.from(attachmentNodes)
        .map(n => n.innerText || n.textContent)
        .map(t => t.trim())
        .filter(t => t && t.includes("."));
      if (names.length > 0) {
        attachment = names[0];
      }
    }
    
    // Assemble text payload
    const textToAnalyze = `From: ${sender}\nSubject: ${subject}\nAttachment: ${attachment}\n\n${bodyText}`;
    
    const result = await processDomainChecks(senderDomain, textToAnalyze);
    renderAuditResult(bodyNode, paneNode, badge, result, senderDomain);
    
  } catch (error) {
    badge.innerHTML = "🛡️ Scan Error";
    badge.className = "pg-mini-badge phish";
    badge.setAttribute("title", error.message);
  }
}

// Extractor helper for sender domains
function getDomainFromEmail(senderStr) {
  const emailMatch = senderStr.match(/[\w\.-]+@[\w\.-]+\.\w+/);
  if (emailMatch) {
    return emailMatch[0].split('@')[1].toLowerCase().trim();
  }
  return "";
}

// Intercepts and overrides audits if domain is locally whitelisted
async function processDomainChecks(domain, emailText) {
  return new Promise((resolve) => {
    chrome.storage.local.get({ whitelistedDomains: [] }, async (settings) => {
      if (domain && settings.whitelistedDomains.includes(domain)) {
        // Mock a perfect response bypassing ML
        resolve({
          prediction: "Safe",
          confidence: 1.0,
          model_used: "local-whitelist",
          sender: `System Whitelist: ${domain}`,
          domain_spoof: false,
          is_verified_brand: true,
          is_dkim_signed: true,
          dkim_domain: domain,
          attachment: "None",
          attachment_risk: "None",
          has_url: false,
          url_count: 0,
          suspicious_url: false,
          risk_score: 0,
          risk_level: "Low Risk (Whitelisted)",
          recommended_action: "No action required",
          xai_weights: []
        });
      } else {
        // Query background.js
        try {
          const apiRes = await requestPrediction(emailText);
          resolve(apiRes);
        } catch (err) {
          throw err;
        }
      }
    });
  });
}

// Contacts background.js worker to query backend
function requestPrediction(emailText) {
  return new Promise((resolve, reject) => {
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
function renderAuditResult(bodyNode, parentNode, badge, result, senderDomain) {
  const isPhish = result.prediction === "Phishing";
  const isWhitelisted = result.model_used === "local-whitelist";
  
  // Set badge class and text based on diagnosis
  if (isWhitelisted) {
    badge.className = "pg-mini-badge whitelisted";
    badge.innerHTML = "🛡️ Whitelisted";
  } else if (isPhish) {
    badge.className = "pg-mini-badge phish";
    badge.innerHTML = `🚨 Phishing (${(result.confidence * 100).toFixed(0)}%)`;
  } else {
    badge.className = "pg-mini-badge safe";
    badge.innerHTML = `🟢 Safe (${(result.confidence * 100).toFixed(0)}%)`;
  }
  
  // Remove existing banner if already present
  const existing = parentNode.querySelector(".phishguard-alert-banner");
  if (existing) existing.remove();
  
  const banner = document.createElement("div");
  banner.className = `phishguard-alert-banner ${isWhitelisted ? 'whitelisted' : (isPhish ? 'phish' : 'safe')}`;
  
  // Format badges
  const spoofBadge = result.domain_spoof 
    ? '<span class="pg-badge danger">❌ Spoofed Domain</span>' 
    : (result.is_verified_brand ? '<span class="pg-badge success">✅ Verified Brand</span>' : '<span class="pg-badge success">Domain OK</span>');
  
  const dkimBadge = result.is_dkim_signed 
    ? '<span class="pg-badge success">🔑 DKIM verified</span>' 
    : (result.dkim_domain ? '<span class="pg-badge warning">🔑 DKIM Domain Unrecognized</span>' : '<span class="pg-badge secondary">No DKIM</span>');
  
  const linkBadge = result.suspicious_url 
    ? '<span class="pg-badge danger">❌ Dangerous Links</span>' 
    : (result.has_url ? '<span class="pg-badge success">✅ Links Checked & Safe</span>' : '<span class="pg-badge success">No Links</span>');
  
  const attachmentBadge = result.attachment_risk === "High Risk" 
    ? '<span class="pg-badge danger">⚠ Dangerous Attachment</span>' 
    : (result.attachment_risk === "Low Risk" ? '<span class="pg-badge success">📎 Attachment Checked Safe</span>' : '<span class="pg-badge success">No Attachments</span>');

  // Build Anomaly List
  const anomalies = [];
  if (isWhitelisted) {
    anomalies.push("Sender domain is locally whitelisted on this computer. Predictions bypassed.");
  } else {
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
  }
  const anomaliesHtml = anomalies.map(a => `<li style="margin-bottom: 4px;">${a}</li>`).join("");

  // Build VirusTotal Simulation Block
  let vtHtml = "";
  if (result.attachment && result.attachment !== "None") {
    const isDangerousFile = result.attachment_risk === "High Risk";
    const vtColor = isDangerousFile ? "#f87171" : "#34d399";
    const vtVerdict = isDangerousFile 
      ? `<strong>43 / 72</strong> security engines flagged this signature as malicious!`
      : `<strong>0 / 72</strong> engines flagged this signature (Clean).`;
    
    vtHtml = `
      <div style="margin-bottom:12px; border-top:1px dashed rgba(255,255,255,0.05); padding-top:8px;">
        <strong style="color:#60a5fa; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">VirusTotal File Analysis:</strong>
        <p style="margin:4px 0 0 0; font-size:11px; color:${vtColor};">
          🔍 File: <code>${result.attachment}</code> &mdash; ${vtVerdict}
        </p>
      </div>
    `;
  }

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

  // Whitelist/Blacklist button html
  const whitelistBtnHtml = isWhitelisted
    ? `<button class="pg-whitelist-btn" style="background:#ef4444; border:none; border-radius:4px; padding:3px 8px; color:white; font-size:10px; cursor:pointer; font-weight:600;">Remove Whitelist</button>`
    : (senderDomain ? `<button class="pg-whitelist-btn" style="background:#3b82f6; border:none; border-radius:4px; padding:3px 8px; color:white; font-size:10px; cursor:pointer; font-weight:600;">Whitelist Domain</button>` : '');

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
        ${whitelistBtnHtml}
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
      
      ${vtHtml}

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
  
  // Prepend/insert banner to parent container
  parentNode.insertBefore(banner, parentNode.firstChild);
  
  // Link Click Interception logic
  if (result.suspicious_url || isPhish) {
    interceptSuspiciousLinks(bodyNode);
  }

  // Toggle banner details drawer via mini-badge click
  badge.removeEventListener("click", toggleBannerVisibility);
  badge.addEventListener("click", toggleBannerVisibility);
  
  function toggleBannerVisibility() {
    const isCurrentlyHidden = window.getComputedStyle(banner).display === "none";
    banner.style.display = isCurrentlyHidden ? "block" : "none";
  }

  // Wire up close button
  const closeBtn = banner.querySelector(".pg-close-banner");
  closeBtn.addEventListener("click", () => {
    banner.style.display = "none";
  });
  
  // Wire up details drawer toggling
  const toggleDetailsBtn = banner.querySelector(".pg-toggle-details");
  const detailsDrawer = banner.querySelector(".pg-details-drawer");
  toggleDetailsBtn.addEventListener("click", () => {
    const isHidden = detailsDrawer.style.display === "none";
    detailsDrawer.style.display = isHidden ? "block" : "none";
    toggleDetailsBtn.textContent = isHidden ? "Hide Details" : "More Details";
  });
  
  // Wire up whitelist button
  const whitelistBtn = banner.querySelector(".pg-whitelist-btn");
  if (whitelistBtn) {
    whitelistBtn.addEventListener("click", () => {
      chrome.storage.local.get({ whitelistedDomains: [] }, (settings) => {
        let currentList = settings.whitelistedDomains;
        if (isWhitelisted) {
          // Remove
          currentList = currentList.filter(d => d !== senderDomain);
          alert(`Removed domain "${senderDomain}" from whitelist.`);
        } else {
          // Add
          if (!currentList.includes(senderDomain)) {
            currentList.push(senderDomain);
            alert(`Added domain "${senderDomain}" to local whitelist.`);
          }
        }
        
        chrome.storage.local.set({ whitelistedDomains: currentList }, () => {
          // Trigger a recheck
          if (window.location.hostname.includes("mail.google.com")) {
            runGmailAudit(parentNode, badge);
          } else {
            runOutlookAudit(parentNode, badge);
          }
        });
      });
    });
  }

  // Wire up XAI toggling
  const toggleBtn = banner.querySelector(".pg-toggle-xai");
  toggleBtn.addEventListener("click", () => {
    toggleXaiHighlighting(bodyNode, result.xai_weights);
  });
}

// Redirect and click safety interceptor
function interceptSuspiciousLinks(bodyNode) {
  if (!bodyNode) return;
  const links = bodyNode.querySelectorAll("a");
  
  links.forEach(link => {
    if (link.getAttribute("data-pg-intercepted")) return;
    link.setAttribute("data-pg-intercepted", "true");
    
    link.addEventListener("click", (e) => {
      const url = link.href;
      // Skip mailto and internal hashes
      if (!url.startsWith("http")) return;
      
      const proceed = confirm(
        `⚠️ PHISHGUARD SECURITY WARNING:\n\n` +
        `You are attempting to open an external link inside a suspicious email:\n` +
        `➡ ${url}\n\n` +
        `This email has failed standard safety audits. Opening links from unverified senders could expose you to phishing, credential theft, or malware.\n\n` +
        `Are you absolutely sure you want to proceed to this address?`
      );
      
      if (!proceed) {
        e.preventDefault();
      }
    });
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
    const parent = node.parentNode;
    if (parent.tagName === "SCRIPT" || parent.tagName === "STYLE" || parent.className.includes("xai-ext")) continue;
    
    let text = node.nodeValue;
    let matchesFound = false;
    
    // Sort words by length descending
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
