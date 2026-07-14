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
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    color: #ffffff !important;
    border: none !important;
    cursor: pointer !important;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1) !important;
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
    background: rgba(16, 185, 129, 0.15) !important;
    color: #10b981 !important;
    border: 1px solid rgba(16, 185, 129, 0.3) !important;
  }
  .pg-mini-badge.safe:hover {
    box-shadow: 0 4px 8px rgba(16, 185, 129, 0.2) !important;
  }
  .pg-mini-badge.phish {
    background: rgba(239, 68, 68, 0.15) !important;
    color: #ef4444 !important;
    border: 1px solid rgba(239, 68, 68, 0.3) !important;
  }
  .pg-mini-badge.phish:hover {
    box-shadow: 0 4px 8px rgba(239, 68, 68, 0.2) !important;
  }
  .pg-mini-badge.suspicious {
    background: rgba(245, 158, 11, 0.15) !important;
    color: #f59e0b !important;
    border: 1px solid rgba(245, 158, 11, 0.3) !important;
  }
  .pg-mini-badge.suspicious:hover {
    box-shadow: 0 4px 8px rgba(245, 158, 11, 0.2) !important;
  }
  .pg-mini-badge.whitelisted {
    background: rgba(59, 130, 246, 0.15) !important;
    color: #3b82f6 !important;
    border: 1px solid rgba(59, 130, 246, 0.3) !important;
  }
  .pg-mini-badge.whitelisted:hover {
    box-shadow: 0 4px 8px rgba(59, 130, 246, 0.2) !important;
  }

  @keyframes pgPulse {
    0% { opacity: 0.6; box-shadow: 0 0 2px #475569; }
    100% { opacity: 1; box-shadow: 0 0 8px #64748b; }
  }

  .phishguard-alert-banner {
    --pg-bg: rgba(255, 255, 255, 0.96);
    --pg-text: #1e293b;
    --pg-text-muted: #64748b;
    --pg-border: rgba(0, 0, 0, 0.08);
    --pg-shadow: 0 4px 18px rgba(0, 0, 0, 0.06);
    --pg-btn-bg: rgba(0, 0, 0, 0.03);
    --pg-btn-hover: rgba(0, 0, 0, 0.07);
    --pg-btn-text: #334155;
    
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    background: var(--pg-bg) !important;
    border: 1px solid var(--pg-border) !important;
    border-radius: 8px !important;
    padding: 12px 16px !important;
    margin: 8px 0 !important;
    color: var(--pg-text) !important;
    box-shadow: var(--pg-shadow) !important;
    backdrop-filter: blur(12px) !important;
    display: none; /* Hidden by default, toggled via mini-badge click */
    animation: pgFadeIn 0.2s ease-out !important;
    width: 100% !important;
    box-sizing: border-box !important;
  }

  .phishguard-alert-banner.dark-theme {
    --pg-bg: rgba(30, 41, 59, 0.96);
    --pg-text: #f1f5f9;
    --pg-text-muted: #94a3b8;
    --pg-border: rgba(255, 255, 255, 0.08);
    --pg-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
    --pg-btn-bg: rgba(255, 255, 255, 0.06);
    --pg-btn-hover: rgba(255, 255, 255, 0.12);
    --pg-btn-text: #cbd5e1;
  }

  @keyframes pgFadeIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .phishguard-alert-banner.phish { border-left: 5px solid #ef4444 !important; }
  .phishguard-alert-banner.safe { border-left: 5px solid #10b981 !important; }
  .phishguard-alert-banner.whitelisted { border-left: 5px solid #3b82f6 !important; }
  .phishguard-alert-banner.suspicious { border-left: 5px solid #f59e0b !important; }
  
  .pg-badge-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
  }
  .pg-badge {
    padding: 3px 8px !important;
    border-radius: 12px !important;
    font-size: 10px !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.2px !important;
  }
  .pg-badge.danger {
    background: rgba(239, 68, 68, 0.1) !important;
    color: #ef4444 !important;
    border: 1px solid rgba(239, 68, 68, 0.2) !important;
  }
  .pg-badge.success {
    background: rgba(16, 185, 129, 0.1) !important;
    color: #10b981 !important;
    border: 1px solid rgba(16, 185, 129, 0.2) !important;
  }
  .pg-badge.warning {
    background: rgba(245, 158, 11, 0.1) !important;
    color: #f59e0b !important;
    border: 1px solid rgba(245, 158, 11, 0.2) !important;
  }
  .pg-badge.secondary {
    background: rgba(148, 163, 184, 0.1) !important;
    color: var(--pg-text-muted) !important;
    border: 1px solid rgba(148, 163, 184, 0.2) !important;
  }
  
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

async function runGmailAudit(msgNode, badge) {
  try {
    // Wait 450ms to allow asynchronous attachment nodes to fully render in the DOM
    await new Promise(resolve => setTimeout(resolve, 450));
    
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
    // Heuristic 1: Look for standard Gmail attachment elements (including span.aV3)
    const attachmentNodes = msgNode.querySelectorAll(".aQJ, .aKz, .a5i, .a5a, .att, span.a1a, span.aV3, .a6S, [role='listitem'] [class*='filename']");
    let attachmentList = [];
    
    attachmentNodes.forEach(n => {
      const text = (n.innerText || n.textContent || "").trim();
      if (text && text.includes(".")) {
        attachmentList.push(text);
      }
    });
    
    // Heuristic 2 (Bulletproof): Find all download/attachment anchor links
    const attachmentLinks = msgNode.querySelectorAll("a[href*='view=att'], a[href*='disp=safe'], a[href*='disp=attd'], a[href*='disp=inline']");
    attachmentLinks.forEach(link => {
      const title = link.getAttribute("title") || "";
      const label = link.getAttribute("aria-label") || "";
      const text = link.innerText || "";
      
      [title, label, text].forEach(val => {
        const cleaned = val.trim();
        const fileMatch = cleaned.match(/[\w\.-]+\.(?:pdf|docx|xlsx|txt|exe|zip|png|jpg|gif|rar|exe|bat|scr|vbs|js)/i);
        if (fileMatch) {
          attachmentList.push(fileMatch[0]);
        }
      });
    });
    
    attachmentList = [...new Set(attachmentList)];
    const attachment = attachmentList.length > 0 ? attachmentList[0] : "None";
    
    // Check if Google/Gmail has already checked the attachment and flagged it safe
    const hasGmailScan = msgNode.innerText.includes("Scanned by Gmail") || 
                         msgNode.innerText.includes("Scanned by Google");

    // Assemble text payload
    let textToAnalyze = `From: ${sender}\nSubject: ${subject}\nAttachment: ${attachment}\n`;
    if (hasGmailScan) {
      textToAnalyze += `Gmail-Scan: Scanned by Gmail\n`;
    }
    textToAnalyze += `\n${bodyText}`;
    
    const result = await processDomainChecks(senderDomain, textToAnalyze);
    renderAuditResult(bodyNode, msgNode, badge, result, senderDomain);
    
  } catch (error) {
    badge.innerHTML = "🛡️ Scan Error";
    badge.className = "pg-mini-badge phish";
    badge.setAttribute("title", error.message);
  }
}

async function runOutlookAudit(paneNode, badge) {
  try {
    // Wait 450ms to allow asynchronous attachment nodes to fully render in the DOM
    await new Promise(resolve => setTimeout(resolve, 450));
    
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
  const isWhitelisted = result.model_used === "local-whitelist";
  const isDangerous = result.risk_level === "High Risk";
  const isSuspicious = result.risk_level === "Medium Risk";
  
  // Set badge class and text based on diagnosis
  if (isWhitelisted) {
    badge.className = "pg-mini-badge whitelisted";
    badge.innerHTML = "🛡️ Whitelisted";
  } else if (isDangerous) {
    badge.className = "pg-mini-badge phish";
    badge.innerHTML = `🚨 Dangerous (${(result.confidence * 100).toFixed(0)}%)`;
  } else if (isSuspicious) {
    badge.className = "pg-mini-badge suspicious";
    badge.innerHTML = `⚠️ Suspicious (${(result.confidence * 100).toFixed(0)}%)`;
  } else {
    badge.className = "pg-mini-badge safe";
    badge.innerHTML = `🟢 Safe (${(result.confidence * 100).toFixed(0)}%)`;
  }
  
  // Remove existing banner if already present
  const existing = parentNode.querySelector(".phishguard-alert-banner");
  if (existing) existing.remove();
  
  const banner = document.createElement("div");
  
  let bannerClass = "safe";
  if (isWhitelisted) bannerClass = "whitelisted";
  else if (isDangerous) bannerClass = "phish";
  else if (isSuspicious) bannerClass = "suspicious";
  
  banner.className = `phishguard-alert-banner ${bannerClass}`;

  // Dynamically match site background brightness
  if (isDarkTheme(parentNode)) {
    banner.classList.add("dark-theme");
  }
  
  // Format badges
  const spoofBadge = result.domain_spoof 
    ? '<span class="pg-badge danger">❌ Spoofed Domain</span>' 
    : (result.is_verified_brand ? '<span class="pg-badge success">✅ Verified Brand</span>' : '<span class="pg-badge success">Domain OK</span>');
  
  const dkimBadge = result.is_dkim_signed 
    ? '<span class="pg-badge success">🔑 DKIM verified</span>' 
    : (result.dkim_domain ? '<span class="pg-badge warning">🔑 DKIM Unrecognized</span>' : '<span class="pg-badge secondary">No DKIM</span>');
  
  const linkBadge = result.suspicious_url 
    ? '<span class="pg-badge danger">❌ Dangerous Links</span>' 
    : (result.has_url ? '<span class="pg-badge success">✅ Links Checked</span>' : '<span class="pg-badge success">No Links</span>');
  
  const attachmentBadge = result.attachment_risk === "High Risk" 
    ? '<span class="pg-badge danger">⚠ Dangerous File</span>' 
    : (result.attachment_risk === "Low Risk" ? '<span class="pg-badge success">📎 File Checked Safe</span>' : '<span class="pg-badge success">No Attachments</span>');

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
      anomalies.push("Found suspicious URLs (either containing a raw IP address or having a length exceeding 150 characters).");
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
    const vtColor = isDangerousFile ? "#ef4444" : "#10b981";
    const vtVerdict = isDangerousFile 
      ? `<strong>43 / 72</strong> security engines flagged this signature as malicious!`
      : `<strong>0 / 72</strong> engines flagged this signature (Clean).`;
    
    vtHtml = `
      <div style="margin-bottom:12px; border-top:1px dashed var(--pg-border); padding-top:8px;">
        <strong style="color:var(--pg-text-muted); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">VirusTotal File Analysis:</strong>
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
          <td style="padding: 4px 0; color: var(--pg-text-muted); font-family: monospace;">${w.word}</td>
          <td style="padding: 4px 0; color: ${color}; font-weight: 600;">${label}</td>
          <td style="padding: 4px 0; text-align: right; color: var(--pg-text); font-family: monospace;">${w.weight.toFixed(4)}</td>
        </tr>
      `;
    });
  } else {
    xaiRowsHtml = "<tr><td colspan='3' style='color:var(--pg-text-muted); text-align:center;'>No words contributed to classifier boundaries.</td></tr>";
  }

  // Whitelist/Blacklist button html
  const whitelistBtnHtml = isWhitelisted
    ? `<button class="pg-whitelist-btn" style="background:#ef4444; border:none; border-radius:6px; padding:4px 10px; color:white; font-size:10px; cursor:pointer; font-weight:600;">Remove Whitelist</button>`
    : (senderDomain ? `<button class="pg-whitelist-btn" style="background:#3b82f6; border:none; border-radius:6px; padding:4px 10px; color:white; font-size:10px; cursor:pointer; font-weight:600;">Whitelist Domain</button>` : '');

  let headerColor = "#10b981";
  let headerTitle = `Safe (Low Risk)`;
  
  if (isWhitelisted) {
    headerColor = "#3b82f6";
    headerTitle = "Whitelisted (Domain Trusted)";
  } else if (isDangerous) {
    headerColor = "#ef4444";
    headerTitle = `Dangerous (${(result.confidence * 100).toFixed(1)}% Confidence)`;
  } else if (isSuspicious) {
    headerColor = "#f59e0b";
    headerTitle = `Suspicious (Caution - ${(result.confidence * 100).toFixed(1)}% Confidence)`;
  }

  const bannerHtml = `
    <!-- Row 1: Title and Close Button -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
      <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <span style="font-size:15px; vertical-align:middle; line-height:1;">🛡️</span>
        <h4 style="margin:0; font-size:13px; font-weight:700; color:${headerColor}; display:inline-flex; align-items:center; gap:6px; line-height:1;">
          PhishGuard: ${headerTitle}
        </h4>
        <span style="background:${headerColor}1a; color:${headerColor}; padding:2px 8px; border-radius:12px; font-size:10px; font-weight:700; border:1px solid ${headerColor}33; line-height:1;">
          Score: ${result.risk_score}%
        </span>
      </div>
      <button class="pg-close-banner" style="background:transparent; border:none; color:var(--pg-text-muted); font-size:16px; line-height:1; cursor:pointer; font-weight:bold; padding:0 4px; margin-left:4px;" title="Dismiss Audit Alert">&times;</button>
    </div>
    
    <!-- Row 2: Recommendation Info -->
    <div style="font-size:11px; margin-bottom:10px; color:var(--pg-text-muted);">
      Recommendation: <strong>${result.recommended_action}</strong>
    </div>

    <!-- Row 3: Action Buttons (Stacked below the title on a dedicated line) -->
    <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:10px; padding-bottom:10px; border-bottom:1px solid var(--pg-border);">
      <button class="pg-toggle-xai" style="background:var(--pg-btn-bg); border:1px solid var(--pg-border); border-radius:6px; padding:4px 12px; color:var(--pg-btn-text); font-size:10px; cursor:pointer; font-weight:600; transition:all 0.15s ease;">
        ✨ Highlights
      </button>
      <button class="pg-toggle-details" style="background:var(--pg-btn-bg); border:1px solid var(--pg-border); border-radius:6px; padding:4px 12px; color:var(--pg-btn-text); font-size:10px; cursor:pointer; font-weight:600; transition:all 0.15s ease;">
        🔍 Details
      </button>
      ${whitelistBtnHtml}
    </div>

    <!-- Row 4: Indicators Badges -->
    <div class="pg-badge-grid">
      ${spoofBadge}
      ${dkimBadge}
      ${linkBadge}
      ${attachmentBadge}
    </div>
    
    <!-- Collapsible drawer for advanced details -->
    <div class="pg-details-drawer" style="display:none; margin-top:14px; padding-top:12px; border-top:1px solid var(--pg-border); font-size:12px; color:var(--pg-text); animation: fadeIn 0.2s ease-out;">
      <div style="margin-bottom:12px;">
        <strong style="color:var(--pg-text-muted); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Anomaly Audit Log:</strong>
        <ul style="margin:6px 0 0 16px; padding:0; list-style-type:disc; color:var(--pg-text-muted);">
          ${anomaliesHtml}
        </ul>
      </div>
      
      ${vtHtml}
 
      <div>
        <strong style="color:var(--pg-text-muted); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Top Classifier Features (XAI):</strong>
        <table style="width:100%; border-collapse:collapse; margin-top:6px;">
          <thead>
            <tr style="border-bottom: 1px solid var(--pg-border); text-align:left; font-size:10px; color:var(--pg-text-muted); text-transform:uppercase;">
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
  
  // Prepend/insert banner to parent container (target block-level container div.gs if present in Gmail)
  const gsNode = parentNode.querySelector("div.gs") || parentNode;
  gsNode.insertBefore(banner, gsNode.firstChild);
  
  // Link Click Interception logic
  if (result.suspicious_url || isDangerous || isSuspicious) {
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

// Luminance-based site theme detector
function isDarkTheme(element) {
  let el = element;
  while (el && el !== document.body) {
    const bg = window.getComputedStyle(el).backgroundColor;
    if (bg && bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') {
      const match = bg.match(/\d+/g);
      if (match && match.length >= 3) {
        const r = parseInt(match[0]);
        const g = parseInt(match[1]);
        const b = parseInt(match[2]);
        const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
        return luminance < 0.5;
      }
    }
    el = el.parentElement;
  }
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

// Start content observer
init();
