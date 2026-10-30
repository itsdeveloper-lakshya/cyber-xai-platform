/**
 * In-Page Content Script (Section 6.5)
 * Captures paste & upload events via document-level capture-phase listeners.
 * Evaluates locally. Never transmits pasted text or file contents.
 */

(function() {
  console.log("[Cyber Sentinel] Content script initialized on:", window.location.hostname);

  // Cached model config
  let activeModel = null;
  fetch(chrome.runtime.getURL("config/default_model.json"))
    .then(r => r.json())
    .then(data => { activeModel = data; })
    .catch(err => console.warn("[Cyber Sentinel] Could not load default model:", err));

  // Isolated UI rendering in Shadow DOM to avoid host CSS pollution
  function showWarningModal(decision, onProceed, onCancel) {
    const existing = document.getElementById("cyber-sentinel-overlay");
    if (existing) existing.remove();

    const host = document.createElement("div");
    host.id = "cyber-sentinel-overlay";
    host.style.position = "fixed";
    host.style.top = "0";
    host.style.left = "0";
    host.style.width = "100vw";
    host.style.height = "100vh";
    host.style.zIndex = "2147483647";
    host.style.display = "flex";
    host.style.alignItems = "center";
    host.style.justifyContent = "center";
    host.style.backgroundColor = "rgba(15, 23, 42, 0.75)";
    host.style.backdropFilter = "blur(4px)";

    const shadow = host.attachShadow({ mode: "open" });
    const isBlock = decision.riskTier === "high";

    shadow.innerHTML = `
      <style>
        .dialog {
          background: #ffffff;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          color: #0f172a;
          border-radius: 12px;
          padding: 24px;
          max-width: 480px;
          width: 90%;
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
          border-top: 6px solid ${isBlock ? "#ef4444" : "#f59e0b"};
        }
        h2 { margin: 0 0 12px 0; font-size: 1.25rem; display: flex; align-items: center; gap: 8px; color: ${isBlock ? "#b91c1c" : "#b45309"}; }
        p { font-size: 0.95rem; line-height: 1.5; margin: 8px 0; color: #334155; }
        .badge-list { display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }
        .badge { background: #f1f5f9; color: #475569; padding: 4px 10px; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; }
        .override-box { margin-top: 16px; padding: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; }
        input[type="text"] { width: 100%; box-sizing: border-box; padding: 8px 10px; margin-top: 6px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.9rem; }
        .actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
        button { padding: 9px 16px; border-radius: 6px; font-size: 0.9rem; font-weight: 600; cursor: pointer; border: none; }
        .btn-cancel { background: #e2e8f0; color: #1e293b; }
        .btn-cancel:hover { background: #cbd5e1; }
        .btn-proceed { background: ${isBlock ? "#ef4444" : "#f59e0b"}; color: #ffffff; }
        .btn-proceed:hover { opacity: 0.9; }
      </style>
      <div class="dialog">
        <h2>${isBlock ? "⚠️ Potential Data Leak Blocked" : "⚠️ Sensitive Content Detected"}</h2>
        <p>This paste into <strong>${window.location.hostname}</strong> contains content flagged by data protection policy.</p>
        <div class="badge-list">
          ${decision.matchedCategories.map(c => `<span class="badge">${c}</span>`).join("")}
          <span class="badge">Risk Score: ${(decision.finalScore * 100).toFixed(0)}%</span>
        </div>
        ${isBlock ? `
          <div class="override-box">
            <label for="override-reason" style="font-size: 0.85rem; font-weight: 600; color: #475569;">Business Justification (Required to proceed):</label>
            <input type="text" id="override-reason" placeholder="e.g. Sanitized testing code for task #412" />
          </div>
        ` : `
          <p style="font-size: 0.85rem; color: #64748b;">Notice: Content metadata has been logged in accordance with enterprise data protection guidelines.</p>
        `}
        <div class="actions">
          <button class="btn-cancel" id="btn-cancel">Discard Paste</button>
          <button class="btn-proceed" id="btn-proceed">${isBlock ? "I Need to Proceed" : "Acknowledge"}</button>
        </div>
      </div>
    `;

    document.body.appendChild(host);

    const cleanup = () => host.remove();
    shadow.getElementById("btn-cancel").addEventListener("click", () => {
      cleanup();
      if (onCancel) onCancel();
    });

    shadow.getElementById("btn-proceed").addEventListener("click", () => {
      let reason = "";
      if (isBlock) {
        reason = shadow.getElementById("override-reason").value.trim();
        if (!reason) {
          alert("A business justification is required to proceed.");
          return;
        }
      }
      cleanup();
      if (onProceed) onProceed(reason);
    });
  }

  // 1. Capture-phase paste listener
  document.addEventListener("paste", function(e) {
    const clipboardData = e.clipboardData || window.clipboardData;
    if (!clipboardData) return;

    const pastedText = clipboardData.getData("text/plain");
    if (!pastedText || pastedText.length === 0) return;

    // Run local evaluation
    const decision = ScoringEngine.scoreText(pastedText, activeModel);
    console.log("[Cyber Sentinel] Paste evaluated:", decision.riskTier, "Score:", decision.finalScore);

    const eventPayload = {
      event_id: crypto.randomUUID(),
      site_domain: window.location.hostname,
      event_type: "paste",
      content_length: pastedText.length,
      line_count: pastedText.split("\n").length,
      file_extension: null,
      matched_categories: decision.matchedCategories,
      regex_score: decision.regexScore,
      ml_score: decision.mlScore,
      final_score: decision.finalScore,
      risk_tier: decision.riskTier,
      action: decision.action,
      override_used: false,
      override_reason: null,
      occurred_at: new Date().toISOString()
    };

    if (decision.riskTier === "low") {
      // Allow immediately, log event in background
      chrome.runtime.sendMessage({ type: "QUEUE_EVENT", event: eventPayload });
    } else if (decision.riskTier === "medium") {
      // Warn banner, allow paste through
      showWarningModal(decision, () => {
        chrome.runtime.sendMessage({ type: "QUEUE_EVENT", event: eventPayload });
      });
    } else if (decision.riskTier === "high") {
      // BLOCK paste immediately
      e.preventDefault();
      e.stopImmediatePropagation();

      const targetElement = e.target;
      showWarningModal(
        decision,
        (reason) => {
          // Employee overrode the block with justification
          eventPayload.override_used = true;
          eventPayload.override_reason = reason;
          chrome.runtime.sendMessage({ type: "QUEUE_EVENT", event: eventPayload });

          // Re-insert text into target if editable
          if (targetElement && (targetElement.tagName === "TEXTAREA" || targetElement.tagName === "INPUT" || targetElement.isContentEditable)) {
            if (targetElement.isContentEditable) {
              document.execCommand("insertText", false, pastedText);
            } else {
              const start = targetElement.selectionStart || 0;
              const end = targetElement.selectionEnd || 0;
              targetElement.value = targetElement.value.substring(0, start) + pastedText + targetElement.value.substring(end);
              targetElement.selectionStart = targetElement.selectionEnd = start + pastedText.length;
            }
          }
        },
        () => {
          // Discarded
          chrome.runtime.sendMessage({ type: "QUEUE_EVENT", event: eventPayload });
        }
      );
    }
  }, true); // Use capture phase!

  // 2. Capture-phase file upload listener (Drag & Drop)
  document.addEventListener("drop", function(e) {
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      for (const file of e.dataTransfer.files) {
        handleFileUploadEvent(file, e);
      }
    }
  }, true);

  // 3. Capture-phase input change listener (File inputs)
  document.addEventListener("change", function(e) {
    if (e.target && e.target.type === "file" && e.target.files && e.target.files.length > 0) {
      for (const file of e.target.files) {
        handleFileUploadEvent(file, e);
      }
    }
  }, true);

  function handleFileUploadEvent(file, originalEvent) {
    const ext = file.name.split(".").pop().toLowerCase();
    const size = file.size;
    const sensitiveExts = ["pem", "key", "pfx", "env", "sql", "csv", "xlsx", "db", "dump"];
    const isSensitive = sensitiveExts.includes(ext);

    const eventPayload = {
      event_id: crypto.randomUUID(),
      site_domain: window.location.hostname,
      event_type: "upload",
      content_length: size,
      line_count: 0,
      file_extension: ext,
      matched_categories: isSensitive ? ["SensitiveFileExtension"] : [],
      regex_score: isSensitive ? 0.8 : 0.0,
      ml_score: 0.0,
      final_score: isSensitive ? 0.8 : 0.1,
      risk_tier: isSensitive ? "high" : "low",
      action: isSensitive ? "blocked" : "logged",
      override_used: false,
      override_reason: null,
      occurred_at: new Date().toISOString()
    };

    if (isSensitive) {
      originalEvent.preventDefault();
      originalEvent.stopImmediatePropagation();
      showWarningModal(
        { riskTier: "high", finalScore: 0.8, matchedCategories: ["SensitiveExtension: ." + ext] },
        (reason) => {
          eventPayload.override_used = true;
          eventPayload.override_reason = reason;
          chrome.runtime.sendMessage({ type: "QUEUE_EVENT", event: eventPayload });
        },
        () => {
          chrome.runtime.sendMessage({ type: "QUEUE_EVENT", event: eventPayload });
        }
      );
    } else {
      chrome.runtime.sendMessage({ type: "QUEUE_EVENT", event: eventPayload });
    }
  }
})();
