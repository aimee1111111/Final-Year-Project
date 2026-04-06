import {
  escapeHtml,
  bytesToHuman,
  safeFlag,
  pickThreatList,
  pickScanResults,
  formatEngineDetail
} from "./file-utils.js";

import "./file-toggle.js";

export function resetUI(resultDiv, detailsDiv) {
  resultDiv.style.display = "none";
  resultDiv.textContent = "";
  detailsDiv.style.display = "none";
  detailsDiv.innerHTML = "";
}

export function renderHeaderSingle(resultDiv, resultObj) {
  const safe = safeFlag(resultObj);
  const msg = resultObj?.message;

  let text;
  let cls;

  if (safe) {
    text = `✓ ${msg || "File is clean"}`;
    cls = "ok";
  } else {
    const threats = pickThreatList(resultObj);
    const items = threats.length ? threats.join(", ") : "Unknown";
    text = `✗ ${msg || "Threats detected"} — ${items}`;
    cls = "bad";
  }

  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="${cls}">${escapeHtml(text)}</div>`;
}

export function renderFolderHeader(resultDiv, results, skippedCount = 0, skippedBytes = 0) {
  const totalFiles = results.length;
  const cleanFiles = results.filter((r) => safeFlag(r) === true && !r.error).length;
  const threatsFound = results.filter((r) => safeFlag(r) === false && !r.error).length;
  const errors = results.filter((r) => !!r.error).length;

  let text;
  let cls;

  if (threatsFound > 0) {
    text = `✗ Threats detected in ${threatsFound} of ${totalFiles} files`;
    cls = "bad";
  } else if (errors > 0) {
    text = `⚠ Scan completed with ${errors} error(s) in ${totalFiles} files`;
    cls = "bad";
  } else {
    text = `✓ All ${totalFiles} files are clean`;
    cls = "ok";
  }

  const skippedLine = skippedCount > 0
    ? `<div class="muted" style="margin-top:6px;">Skipped: ${skippedCount} file(s) (${escapeHtml(bytesToHuman(skippedBytes))}) due to size limits</div>`
    : "";

  resultDiv.style.display = "block";
  resultDiv.innerHTML = `
    <div class="${cls}">${escapeHtml(text)}</div>
    <div class="muted" style="margin-top: 20px;">Clean: ${cleanFiles} | Threats: ${threatsFound} | Errors: ${errors}</div>
    ${skippedLine}
  `;
}

export function buildDetailsRichHtml(resultObj, fileObjOrName) {
  const when = new Date().toLocaleString();
  const safe = safeFlag(resultObj);
  const verdict = safe ? "Clean" : "Threats detected";
  const verdictClass = safe ? "ok" : "bad";

  let fname = "(unknown)";
  let fsize = "";
  let ftype = "—";

  if (fileObjOrName && typeof fileObjOrName === "object") {
    fname = fileObjOrName.name || fname;
    fsize = fileObjOrName.size ? bytesToHuman(fileObjOrName.size) : "";
    ftype = fileObjOrName.type || "—";
  } else if (typeof fileObjOrName === "string") {
    fname = fileObjOrName;
  }

  const sha256 = resultObj?.sha256 || "";
  const threats = pickThreatList(resultObj);
  const engines = pickScanResults(resultObj);
  const totalEngines = engines.length;

  const threatEngines = engines.filter((r) => {
    const status = (r.status || r.result || "").toLowerCase();
    return status === "threat_detected" || status === "malicious" || status === "infected";
  }).length;

  const userFriendlyView = `
    <div class="scan-result-card ${safe ? "result-safe" : "result-danger"}">
      <div class="result-header">
        <div class="result-icon">
          ${
            safe
              ? '<svg width="60" height="60" viewBox="0 0 60 60"><circle cx="30" cy="30" r="28" fill="#10b981" opacity="0.2"/><path d="M20 30 L27 37 L40 23" stroke="#10b981" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>'
              : '<svg width="60" height="60" viewBox="0 0 60 60"><circle cx="30" cy="30" r="28" fill="#ef4444" opacity="0.2"/><path d="M30 18 L30 34 M30 42 L30 44" stroke="#ef4444" stroke-width="4" stroke-linecap="round"/></svg>'
          }
        </div>
        <div class="result-content">
          <h2 class="result-title">${safe ? "✓ File is Safe" : "⚠ Threats Detected!"}</h2>
          <p class="result-filename">${escapeHtml(fname)}</p>
        </div>
      </div>

      ${
        !safe
          ? `
        <div class="threat-alert">
          <h3 class="alert-title">⚠️ Security Alert</h3>
          <p class="alert-message">This file contains malicious content. <strong>Do not open it.</strong></p>

          <div class="threat-details">
            <h4>Detected Threats:</h4>
            <ul class="threat-list">
              ${threats.map((t) => `<li><span class="threat-badge">${escapeHtml(t)}</span></li>`).join("")}
            </ul>
          </div>

          <div class="action-box danger">
            <h4>⚠️ What to Do:</h4>

            <div class="response-step">
              <div class="response-step-number">1.</div>
              <div class="response-step-content">
                <div class="response-step-title">Delete this file immediately</div>
              </div>
            </div>

            <div class="response-step">
              <div class="response-step-number">2.</div>
              <div class="response-step-content">
                <div class="response-step-title">If you opened it, run a full system scan</div>
              </div>
            </div>

            <div class="response-step">
              <div class="response-step-number">3.</div>
              <div class="response-step-content">
                <div class="response-step-title">Change passwords if you entered any credentials</div>
              </div>
            </div>

            <div class="response-step">
              <div class="response-step-number">4.</div>
              <div class="response-step-content">
                <div class="response-step-title">Monitor your accounts for unusual activity</div>
              </div>
            </div>
          </div>
        </div>
      `
          : `
        <div class="safe-summary">
          <div class="scan-success">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            <span>No threats detected</span>
          </div>
          <p class="scan-info">This file has been scanned by ${totalEngines} security engine${totalEngines !== 1 ? "s" : ""} and appears to be safe.</p>

          <div class="action-box safe">
            <h4>✓ You're Good to Go</h4>
            <p>This file appears safe to open and use. However, always exercise caution with files from unknown sources.</p>
          </div>
        </div>
      `
      }

      <div class="scan-meta-grid">
        <div class="meta-card">
          <div class="meta-icon">📄</div>
          <div class="meta-info">
            <div class="meta-label">File Size</div>
            <div class="meta-value">${escapeHtml(fsize || "Unknown")}</div>
          </div>
        </div>

        <div class="meta-card">
          <div class="meta-icon">🕐</div>
          <div class="meta-info">
            <div class="meta-label">Scanned</div>
            <div class="meta-value">${escapeHtml(when.split(",")[0])}</div>
          </div>
        </div>

        <div class="meta-card">
          <div class="meta-icon">🛡️</div>
          <div class="meta-info">
            <div class="meta-label">Engines</div>
            <div class="meta-value">${totalEngines} scanner${totalEngines !== 1 ? "s" : ""}</div>
          </div>
        </div>

        ${
          !safe
            ? `
          <div class="meta-card danger">
            <div class="meta-icon">⚠️</div>
            <div class="meta-info">
              <div class="meta-label">Threats Found</div>
              <div class="meta-value">${threatEngines} detection${threatEngines !== 1 ? "s" : ""}</div>
            </div>
          </div>
        `
            : `
          <div class="meta-card success">
            <div class="meta-icon">✓</div>
            <div class="meta-info">
              <div class="meta-label">Status</div>
              <div class="meta-value">All Clear</div>
            </div>
          </div>
        `
        }
      </div>
    </div>
  `;

  const threatList = threats.length
    ? `<ul class="tech-threat-list">${threats.map((t) => `<li>${escapeHtml(t)}</li>`).join("")}</ul>`
    : `<div class="muted">No threats listed.</div>`;

  const enginesHTML = engines.map((r) => {
    const eng = r.engine || r.name || "Engine";
    const status = r.status || r.result || "unknown";
    let detail = "";

    if (r.details) {
      detail = formatEngineDetail(eng, r.details);
    } else if (r.error) {
      detail = `error: ${r.error}`;
    } else if (r.message) {
      detail = r.message;
    }

    let chips = "";
    if (Array.isArray(r.details)) {
      const allTags = r.details.flatMap((d) => Array.isArray(d.tags) ? d.tags : []);
      if (allTags.length) {
        const uniq = [...new Set(allTags)];
        chips = `<div class="muted">Tags: ${uniq.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join(" ")}</div>`;
      }
    }

    return `
      <div class="engine">
        <div class="field"><label>Engine</label><div>${escapeHtml(eng)}</div></div>
        <div class="field"><label>Status</label><div>${escapeHtml(status)}</div></div>
        ${detail ? `<div class="field"><label>Details</label><div>${escapeHtml(detail)}</div></div>` : ""}
        ${chips}
      </div>
    `;
  }).join("");

  const technicalView = `
    <div class="technical-panel">
      <h3>Technical Details</h3>
      <form class="kv">
        <label>Filename</label><input type="text" value="${escapeHtml(fname)}" readonly />
        <label>Size</label><input type="text" value="${escapeHtml(fsize)}" readonly />
        <label>Type</label><input type="text" value="${escapeHtml(ftype)}" readonly />
        <label>Scanned</label><input type="text" value="${escapeHtml(when)}" readonly />
        <label>SHA-256</label><input type="text" value="${escapeHtml(sha256 || "—")}" readonly />
        <label>Verdict</label><input class="${verdictClass}" type="text" value="${escapeHtml(verdict)}" readonly />
      </form>

      <div class="tech-section">
        <h4>Per-engine results</h4>
        ${enginesHTML || '<div class="muted">No engine data.</div>'}
      </div>

      <div class="tech-section">
        <h4>Detected Threats</h4>
        ${threatList}
      </div>
    </div>
  `;

  return `
    <div class="view-toggle-container">
      <button type="button" class="view-toggle-btn active" data-view="simple" onclick="window.toggleResultView(this, 'simple')">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
          <path d="M2 3h12v2H2V3zm0 4h12v2H2V7zm0 4h12v2H2v-2z"/>
        </svg>
        Simple View
      </button>
      <button type="button" class="view-toggle-btn" data-view="technical" onclick="window.toggleResultView(this, 'technical')">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
          <path d="M5.854 4.854a.5.5 0 1 0-.708-.708l-3.5 3.5a.5.5 0 0 0 0 .708l3.5 3.5a.5.5 0 0 0 .708-.708L2.707 8l3.147-3.146zm4.292 0a.5.5 0 0 1 .708-.708l3.5 3.5a.5.5 0 0 1 0 .708l-3.5 3.5a.5.5 0 0 1-.708-.708L13.293 8l-3.147-3.146z"/>
        </svg>
        Technical Details
      </button>
    </div>

    <div class="view-content simple-view active">
      ${userFriendlyView}
    </div>

    <div class="view-content technical-view">
      ${technicalView}
    </div>
  `;
}