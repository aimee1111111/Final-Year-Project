import "./url-toggle.js";

export function displayUrlError(resultMessage) {
  resultMessage.innerHTML = `
    <div style="text-align:left;">
      <h3 style="color:red;">❌ Error Checking URL</h3>
      <p>Could not complete the security check. This might be due to:</p>
      <ul style="margin:10px 0; padding-left:20px;">
        <li>Network connectivity issues</li>
        <li>API rate limits reached</li>
        <li>CORS restrictions (browser security)</li>
        <li>Invalid or expired API keys</li>
      </ul>
      <p><strong>Tip:</strong> Check the browser console (F12) for detailed error messages.</p>
    </div>
  `;
  resultMessage.style.color = "red";
}

export function displayCombinedResults(results, scanTime, scannedUrl) {
  const resultMessage = document.getElementById("resultMessage");

  const normalized = results.map(
    (r) => r ?? { service: "(Unknown)", error: true, details: "No result" }
  );

  const anyUnsafe = normalized.some((r) => !r.error && r.safe === false);
  const hasErrors = normalized.some((r) => r.error);
  const servicesChecked = normalized.filter((r) => !r.error).length;
  const servicesReporting = normalized.filter((r) => !r.error && r.safe === false).length;

  let confidenceLevel = "High";
  if (servicesChecked < 2) confidenceLevel = "Low";
  else if (servicesReporting === 1 && servicesChecked >= 2) confidenceLevel = "Medium";
  else if (servicesChecked >= 3 && servicesReporting === 0) confidenceLevel = "Very High";

  const allThreats = normalized.flatMap((r) =>
    !r.error && !r.safe && Array.isArray(r.threats) ? r.threats : []
  );

  const isDanger = anyUnsafe;
  const isWarning = !anyUnsafe && hasErrors;
  const variant = isDanger ? "danger" : isWarning ? "warning" : "safe";

  const iconMap = {
    safe: `<svg width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="rgba(16,185,129,0.15)" stroke="rgba(16,185,129,0.5)" stroke-width="2"/><path d="M20 32 L28 40 L44 24" stroke="#10b981" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    danger: `<svg width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="rgba(239,68,68,0.15)" stroke="rgba(239,68,68,0.5)" stroke-width="2"/><path d="M32 20 L32 38 M32 46 L32 48" stroke="#ef4444" stroke-width="4" stroke-linecap="round"/></svg>`,
    warning: `<svg width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="rgba(251,191,36,0.15)" stroke="rgba(251,191,36,0.5)" stroke-width="2"/><path d="M32 20 L32 38 M32 46 L32 48" stroke="#fbbf24" stroke-width="4" stroke-linecap="round"/></svg>`
  };

  const titleMap = {
    safe: "✓ Link Looks Safe",
    danger: "⚠️ Unsafe URL!",
    warning: "⚠️ Partial Results"
  };

  const verdictMap = {
    safe: "Safe",
    danger: "Unsafe",
    warning: "Caution"
  };

  const displayUrl =
    scannedUrl && scannedUrl.length > 50
      ? `${scannedUrl.slice(0, 47)}…`
      : (scannedUrl || "");

  const simpleView = `
    <div class="uc-card uc-card--${variant}">
      <div class="uc-card__header">
        <div class="uc-card__icon">${iconMap[variant]}</div>
        <div>
          <div class="uc-card__title uc-card__title--${variant}">${titleMap[variant]}</div>
          <div class="uc-card__url">${displayUrl}</div>
        </div>
      </div>

      ${isDanger ? `
        <div class="uc-alert uc-alert--danger">
          <div class="uc-alert__title uc-alert__title--danger">🚨 This link is dangerous</div>
          <p class="uc-alert__body">One or more security services flagged this URL as malicious.
            <strong>Do not open it</strong> and do not share it with others.</p>

          ${allThreats.length ? `
            <div class="uc-threat-label">Threat types detected</div>
            <div class="uc-threat-tags">
              ${allThreats.map((t) => `<span class="uc-threat-tag">${t}</span>`).join("")}
            </div>
          ` : ""}

          <div class="uc-action-box uc-action-box--danger">
            <div class="uc-action-box__title uc-action-box__title--danger">⚠️ What to do:</div>
            <ol>
              <li>Close this tab and do <strong>not</strong> revisit the link</li>
              <li>If you already visited it, run a full security scan on your device</li>
              <li>Do not enter any personal information or passwords</li>
              <li>Report it as phishing/malware to your browser</li>
            </ol>
          </div>
        </div>
      ` : isWarning ? `
        <div class="uc-alert uc-alert--warning">
          <p class="uc-alert__body">Some security services couldn't be reached, but the ones that
            responded found no threats. Exercise caution before opening this link.</p>
        </div>
      ` : `
        <div class="uc-alert uc-alert--safe">
          <div class="uc-safe-check">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#10b981" stroke-width="2">
              <polyline points="17 5 8 14 3 9"/>
            </svg>
            No threats detected
          </div>
          <p class="uc-alert__body--muted">
            This link was checked by ${servicesChecked} security service${servicesChecked !== 1 ? "s" : ""}
            and none flagged it as dangerous.
          </p>
          <div class="uc-action-box uc-action-box--safe">
            <div class="uc-action-box__title uc-action-box__title--safe">✓ Safe to proceed</div>
            <p class="uc-action-box__text">This URL appears safe. Still, only visit sites you trust
              and look out for lookalike domains.</p>
          </div>
        </div>
      `}

      <div class="uc-meta-grid">
        <div class="uc-meta-card">
          <span class="uc-meta-card__icon">🛡️</span>
          <div>
            <div class="uc-meta-card__label">Services</div>
            <div class="uc-meta-card__value">${servicesChecked} / ${normalized.length}</div>
          </div>
        </div>
        <div class="uc-meta-card">
          <span class="uc-meta-card__icon">📊</span>
          <div>
            <div class="uc-meta-card__label">Confidence</div>
            <div class="uc-meta-card__value">${confidenceLevel}</div>
          </div>
        </div>
        <div class="uc-meta-card">
          <span class="uc-meta-card__icon">⏱️</span>
          <div>
            <div class="uc-meta-card__label">Scan time</div>
            <div class="uc-meta-card__value">${scanTime}s</div>
          </div>
        </div>
        <div class="uc-meta-card">
          <span class="uc-meta-card__icon">${isDanger ? "⚠️" : "✅"}</span>
          <div>
            <div class="uc-meta-card__label">Verdict</div>
            <div class="uc-meta-card__value uc-meta-card__value--${variant}">${verdictMap[variant]}</div>
          </div>
        </div>
      </div>
    </div>
  `;

  const threatValueClass = isDanger
    ? "uc-tech-stat__value--bad"
    : "uc-tech-stat__value--safe";

  let techHtml = `
    <div class="uc-tech-panel">
      <div class="uc-tech-url-section">
        <div class="uc-tech-url-label">Scanned URL</div>
        <div class="uc-tech-url-value">${scannedUrl || "—"}</div>
      </div>
      <div class="uc-tech-stats">
        <div>
          <span class="uc-tech-stat__label">Scan time</span>
          <span class="uc-tech-stat__value">${scanTime}s</span>
        </div>
        <div>
          <span class="uc-tech-stat__label">Confidence</span>
          <span class="uc-tech-stat__value">${confidenceLevel}</span>
        </div>
        <div>
          <span class="uc-tech-stat__label">Services responded</span>
          <span class="uc-tech-stat__value">${servicesChecked} / ${normalized.length}</span>
        </div>
        <div>
          <span class="uc-tech-stat__label">Threats reported by</span>
          <span class="uc-tech-stat__value ${threatValueClass}">
            ${servicesReporting} service${servicesReporting !== 1 ? "s" : ""}
          </span>
        </div>
      </div>
  `;

  normalized.forEach((r) => {
    techHtml += buildServiceRow(r);
  });

  techHtml += `</div>`;

  const uid = "uc_" + Date.now();

  resultMessage.innerHTML = `
    <div class="uc-wrapper">
      <div class="uc-toggle-bar">
        <button class="uc-toggle-btn uc-toggle-btn--active"
                id="${uid}_btn_simple"
                onclick="window.ucToggle('${uid}','simple')">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M2 3h12v2H2V3zm0 4h12v2H2V7zm0 4h12v2H2v-2z"/>
          </svg>
          Simple View
        </button>
        <button class="uc-toggle-btn uc-toggle-btn--inactive"
                id="${uid}_btn_technical"
                onclick="window.ucToggle('${uid}','technical')">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M5.854 4.854a.5.5 0 1 0-.708-.708l-3.5 3.5a.5.5 0 0 0 0 .708l3.5 3.5a.5.5 0 0 0 .708-.708L2.707 8l3.147-3.146zm4.292 0a.5.5 0 0 1 .708-.708l3.5 3.5a.5.5 0 0 1 0 .708l-3.5 3.5a.5.5 0 0 1-.708-.708L13.293 8l-3.147-3.146z"/>
          </svg>
          Technical Details
        </button>
      </div>

      <div id="${uid}_simple">${simpleView}</div>
      <div id="${uid}_technical" style="display:none;">${techHtml}</div>
    </div>
  `;

  resultMessage.style.color = "#fff";
}

function buildServiceRow(result) {
  if (!result || !result.service) {
    return `<div class="uc-service uc-service--error">
      <span class="uc-service__name uc-service__name--error">(Unknown Service)</span>
      <span class="uc-service__error-text"> — unavailable</span>
    </div>`;
  }

  const isError = !!result.error;
  const isThreat = !isError && result.safe === false;
  const isClean = !isError && result.safe === true;

  const cls = isThreat ? "threat" : (isClean ? "clean" : "error");
  const badge = isClean ? "✓ Clean" : (isThreat ? "✗ Threat detected" : "⚠ Unavailable");

  let html = `
    <div class="uc-service uc-service--${cls}">
      <div class="uc-service__header">
        <span class="uc-service__name uc-service__name--${cls}">${result.service}</span>
        <span class="uc-service__badge uc-service__badge--${cls}">${badge}</span>
      </div>
  `;

  if (isError) {
    html += `<div class="uc-service__error-text">
      Service unavailable${result.details ? ` — ${result.details}` : ""}
    </div>`;
  } else {
    const rows = [];

    if (Array.isArray(result.threats) && result.threats.length) {
      rows.push(["Threats", result.threats.join(", ")]);
    }
    if (typeof result.malicious === "number") rows.push(["Malicious", result.malicious]);
    if (typeof result.suspicious === "number") rows.push(["Suspicious", result.suspicious]);
    if (typeof result.undetected === "number") rows.push(["Undetected", result.undetected]);
    if (typeof result.harmless === "number") rows.push(["Harmless", result.harmless]);
    if (typeof result.totalEngines === "number") rows.push(["Total engines", result.totalEngines]);
    if (result.disposition && result.disposition !== "N/A") rows.push(["Disposition", result.disposition]);
    if (result.brand && result.brand !== "N/A") rows.push(["Brand", result.brand]);
    if (result.jobID) rows.push(["Job ID", result.jobID]);
    if (result.hasA !== undefined) rows.push(["DNS A records", result.hasA ? "yes" : "no"]);
    if (result.hasAAAA !== undefined) rows.push(["DNS AAAA records", result.hasAAAA ? "yes" : "no"]);
    if (result.hasMX !== undefined) rows.push(["DNS MX records", result.hasMX ? "yes" : "no"]);
    if (Array.isArray(result.ips) && result.ips.length) rows.push(["IP addresses", result.ips.join(", ")]);
    if (result.details) rows.push(["Raw details", result.details]);
    if (result.host) rows.push(["Hostname", result.host]);

    if (rows.length) {
      html += `<table class="uc-service__table">`;
      rows.forEach(([label, val]) => {
        html += `<tr><td>${label}</td><td>${val}</td></tr>`;
      });
      html += `</table>`;
    }
  }

  html += `</div>`;
  return html;
}