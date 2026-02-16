import {
  GOOGLE_API_KEY,
  VIRUSTOTAL_API_KEY,
  CHECKPHISH_API_KEY,
} from "./config.js";

// ─── Main logic ──────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const urlButton    = document.getElementById("urlButton");
  const urlInputBox  = document.getElementById("urlInputBox");
  const submitUrl    = document.getElementById("submitUrl");
  const resultMessage = document.getElementById("resultMessage");
  const urlInput     = document.getElementById("urlInput");

  if (!urlButton || !urlInputBox || !submitUrl || !resultMessage || !urlInput) {
    console.warn("url-checker.js: required elements missing on this page.");
    return;
  }

  // Toggle URL input box visibility
  urlButton.addEventListener("click", () => {
    const isHidden = urlInputBox.style.display === "none" || !urlInputBox.style.display;
    urlInputBox.style.display = isHidden ? "block" : "none";
    urlButton.setAttribute("aria-expanded", String(isHidden));
    if (isHidden) urlInput.focus();
  });

  // Handle URL submission
  submitUrl.addEventListener("click", async () => {
    const url = (urlInput.value || "").trim();
    if (!url) { alert("Please enter a URL."); return; }

    resultMessage.innerHTML =
      "🔍 Checking URL safety with multiple services...<br><small>This may take a few seconds</small>";
    resultMessage.style.color = "orange";
    submitUrl.disabled = true;

    const startTime = Date.now();

    try {
      const [
        googleResult,
        virusTotalResult,
        checkPhishResult,
        phishStatsResult,
        dnsHealthResult
      ] = await Promise.all([
        checkGoogleSafeBrowsing(url),
        checkVirusTotal(url),
        checkPhishAPI(url),
        checkPhishStats(url),
        checkDnsHealth(url)
      ]);

      const scanTime = ((Date.now() - startTime) / 1000).toFixed(1);
      displayCombinedResults(
        [googleResult, virusTotalResult, checkPhishResult, phishStatsResult, dnsHealthResult],
        scanTime,
        url
      );
    } catch (err) {
      console.error("Error checking URL:", err);
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
        </div>`;
      resultMessage.style.color = "red";
    } finally {
      submitUrl.disabled = false;
    }
  });
});

// ─── API calls (unchanged) ───────────────────────────────────────────────────

async function checkGoogleSafeBrowsing(url) {
  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "threatcheck", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );
    if (!response.ok) {
      console.error(`Google Safe Browsing HTTP error: ${response.status}`);
      return { service: "Google Safe Browsing", error: true, details: `HTTP ${response.status}` };
    }
    const data = await response.json();
    return {
      service: "Google Safe Browsing",
      safe: !data.matches || data.matches.length === 0,
      threats: data.matches ? data.matches.map(m => m.threatType) : [],
      matches: data.matches || null
    };
  } catch (err) {
    console.error("Google Safe Browsing error:", err);
    return { service: "Google Safe Browsing", error: true, details: err.message };
  }
}

async function checkVirusTotal(url) {
  try {
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": VIRUSTOTAL_API_KEY, "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`
    });
    if (!submitResponse.ok) throw new Error(`VirusTotal API error: ${submitResponse.status}`);
    const submitData = await submitResponse.json();
    const analysisId = submitData?.data?.id;

    const analysisResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": VIRUSTOTAL_API_KEY } }
    );
    if (!analysisResponse.ok) throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
    const analysisData = await analysisResponse.json();

    const stats = analysisData?.data?.attributes?.stats || {};
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;

    return {
      service: "VirusTotal",
      safe: malicious === 0 && suspicious === 0,
      malicious,
      suspicious,
      undetected:    stats.undetected    || 0,
      harmless:      stats.harmless      || 0,
      timeout:       stats.timeout       || 0,
      failure:       stats.failure       || 0,
      typeUnsupported: stats.type_unsupported || 0,
      totalEngines: Object.values(stats).filter(v => typeof v === "number").reduce((a, b) => a + b, 0)
    };
  } catch (err) {
    console.error("VirusTotal error:", err);
    return { service: "VirusTotal", error: true, details: err.message };
  }
}

async function checkPhishAPI(url) {
  try {
    const submitResponse = await fetch("https://developers.checkphish.ai/api/neo/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiKey: CHECKPHISH_API_KEY, urlInfo: { url } })
    });
    if (!submitResponse.ok) throw new Error(`CheckPhish API error: ${submitResponse.status}`);
    const { jobID } = await submitResponse.json();

    for (let attempts = 0; attempts < 15; attempts++) {
      await new Promise(r => setTimeout(r, 2000));
      const statusResponse = await fetch("https://developers.checkphish.ai/api/neo/scan/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: CHECKPHISH_API_KEY, jobID, insights: true })
      });
      if (!statusResponse.ok) throw new Error(`CheckPhish status error: ${statusResponse.status}`);
      const statusData = await statusResponse.json();

      if (statusData.status === "DONE") {
        const disposition = statusData.disposition?.toLowerCase() || "unknown";
        return {
          service: "CheckPhish",
          safe: disposition === "clean",
          disposition: statusData.disposition || "Unknown",
          brand: statusData.brand || "N/A",
          resolved: statusData.resolved || false,
          jobID,
          insights: statusData.insights ?? null,
          finalURL: statusData.url || null,
          screenshotPath: statusData.screenshot_path || null,
          raw: statusData
        };
      }
    }
    return { service: "CheckPhish", error: true, details: "Scan timeout - results not available" };
  } catch (err) {
    console.error("CheckPhish error:", err);
    return { service: "CheckPhish", error: true, details: err.message };
  }
}

async function checkDnsHealth(url) {
  try {
    const host = new URL(url).hostname;

    async function dohCF(type) {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
        { headers: { "Accept": "application/dns-json" } }
      );
      if (!res.ok) throw new Error(`CF DoH ${type} HTTP ${res.status}`);
      return res.json();
    }

    async function dohGoogle(type) {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`);
      if (!res.ok) throw new Error(`Google DoH ${type} HTTP ${res.status}`);
      return res.json();
    }

    async function doh(type) {
      try { return await dohCF(type); } catch { return await dohGoogle(type); }
    }

    const [a, aaaa, mx] = await Promise.allSettled([doh("A"), doh("AAAA"), doh("MX")]);

    const getAnswers = r =>
      r.status === "fulfilled" && Array.isArray(r.value?.Answer) ? r.value.Answer : [];

    const A_records    = getAnswers(a);
    const AAAA_records = getAnswers(aaaa);
    const MX_records   = getAnswers(mx);

    const A    = A_records.map(x => x.data);
    const AAAA = AAAA_records.map(x => x.data);
    const MX   = MX_records.map(x => x.data.split(" ").pop());

    return {
      service: "DNS (DoH)",
      safe: A.length + AAAA.length > 0,
      hasA:    A.length    > 0,
      hasAAAA: AAAA.length > 0,
      hasMX:   MX.length   > 0,
      ips: [...A, ...AAAA].slice(0, 5),
      details: `A:${A.length} AAAA:${AAAA.length} MX:${MX.length}`,
      rawA:    A_records.length    ? A_records    : null,
      rawAAAA: AAAA_records.length ? AAAA_records : null,
      rawMX:   MX_records.length   ? MX_records   : null,
      host
    };
  } catch (e) {
    console.error("DoH error:", e);
    return { service: "DNS (DoH)", error: true, details: e.message };
  }
}

async function checkPhishStats(url) {
  try {
    const q   = encodeURIComponent(`(url,eq,${url})`);
    const res = await fetch(`https://api.phishstats.info/api/phishing?_where=${q}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const arr   = await res.json();
    const found = Array.isArray(arr) && arr.length > 0;
    return {
      service: "PhishStats",
      safe: !found,
      disposition: found ? "phishing" : "clean",
      brand: found ? (arr[0].target || "N/A") : "N/A",
      resolved: found,
      records: found ? arr : []
    };
  } catch (e) {
    console.error("PhishStats error:", e);
    return { service: "PhishStats", error: true, details: e.message };
  }
}

// ─── Display ─────────────────────────────────────────────────────────────────

function displayCombinedResults(results, scanTime, scannedUrl) {
  const resultMessage = document.getElementById("resultMessage");
  const normalized = results.map(r => r ?? { service: "(Unknown)", error: true, details: "No result" });

  const allSafe           = normalized.length > 0 && normalized.every(r => !r.error && r.safe === true);
  const anyUnsafe         = normalized.some(r => !r.error && r.safe === false);
  const hasErrors         = normalized.some(r => r.error);
  const servicesChecked   = normalized.filter(r => !r.error).length;
  const servicesReporting = normalized.filter(r => !r.error && r.safe === false).length;

  let confidenceLevel = "High";
  if (servicesChecked < 2)                                    confidenceLevel = "Low";
  else if (servicesReporting === 1 && servicesChecked >= 2)   confidenceLevel = "Medium";
  else if (servicesChecked >= 3 && servicesReporting === 0)   confidenceLevel = "Very High";

  const allThreats = normalized.flatMap(r =>
    (!r.error && !r.safe && Array.isArray(r.threats)) ? r.threats : []
  );

  const isDanger  = anyUnsafe;
  const isWarning = !anyUnsafe && hasErrors;
  // isSafe = everything else

  const variant = isDanger ? "danger" : isWarning ? "warning" : "safe";

  const iconMap = {
    safe:    `<svg width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="rgba(16,185,129,0.15)" stroke="rgba(16,185,129,0.5)" stroke-width="2"/><path d="M20 32 L28 40 L44 24" stroke="#10b981" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    danger:  `<svg width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="rgba(239,68,68,0.15)" stroke="rgba(239,68,68,0.5)" stroke-width="2"/><path d="M32 20 L32 38 M32 46 L32 48" stroke="#ef4444" stroke-width="4" stroke-linecap="round"/></svg>`,
    warning: `<svg width="64" height="64" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="rgba(251,191,36,0.15)" stroke="rgba(251,191,36,0.5)" stroke-width="2"/><path d="M32 20 L32 38 M32 46 L32 48" stroke="#fbbf24" stroke-width="4" stroke-linecap="round"/></svg>`
  };

  const titleMap = {
    safe:    "✓ Link Looks Safe",
    danger:  "⚠️ Unsafe URL!",
    warning: "⚠️ Partial Results"
  };

  const verdictMap = { safe: "Safe", danger: "Unsafe", warning: "Caution" };

  const displayUrl = scannedUrl && scannedUrl.length > 50
    ? scannedUrl.slice(0, 47) + "…"
    : (scannedUrl || "");

  // ── Simple view ────────────────────────────────────────────────────────
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
              ${allThreats.map(t => `<span class="uc-threat-tag">${t}</span>`).join("")}
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

  // ── Technical view ─────────────────────────────────────────────────────
  const threatValueClass = isDanger ? "uc-tech-stat__value--bad" : "uc-tech-stat__value--safe";

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

  normalized.forEach(r => { techHtml += buildServiceRow(r); });
  techHtml += `</div>`;

  // ── Wrapper with toggle ────────────────────────────────────────────────
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

// Global toggle
window.ucToggle = function(uid, view) {
  const simpleEl  = document.getElementById(uid + "_simple");
  const techEl    = document.getElementById(uid + "_technical");
  const simpleBtn = document.getElementById(uid + "_btn_simple");
  const techBtn   = document.getElementById(uid + "_btn_technical");

  const isSimple = view === "simple";

  simpleEl.style.display = isSimple ? "block" : "none";
  techEl.style.display   = isSimple ? "none"  : "block";

  simpleBtn.className = "uc-toggle-btn " + (isSimple  ? "uc-toggle-btn--active"   : "uc-toggle-btn--inactive");
  techBtn.className   = "uc-toggle-btn " + (!isSimple ? "uc-toggle-btn--active"   : "uc-toggle-btn--inactive");
};

// Builds one service card for the technical view
function buildServiceRow(result) {
  if (!result || !result.service) {
    return `<div class="uc-service uc-service--error">
      <span class="uc-service__name uc-service__name--error">(Unknown Service)</span>
      <span class="uc-service__error-text"> — unavailable</span>
    </div>`;
  }

  const isError  = !!result.error;
  const isThreat = !isError && result.safe === false;
  const isClean  = !isError && result.safe === true;

  const cls       = isThreat ? "threat" : (isClean ? "clean" : "error");
  const badge     = isClean ? "✓ Clean" : (isThreat ? "✗ Threat detected" : "⚠ Unavailable");

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
    if (Array.isArray(result.threats) && result.threats.length) rows.push(["Threats",          result.threats.join(", ")]);
    if (typeof result.malicious    === "number")                rows.push(["Malicious",         result.malicious]);
    if (typeof result.suspicious   === "number")                rows.push(["Suspicious",        result.suspicious]);
    if (typeof result.undetected   === "number")                rows.push(["Undetected",        result.undetected]);
    if (typeof result.harmless     === "number")                rows.push(["Harmless",          result.harmless]);
    if (typeof result.totalEngines === "number")                rows.push(["Total engines",     result.totalEngines]);
    if (result.disposition && result.disposition !== "N/A")     rows.push(["Disposition",       result.disposition]);
    if (result.brand && result.brand !== "N/A")                 rows.push(["Brand",             result.brand]);
    if (result.jobID)                                           rows.push(["Job ID",            result.jobID]);
    if (result.hasA     !== undefined)                          rows.push(["DNS A records",     result.hasA     ? "yes" : "no"]);
    if (result.hasAAAA  !== undefined)                          rows.push(["DNS AAAA records",  result.hasAAAA  ? "yes" : "no"]);
    if (result.hasMX    !== undefined)                          rows.push(["DNS MX records",    result.hasMX    ? "yes" : "no"]);
    if (Array.isArray(result.ips) && result.ips.length)         rows.push(["IP addresses",      result.ips.join(", ")]);
    if (result.details)                                         rows.push(["Raw details",       result.details]);
    if (result.host)                                            rows.push(["Hostname",          result.host]);

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