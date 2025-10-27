import {//import api keys from config file
  GOOGLE_API_KEY,
  VIRUSTOTAL_API_KEY,
  CHECKPHISH_API_KEY,
} from "./config.js";
// Main logic
document.addEventListener("DOMContentLoaded", () => {
  const urlButton = document.getElementById("urlButton");
  const urlInputBox = document.getElementById("urlInputBox");
  const submitUrl = document.getElementById("submitUrl");
  const resultMessage = document.getElementById("resultMessage");
  const urlInput = document.getElementById("urlInput");

  // Toggle URL input box visibility
  urlButton.addEventListener("click", () => {
    const isHidden = urlInputBox.style.display === "none" || !urlInputBox.style.display;
    urlInputBox.style.display = isHidden ? "block" : "none";
    if (isHidden) urlInput.focus();
  });
// Handle URL submission
  submitUrl.addEventListener("click", async () => {
    const url = (urlInput.value || "").trim();
    if (!url) {
      alert("Please enter a URL.");
      return;
    }
// Indicate checking in progress
    resultMessage.innerHTML =
      "🔍 Checking URL safety with multiple services...<br><small>This may take a few seconds</small>";
    resultMessage.style.color = "orange";
    submitUrl.disabled = true;

    const startTime = Date.now();

    try {
      // Run checks in parallel
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
      const results = [
        googleResult,
        virusTotalResult,
        checkPhishResult,
        phishStatsResult,
        dnsHealthResult
      ];

      displayCombinedResults(results, scanTime);
    } catch (err) {
      console.error("Error checking URL:", err);
      resultMessage.innerHTML = `
        <div style='text-align: left;'>
          <h3 style='color: red;'>❌ Error Checking URL</h3>
          <p>Could not complete the security check. This might be due to:</p>
          <ul style='margin: 10px 0; padding-left: 20px;'>
            <li>Network connectivity issues</li>
            <li>API rate limits reached</li>
            <li>CORS restrictions (browser security)</li>
            <li>Invalid or expired API keys</li>
          </ul>
          <p><strong>Tip:</strong> Check the browser console (F12) for detailed error messages.</p>
        </div>
      `;
      resultMessage.style.color = "red";
    } finally {
      submitUrl.disabled = false;
    }
  });
});

// Checks a URL with Google Safe Browsing. Returns full matches if present.
async function checkGoogleSafeBrowsing(url) {
  try {// uses a post to check google safe browsing website with api key
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "threatcheck", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: [//checks for these threat types
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],//checks on any platform
            threatEntryTypes: ["URL"],//specifies that we are checking URLs
            threatEntries: [{ url }]//the url to check
          }
        })
      }
    );

    if (!response.ok) {
      console.error(`Google Safe Browsing HTTP error: ${response.status}`);
      return { service: "Google Safe Browsing", error: true, details: `HTTP ${response.status}` };
    }

    const data = await response.json();//get json response
    return {
      service: "Google Safe Browsing",
      safe: !data.matches || data.matches.length === 0,//if no matches, it's safe
      threats: data.matches ? data.matches.map(m => m.threatType) : [],
      //includes raw matches so you see all fields 
      matches: data.matches || null
    };
  } catch (err) {
    console.error("Google Safe Browsing error:", err);
    return { service: "Google Safe Browsing", error: true, details: err.message };
  }
}

// Checks a URL with VirusTotal. Returns stats + raw attributes/meta.
async function checkVirusTotal(url) {
  try {// Submit URL for analysis on virustotal page
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VIRUSTOTAL_API_KEY,//api key
        "Content-Type": "application/x-www-form-urlencoded"//form data
      },
      body: `url=${encodeURIComponent(url)}`
    });

    if (!submitResponse.ok) throw new Error(`VirusTotal API error: ${submitResponse.status}`);
    const submitData = await submitResponse.json();
    const analysisId = submitData?.data?.id;

    const analysisResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,//fetch analysis results
      { headers: { "x-apikey": VIRUSTOTAL_API_KEY } }
    );

    if (!analysisResponse.ok) throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
    const analysisData = await analysisResponse.json();
//parse stats from attributes
    const attrs = analysisData?.data?.attributes || {};
    const stats = attrs?.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    return {
      service: "VirusTotal",
      safe: malicious === 0 && suspicious === 0,
      malicious,
      suspicious,
      undetected: stats.undetected || 0,
      harmless: stats.harmless || 0,
      timeout: stats.timeout || 0,
      failure: stats.failure || 0,
      typeUnsupported: stats.type_unsupported || 0,
      totalEngines: Object.values(stats).filter(v => typeof v === "number").reduce((a, b) => a + b, 0),

    };
  } catch (err) {
    console.error("VirusTotal error:", err);
    return { service: "VirusTotal", error: true, details: err.message };
  }
}

// Uses CheckPhish; returns disposition + insights + raw status payload.
async function checkPhishAPI(url) {
  try {
    const submitResponse = await fetch("https://developers.checkphish.ai/api/neo/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiKey: CHECKPHISH_API_KEY, urlInfo: { url } })
    });

    if (!submitResponse.ok) throw new Error(`CheckPhish API error: ${submitResponse.status}`);//submit url for scanning
    const submitData = await submitResponse.json();
    const jobID = submitData.jobID;//get job id

    let attempts = 0;
    const maxAttempts = 15;//try for up to 30 seconds

    while (attempts < maxAttempts) {
      await new Promise(r => setTimeout(r, 2000));//wait 2 seconds between attempts

      const statusResponse = await fetch("https://developers.checkphish.ai/api/neo/scan/status", {
        method: "POST",//check scan status
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: CHECKPHISH_API_KEY, jobID, insights: true })
      });

      
      if (!statusResponse.ok) throw new Error(`CheckPhish status error: ${statusResponse.status}`);
      const statusData = await statusResponse.json();

      //if done, parse results
      if (statusData.status === "DONE") {
        const disposition = statusData.disposition?.toLowerCase() || "unknown";
        const isSafe = disposition === "clean";
        return {
          service: "CheckPhish",
          safe: isSafe,
          disposition: statusData.disposition || "Unknown",
          brand: statusData.brand || "N/A",
          resolved: statusData.resolved || false,
          jobID,
          insights: statusData.insights ?? null,  // analysis details when available
          finalURL: statusData.url || null,
          screenshotPath: statusData.screenshot_path || null,
          raw: statusData                            // full payload for maximum detail
        };
      }
      attempts++;
    }

    return { service: "CheckPhish", error: true, details: "Scan timeout - results not available" };
  } catch (err) {
    console.error("CheckPhish error:", err);
    return { service: "CheckPhish", error: true, details: err.message };
  }
}

// Checks DNS health
async function checkDnsHealth(url) {
  try {
    const host = new URL(url).hostname;

    async function dohCF(type) {//cloudflare doh(dns over https)
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
        { headers: { "Accept": "application/dns-json" } }
      );
      if (!res.ok) throw new Error(`CF DoH ${type} HTTP ${res.status}`);
      return res.json();
    }
//google doh
    async function dohGoogle(type) {
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`
      );
      if (!res.ok) throw new Error(`Google DoH ${type} HTTP ${res.status}`);
      return res.json();
    }

    async function doh(type) {//try cloudflare first, then google if it fails
      try { return await dohCF(type); } catch { return await dohGoogle(type); }
    }

    //fetch A, AAAA, MX records in parallel
    const [a, aaaa, mx] = await Promise.allSettled([
      doh("A"),//ipv4
      doh("AAAA"),//ipv6
      doh("MX")//mail exchangers
    ]);

    const getAnswers = (r) =>//extract answers if fulfilled
      r.status === "fulfilled" && Array.isArray(r.value?.Answer)
        ? r.value.Answer
        : [];

    const A_records = getAnswers(a);
    const AAAA_records = getAnswers(aaaa);
    const MX_records = getAnswers(mx);

    const A = A_records.map(x => x.data);
    const AAAA = AAAA_records.map(x => x.data);
    const MX = MX_records.map(x => x.data.split(" ").pop());

    const hasAnyIP = A.length + AAAA.length > 0;
    const hasMX = MX.length > 0;

    const safe = hasAnyIP;

    return {
      service: "DNS (DoH)",
      safe,
      hasA: A.length > 0,
      hasAAAA: AAAA.length > 0,
      hasMX,
      ips: [...A, ...AAAA].slice(0, 5),
      details: `A:${A.length} AAAA:${AAAA.length} MX:${MX.length}`,

      rawA: A_records.length ? A_records : null,
      rawAAAA: AAAA_records.length ? AAAA_records : null,
      rawMX: MX_records.length ? MX_records : null,
      host
    };
  } catch (e) {
    console.error("DoH error:", e);
    return { service: "DNS (DoH)", error: true, details: e.message };
  }
}

// Checks if URL appears in PhishStats; returns full records if present.
async function checkPhishStats(url) {
  try {//query phishstats for the url
    const q = encodeURIComponent(`(url,eq,${url})`);
    const res = await fetch(`https://api.phishstats.info/api/phishing?_where=${q}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);//if not ok, throw error
    const arr = await res.json();//get json response
    const found = Array.isArray(arr) && arr.length > 0;

    return {
      service: "PhishStats",//service name
      safe: !found,
      disposition: found ? "phishing" : "clean",//disposition based on found or not
      brand: found ? (arr[0].target || "N/A") : "N/A",
      resolved: found,
      // NEW: include full matching records so you can inspect all fields
      records: found ? arr : []
    };
  } catch (e) {
    console.error("PhishStats error:", e);//log error
    return { service: "PhishStats", error: true, details: e.message };
  }
}


//History + Display

function displayCombinedResults(results, scanTime) {//display results in a formatted way
  const resultMessage = document.getElementById("resultMessage");
  const normalized = (results || []).map(r => r ?? { service: "(Unknown)", error: true, details: "No result" });

  // Overall status flags
  const allSafe = normalized.length > 0 && normalized.every(r => !r.error && r.safe === true);
  const anyUnsafe = normalized.some(r => !r.error && r.safe === false);
  const hasErrors = normalized.some(r => r.error);
//calculate confidence level
  const servicesChecked = normalized.filter(r => !r.error).length;
  const servicesReporting = normalized.filter(r => !r.error && r.safe === false).length;

  // Determine confidence level
  let confidenceLevel = "High";
  if (servicesChecked < 2) confidenceLevel = "Low";
  else if (servicesReporting === 1 && servicesChecked >= 2) confidenceLevel = "Medium";
  else if (servicesChecked >= 3 && servicesReporting === 0) confidenceLevel = "Very High";

  // Container that constrains width, wraps words, and keeps text inside the panel
  let html = `
    <div style="
      text-align:left;
      margin-top:15px;
      max-width:900px;
      margin-left:auto;
      margin-right:auto;
      background: rgba(0,0,0,0.35);
      border-radius:12px;
      padding:16px 18px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.25);
      color:#fff;
      overflow:hidden;
      word-break: break-word;
      overflow-wrap: anywhere;
      backdrop-filter: blur(4px);
    ">
  `;

  if (hasErrors && !anyUnsafe) {
    html += `<div style="color:#fff;"><h3 style="margin:0 0 6px 0; color:#FFA500;">⚠️ Partial Results</h3><p style="margin:0 0 10px 0;">Some services couldn't be reached, but no threats detected by others.</p></div>`;
  } else if (anyUnsafe) {
    html += `<div style="color:#fff;"><h3 style="margin:0 0 6px 0; color:#ff3b3b;">⚠️ WARNING: Unsafe URL Detected!</h3><p style="margin:0 0 10px 0;">Do not open this link. One or more services flagged it.</p></div>`;
  } else if (allSafe) {
    html += `<div style="color:#fff;"><h3 style="margin:0 0 6px 0; color:#14c414;">✅ URL Appears Safe</h3><p style="margin:0 0 10px 0;">No threats detected by any service.</p></div>`;
  } else {
    html += `<div style="color:#fff;"><h3 style="margin:0 0 6px 0;">Results</h3></div>`;
  }

  html += `<p style="margin-top:6px; color:#cfd8e3; font-size:.9em;">Scan completed in ${scanTime}s • Confidence: ${confidenceLevel} • Services: ${servicesChecked}/${normalized.length} responded</p>`;
  html += `<hr style="border:none;height:1px;background:rgba(255,255,255,0.12); margin:12px 0;">`;

  normalized.forEach(r => { html += formatService(r); });

  html += `</div>`;
  resultMessage.innerHTML = html;

  // Let the colored headers handle the state; keep container text white.
  resultMessage.style.color = "#fff";
}

/* Renders a concise summary + expandable “Show details” with raw JSON */
function formatService(result, icon = "") {
  if (!result || !result.service) {
    return `
      <div style="margin-bottom:12px;">
        <h4 style="margin:0 0 4px 0; color:#FFA500;">${icon ? icon + " " : ""}(Unknown Service)</h4>
        <div style="color:#ffffff;">Service unavailable</div>
      </div>
    `;
  }

  const isError = !!result.error;
  const isThreat = !isError && result.safe === false;
  const isClean  = !isError && result.safe === true;

  // Header color: red if threat, green if clean, orange if error/unknown
  const headerColor = isThreat ? "#ff3b3b" : (isClean ? "#14c414" : "#FFA500");

  let html = `<div style="margin-bottom:14px;">`;
  html += `<h4 style="margin:0 0 6px 0; color:${headerColor};">${icon ? icon + " " : ""}${result.service}${isClean ? ": ✓ Clean" : (isThreat ? ": ✗ Threat detected" : "")}</h4>`;

  // Sub text is always white
  if (isError) {
    html += `<div style="color:#ffffff;">Service unavailable${result.details ? ` (${result.details})` : ""}</div>`;
  } else {
    const bullets = [];

    // Common fields summarized
    if (Array.isArray(result.threats) && result.threats.length) bullets.push(`Threats: ${result.threats.join(", ")}`);
    if (typeof result.malicious === "number") bullets.push(`VT malicious: ${result.malicious}`);
    if (typeof result.suspicious === "number") bullets.push(`VT suspicious: ${result.suspicious}`);
    if (typeof result.undetected === "number") bullets.push(`VT undetected: ${result.undetected}`);
    if (result.status) bullets.push(`Status: ${result.status}`);
    if (result.analysisId) bullets.push(`VT analysisId: ${result.analysisId}`);
    if (result.brand && result.brand !== "N/A") bullets.push(`Brand: ${result.brand}`);
    if (result.hasA !== undefined || result.hasAAAA !== undefined || result.hasMX !== undefined) {
      bullets.push(`DNS → A:${result.hasA ? "yes" : "no"} AAAA:${result.hasAAAA ? "yes" : "no"} MX:${result.hasMX ? "yes" : "no"}`);
    }
    if (Array.isArray(result.ips) && result.ips.length) bullets.push(`IPs: ${result.ips.join(", ")}`);

    if (bullets.length) {
      html += `<ul style="margin:4px 0 0 18px; padding:0; color:#ffffff;">${bullets.map(b => `<li style="margin:3px 0;">${b}</li>`).join("")}</ul>`;
    }
  }

  html += `</div>`;
  return html;
}