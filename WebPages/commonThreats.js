/*
  Common threats page script

  This file loads and displays the most frequently detected threats from
  the backend. It lets the user filter results by time range, minimum hit
  count, and threat name. When a threat is selected, the script also loads
  extra details such as a summary, prevention advice, removal advice, and
  recent scan history.
*/

const API_BASE = "http://localhost:5001";

const els = {
  days: document.getElementById("days"),
  minCount: document.getElementById("minCount"),
  virusName: document.getElementById("virusName"),
  refreshBtn: document.getElementById("refreshBtn"),
  status: document.getElementById("status"),
  threatList: document.getElementById("threatList"),
  detailsEmpty: document.getElementById("detailsEmpty"),
  details: document.getElementById("details"),
  threatName: document.getElementById("threatName"),
  threatMeta: document.getElementById("threatMeta"),
  threatHits: document.getElementById("threatHits"),
  summary: document.getElementById("summary"),
  avoidList: document.getElementById("avoidList"),
  ridList: document.getElementById("ridList"),
  scanTbody: document.getElementById("scanTbody"),
};

// Stores the most recently loaded threat list
let lastItems = [];

// Builds the query string parameters from the filter controls
function qsParams() {
  const days = Number(els.days.value || 30);
  const minCount = Number(els.minCount.value || 10);
  const virusName = (els.virusName?.value || "").trim();

  const p = new URLSearchParams();
  p.set("days", String(days));
  p.set("min_count", String(minCount));
  p.set("limit", "50");
  if (virusName) p.set("name", virusName);
  return p;
}

// Updates the small status message on the page
function setStatus(msg) {
  els.status.textContent = msg;
}

// Removes all child elements from a container
function clearChildren(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// Formats backend date strings into a readable local date/time
function fmtDate(s) {
  if (!s) return "";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return String(s);
  return d.toLocaleString();
}

// Creates one clickable threat item for the list on the left
function makeListItem(item) {
  const li = document.createElement("li");
  li.className = "listItem";

  const row = document.createElement("div");
  row.className = "liRow";

  const name = document.createElement("div");
  name.className = "liName";
  name.textContent = item.threat_name;

  const badge = document.createElement("div");
  badge.className = "badge";
  badge.textContent = `${item.hits} hits`;

  row.appendChild(name);
  row.appendChild(badge);

  const meta = document.createElement("div");
  meta.className = "liMeta";
  meta.textContent = `Last seen: ${fmtDate(item.last_seen)}`;

  li.appendChild(row);
  li.appendChild(meta);

  // When clicked, load the detailed view for this threat
  li.addEventListener("click", () => selectThreat(item, li));
  return li;
}

// Loads the common threat list from the backend using the current filters
async function loadCommonThreats() {
  els.details.classList.add("hidden");
  els.detailsEmpty.classList.remove("hidden");

  setStatus("Loading…");
  clearChildren(els.threatList);

  const p = qsParams();
  const res = await fetch(`${API_BASE}/api/common-viruses?${p.toString()}`);

  if (!res.ok) {
    setStatus(`Error loading list: ${res.status}`);
    return;
  }

  const data = await res.json();
  lastItems = data.items || [];

  if (!lastItems.length) {
    setStatus("No threats matched that criteria.");
    return;
  }

  setStatus(`Found ${lastItems.length} threats.`);

  for (const item of lastItems) {
    els.threatList.appendChild(makeListItem(item));
  }
}

// Loads and displays the details for one selected threat
async function selectThreat(item, liEl) {
  // Highlight the selected threat in the list
  for (const child of els.threatList.children) child.classList.remove("active");
  liEl.classList.add("active");

  els.detailsEmpty.classList.add("hidden");
  els.details.classList.remove("hidden");

  // Fill the top section with the selected threat's main info
  els.threatName.textContent = item.threat_name;
  els.threatHits.textContent = `${item.hits} hits`;
  els.threatMeta.textContent = `Last seen: ${fmtDate(item.last_seen)}`;

  // Load general information about the selected threat
  const infoRes = await fetch(
    `${API_BASE}/api/virus?name=${encodeURIComponent(item.threat_name)}`
  );
  const info = infoRes.ok ? await infoRes.json() : null;

  els.summary.textContent = info?.summary || "No information available.";

  // Fill the "how to avoid" list
  clearChildren(els.avoidList);
  (info?.how_to_avoid || []).forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t;
    els.avoidList.appendChild(li);
  });

  // Fill the "how to get rid of it" list
  clearChildren(els.ridList);
  (info?.how_to_get_rid || []).forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t;
    els.ridList.appendChild(li);
  });

  // Clear any old scan history rows
  clearChildren(els.scanTbody);

  // Load scan history for this specific threat
  const p = qsParams();
  p.set("name", item.threat_name);
  p.set("limit", "100");

  const scansRes = await fetch(`${API_BASE}/api/virus/scans?${p.toString()}`);

  if (!scansRes.ok) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = `Error loading scans: ${scansRes.status}`;
    tr.appendChild(td);
    els.scanTbody.appendChild(tr);
    return;
  }

  const scansData = await scansRes.json();
  const scans = scansData.items || [];

  if (!scans.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = "No scans found for this threat in the selected time window.";
    tr.appendChild(td);
    els.scanTbody.appendChild(tr);
    return;
  }

  // Add one row per scan record
  for (const s of scans) {
    const tr = document.createElement("tr");

    const tdAt = document.createElement("td");
    tdAt.textContent = fmtDate(s.scanned_at);

    const tdSha = document.createElement("td");
    tdSha.textContent = s.sha256 ?? "";

    const tdSafe = document.createElement("td");
    tdSafe.textContent = String(s.safe);

    tr.appendChild(tdAt);
    tr.appendChild(tdSha);
    tr.appendChild(tdSafe);

    els.scanTbody.appendChild(tr);
  }
}

// Reload the list when the user clicks refresh
els.refreshBtn.addEventListener("click", () => {
  loadCommonThreats().catch((err) => setStatus(`Error: ${err.message}`));
});

// Initial page load
loadCommonThreats().catch((err) => setStatus(`Error: ${err.message}`));