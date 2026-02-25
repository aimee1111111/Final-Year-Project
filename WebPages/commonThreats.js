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

let lastItems = [];

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

function setStatus(msg) {
  els.status.textContent = msg;
}

function clearChildren(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function fmtDate(s) {
  if (!s) return "";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return String(s);
  return d.toLocaleString();
}

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

  li.addEventListener("click", () => selectThreat(item, li));
  return li;
}

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

async function selectThreat(item, liEl) {
  for (const child of els.threatList.children) child.classList.remove("active");
  liEl.classList.add("active");

  els.detailsEmpty.classList.add("hidden");
  els.details.classList.remove("hidden");

  els.threatName.textContent = item.threat_name;
  els.threatHits.textContent = `${item.hits} hits`;
  els.threatMeta.textContent = `Last seen: ${fmtDate(item.last_seen)}`;

  const infoRes = await fetch(
    `${API_BASE}/api/virus?name=${encodeURIComponent(item.threat_name)}`
  );
  const info = infoRes.ok ? await infoRes.json() : null;

  els.summary.textContent = info?.summary || "No information available.";

  clearChildren(els.avoidList);
  (info?.how_to_avoid || []).forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t;
    els.avoidList.appendChild(li);
  });

  clearChildren(els.ridList);
  (info?.how_to_get_rid || []).forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t;
    els.ridList.appendChild(li);
  });

  clearChildren(els.scanTbody);

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

  for (const s of scans) {
    const tr = document.createElement("tr");

    const tdAt = document.createElement("td");
    tdAt.textContent = fmtDate(s.scanned_at);

    const tdSha = document.createElement("td");
    tdSha.textContent = s.sha256 ?? "";

    const tdSafe = document.createElement("td");
    tdSafe.textContent = String(s.safe);

    const tdMime = document.createElement("td");
    tdMime.textContent = s.mime_type ?? "";

    tr.appendChild(tdAt);
    tr.appendChild(tdSha);
    tr.appendChild(tdSafe);
    tr.appendChild(tdMime);

    els.scanTbody.appendChild(tr);
  }
}

els.refreshBtn.addEventListener("click", () => {
  loadCommonThreats().catch((err) => setStatus(`Error: ${err.message}`));
});

loadCommonThreats().catch((err) => setStatus(`Error: ${err.message}`));