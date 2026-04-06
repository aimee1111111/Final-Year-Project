/*
  This utility file contains helper values and functions used by the file
  scanning system. It defines file size limits, formats file sizes into a
  readable form, safely escapes HTML, and extracts scan information from
  backend responses.

  It also helps standardise different response formats by pulling out
  threat names, scan engine results, file names, folder results, and
  engine-specific details in a consistent way.
*/

export const MAX_FILE_BYTES = 10 * 1024 * 1024;   // Maximum size allowed for one file (10 MB)
export const MAX_TOTAL_BYTES = 50 * 1024 * 1024;  // Maximum total upload size allowed (50 MB)

export function bytesToHuman(n) {
  // Returns an empty string if the value is not a valid number
  if (!Number.isFinite(n)) return "";

  // Units used to display file sizes
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;

  // Keeps dividing by 1024 until the size fits the correct unit
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }

  // Formats the number and adds the correct unit
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function escapeHtml(s) {
  // Converts special HTML characters into safe escaped versions
  // to help prevent broken HTML or injection issues
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[c]));
}

export function pickThreatList(obj) {
  // Returns an empty list if no object was provided
  if (!obj) return [];

  // Handles different possible backend response names for threats
  if (Array.isArray(obj.threats)) return obj.threats;
  if (Array.isArray(obj.detections)) return obj.detections;
  if (Array.isArray(obj.threat_list)) return obj.threat_list;

  // If there is only one threat value, return it as an array
  if (obj.threat) return [obj.threat];
  if (obj.signature) return [obj.signature];
  if (obj.rule) return [obj.rule];
  if (obj.yara_rule) return [obj.yara_rule];

  // If matches exist, extract the most useful readable field from each one
  if (Array.isArray(obj.matches)) {
    return obj.matches.map((m) => m.rule || m.name || m.identifier || m.signature || JSON.stringify(m));
  }

  // Recursively check nested result or data objects
  if (obj.result) return pickThreatList(obj.result);
  if (obj.data) return pickThreatList(obj.data);

  // Default fallback if no threats are found
  return [];
}

export function pickScanResults(obj) {
  // Returns an empty list if nothing was provided
  if (!obj) return [];

  // Checks common places where scan results may appear
  if (Array.isArray(obj.scan_results)) return obj.scan_results;

  // Handles a generic "results" array if it looks like engine scan data
  if (
    Array.isArray(obj.results) &&
    obj.results.length &&
    typeof obj.results[0] === "object" &&
    ("engine" in obj.results[0] || "status" in obj.results[0])
  ) {
    return obj.results;
  }

  // Checks nested response structures
  if (obj.result && Array.isArray(obj.result.scan_results)) return obj.result.scan_results;
  if (obj.data && Array.isArray(obj.data.scan_results)) return obj.data.scan_results;

  // Default fallback
  return [];
}

export function safeFlag(r) {
  // If the backend directly provides a boolean safe value, use it
  if (typeof r?.safe === "boolean") return r.safe;
  if (typeof r?.is_safe === "boolean") return r.is_safe;

  // If threats were found, treat the file as unsafe
  const t = pickThreatList(r);
  if (t.length) return false;

  // Default fallback is false
  return false;
}

export function filenameFromResult(r, fallback = "") {
  // Returns the first available filename-related field
  return r?.filename ?? r?.file ?? r?.name ?? r?.path ?? fallback;
}

export function extractFolderResults(payload) {
  // Handles different backend response formats for folder scan results
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload.results)) return payload.results;
  if (payload && Array.isArray(payload.files)) return payload.files;
  if (payload && Array.isArray(payload.data)) return payload.data;
  if (payload && payload.result && Array.isArray(payload.result)) return payload.result;

  // Returns null if folder results cannot be found
  return null;
}

export function formatEngineDetail(engineName, detailObjOrString) {
  // Returns an empty string if there is no detail to show
  if (!detailObjOrString) return "";

  // Special formatting for hash reputation results
  if (engineName === "HashReputation" && typeof detailObjOrString === "object") {
    const p = detailObjOrString.provider || "API";
    const v = detailObjOrString.verdict || "unknown";
    const m = detailObjOrString.malicious ?? 0;
    const s = detailObjOrString.suspicious ?? 0;
    const h = detailObjOrString.harmless ?? 0;
    const u = detailObjOrString.undetected ?? 0;

    // If the reputation check returned an error, show that instead
    if (detailObjOrString.error) return `${p}: error: ${detailObjOrString.error}`;

    // Returns a readable summary of the reputation scan
    return `${p}: verdict=${v}; malicious=${m}; suspicious=${s}; harmless=${h}; undetected=${u}`;
  }

  // If detail is already a string, return it directly
  if (typeof detailObjOrString === "string") return detailObjOrString;

  // If detail is an array, convert each item into a readable label
  if (Array.isArray(detailObjOrString)) {
    return detailObjOrString.map((d) => d.rule || d.name || JSON.stringify(d)).join("; ");
  }

  // If detail is an object, convert it to JSON text
  if (typeof detailObjOrString === "object") return JSON.stringify(detailObjOrString);

  // Final fallback for other types
  return String(detailObjOrString);
}