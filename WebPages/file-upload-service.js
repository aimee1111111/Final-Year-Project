import {
  MAX_FILE_BYTES,
  MAX_TOTAL_BYTES,
  extractFolderResults,
  escapeHtml
} from "./file-utils.js";

export async function uploadCurrentFiles(currentFiles, currentMode) {
  if (!currentMode) {
    alert("Choose files or a folder first.");
    return { error: "No mode selected" };
  }

  if (!currentFiles.length) {
    alert(currentMode === "folder" ? "Please choose a folder." : "Please choose file(s).");
    return { error: "No files selected" };
  }

  const userId = window.localStorage?.getItem("user_id");
  if (!userId) {
    alert("You must be logged in to scan files.");
    return { error: "Missing user_id" };
  }

  let total = 0;
  let skippedCount = 0;
  let skippedBytes = 0;
  const selected = [];

  for (const f of currentFiles) {
    const size = f.size || 0;
    if (size > MAX_FILE_BYTES) {
      skippedCount++;
      skippedBytes += size;
      continue;
    }
    if (total + size > MAX_TOTAL_BYTES) {
      skippedCount++;
      skippedBytes += size;
      continue;
    }
    selected.push(f);
    total += size;
  }

  if (!selected.length) {
    alert("All selected files were skipped due to size limits.");
    return { error: "All files skipped" };
  }

  const formData = new FormData();
  const viewerFileMap = new Map();

  for (const file of selected) {
    const uploadName =
      file.webkitRelativePath && file.webkitRelativePath.length
        ? file.webkitRelativePath
        : file.name;

    formData.append("file", file, uploadName);
    viewerFileMap.set(uploadName, file);
    viewerFileMap.set(file.name, file);
  }

  formData.append("user_id", userId);
  formData.append("mode", currentMode);

  const response = await fetch("http://localhost:5001/upload", {
    method: "POST",
    body: formData
  });

  const ct = response.headers.get("content-type") || "";
  if (!ct.includes("application/json")) {
    const text = await response.text();
    throw new Error("Server returned non-JSON: " + text.slice(0, 200));
  }

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.message || payload.error || "Upload failed");
  }

  return {
    payload,
    folderResults: extractFolderResults(payload),
    selected,
    skippedCount,
    skippedBytes,
    viewerFileMap
  };
}

export function renderUploadError(resultDiv, detailsDiv, message) {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<span class="bad">Upload failed:</span> ${escapeHtml(message)}`;
  detailsDiv.style.display = "none";
  detailsDiv.innerHTML = "";
}