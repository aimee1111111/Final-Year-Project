import { bytesToHuman } from "./file-utils.js";
import { resetUI, renderHeaderSingle, renderFolderHeader, buildDetailsRichHtml } from "./file-render.js";
import { createFileViewer } from "./file-viewer.js";
import { uploadCurrentFiles, renderUploadError } from "./file-upload-service.js";

(() => {
  const form = document.getElementById("uploadForm");
  const fileInput = document.getElementById("fileInput");
  const folderInput = document.getElementById("folderInput");
  const dropzone = document.getElementById("dropzone");
  const resultDiv = document.getElementById("result");
  const detailsDiv = document.getElementById("details");
  const fileNameEl = document.getElementById("fileName");
  const clearBtn = document.getElementById("clearBtn");
  const chooseFilesBtn = document.getElementById("chooseFilesBtn");
  const chooseFolderBtn = document.getElementById("chooseFolderBtn");

  let currentFiles = [];
  let currentMode = null;

  const viewer = createFileViewer(detailsDiv);

  function setFiles(files, mode) {
    currentMode = mode;
    currentFiles = Array.from(files || []);

    if (!currentFiles.length) {
      fileNameEl.textContent = "";
      return;
    }

    const totalSize = currentFiles.reduce((sum, f) => sum + (f.size || 0), 0);
    const label = mode === "folder" ? "Folder selected" : "Files selected";

    fileNameEl.textContent =
      `${label}: ${currentFiles.length} file${currentFiles.length > 1 ? "s" : ""} (${bytesToHuman(totalSize)} total)`;
  }

  function clearAll() {
    fileInput.value = "";
    folderInput.value = "";
    currentFiles = [];
    currentMode = null;
    fileNameEl.textContent = "";
    viewer.clear();
    resetUI(resultDiv, detailsDiv);
  }

  chooseFilesBtn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    folderInput.value = "";
    currentFiles = [];
    currentMode = "files";
    fileInput.click();
  });

  chooseFolderBtn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    fileInput.value = "";
    currentFiles = [];
    currentMode = "folder";
    folderInput.click();
  });

  fileInput.addEventListener("change", () => {
    folderInput.value = "";
    if (fileInput.files && fileInput.files.length) setFiles(fileInput.files, "files");
    else clearAll();
  });

  folderInput.addEventListener("change", () => {
    fileInput.value = "";
    if (folderInput.files && folderInput.files.length) setFiles(folderInput.files, "folder");
    else clearAll();
  });

  dropzone.addEventListener("click", (e) => {
    if (e.target.closest("button")) return;
    folderInput.value = "";
    currentMode = "files";
    fileInput.click();
  });

  dropzone.addEventListener("keydown", (e) => {
    if (e.target.closest("button")) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      folderInput.value = "";
      currentMode = "files";
      fileInput.click();
    }
  });

  ["dragenter", "dragover"].forEach((evtName) => {
    dropzone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((evtName) => {
    dropzone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (!files || !files.length) return;
    folderInput.value = "";
    setFiles(files, "files");
  });

  async function handleUpload() {
    resultDiv.style.display = "block";
    resultDiv.textContent = `Scanning ${currentFiles.length} file${currentFiles.length > 1 ? "s" : ""}...`;
    detailsDiv.style.display = "none";
    detailsDiv.innerHTML = "";

    try {
      const {
        payload,
        folderResults,
        selected,
        skippedCount,
        skippedBytes,
        viewerFileMap
      } = await uploadCurrentFiles(currentFiles, currentMode);

      if (folderResults && Array.isArray(folderResults)) {
        viewer.setResults(folderResults, viewerFileMap);
        renderFolderHeader(resultDiv, folderResults, skippedCount, skippedBytes);
        viewer.render();
        return;
      }

      renderHeaderSingle(resultDiv, payload);
      detailsDiv.style.display = "block";
      detailsDiv.innerHTML = buildDetailsRichHtml(payload, selected[0] || null);
    } catch (err) {
      renderUploadError(resultDiv, detailsDiv, err.message);
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await handleUpload();
  });

  clearBtn.addEventListener("click", clearAll);
})();