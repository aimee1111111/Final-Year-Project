/*
  File result viewer

  This file creates the viewer used for browsing folder scan results.
  It stores the scan results, matches each result back to its original file
  when possible, and renders one result at a time with Previous and Next
  navigation buttons. It also supports left and right arrow key navigation.
*/

import { filenameFromResult } from "./file-utils.js";
import { buildDetailsRichHtml } from "./file-render.js";

export function createFileViewer(detailsDiv) {
  // Stores the scan results currently loaded into the viewer
  let viewerResults = [];

  // Tracks which result is currently being shown
  let viewerIndex = 0;

  // Maps filenames to original File objects
  let viewerFileMap = new Map();

  // Loads a new set of results into the viewer and resets to the first item
  function setResults(results, fileMap) {
    viewerResults = results || [];
    viewerIndex = 0;
    viewerFileMap = fileMap || new Map();
  }

  // Clears all viewer state and hides the details panel
  function clear() {
    viewerResults = [];
    viewerIndex = 0;
    viewerFileMap = new Map();
    detailsDiv.style.display = "none";
    detailsDiv.innerHTML = "";
  }

  // Tries to find the original File object that matches a scan result
  // This helps show proper file information in the details view
  function findMatchingFileForResult(r) {
    const key1 = filenameFromResult(r, "");

    if (key1 && viewerFileMap.has(key1)) return viewerFileMap.get(key1);

    if (key1) {
      const base = key1.split("/").pop();
      if (viewerFileMap.has(base)) return viewerFileMap.get(base);
    }

    if (key1) {
      const base = key1.split("/").pop();
      for (const [k, f] of viewerFileMap.entries()) {
        if (k.split("/").pop() === base) return f;
      }
    }

    return null;
  }

  // Renders the currently selected result into the details panel
  function render() {
    if (!viewerResults.length) {
      detailsDiv.style.display = "none";
      detailsDiv.innerHTML = "";
      return;
    }

    const r = viewerResults[viewerIndex];
    const name = filenameFromResult(r, `File ${viewerIndex + 1}`);
    const fileObj = findMatchingFileForResult(r);

    detailsDiv.style.display = "block";
    detailsDiv.innerHTML = `
      <div class="panel" style="margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
          <div class="muted">${name} (${viewerIndex + 1} / ${viewerResults.length})</div>
          <div style="display:flex; gap:8px;">
            <button type="button" id="prevResultBtn" class="btn btn-ghost" ${viewerIndex === 0 ? "disabled" : ""}>Prev</button>
            <button type="button" id="nextResultBtn" class="btn btn-ghost" ${viewerIndex === viewerResults.length - 1 ? "disabled" : ""}>Next</button>
          </div>
        </div>
      </div>
      ${buildDetailsRichHtml(r, fileObj || name)}
    `;

    const prevBtn = detailsDiv.querySelector("#prevResultBtn");
    const nextBtn = detailsDiv.querySelector("#nextResultBtn");

    // Move to the previous result
    if (prevBtn) {
      prevBtn.addEventListener("click", () => {
        if (viewerIndex > 0) {
          viewerIndex--;
          render();
        }
      });
    }

    // Move to the next result
    if (nextBtn) {
      nextBtn.addEventListener("click", () => {
        if (viewerIndex < viewerResults.length - 1) {
          viewerIndex++;
          render();
        }
      });
    }

    // Allow left and right arrow keys to navigate results
    detailsDiv.tabIndex = 0;
    detailsDiv.onkeydown = (e) => {
      if (e.key === "ArrowLeft" && viewerIndex > 0) {
        viewerIndex--;
        render();
      } else if (e.key === "ArrowRight" && viewerIndex < viewerResults.length - 1) {
        viewerIndex++;
        render();
      }
    };
  }

  return {
    setResults,
    clear,
    render
  };
}