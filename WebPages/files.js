(() => {
  const form = document.getElementById('uploadForm');
  const fileInput = document.getElementById('fileInput');
  const folderInput = document.getElementById('folderInput');
  const dropzone = document.getElementById('dropzone');
  const resultDiv = document.getElementById('result');
  const detailsDiv = document.getElementById('details');
  const fileNameEl = document.getElementById('fileName');
  const clearBtn = document.getElementById('clearBtn');
  const chooseFilesBtn = document.getElementById('chooseFilesBtn');
  const chooseFolderBtn = document.getElementById('chooseFolderBtn');

  // limits (change these)
  const MAX_FILE_BYTES = 10 * 1024 * 1024;      // 10 MB per file
  const MAX_TOTAL_BYTES = 50 * 1024 * 1024;     // 50 MB total per upload

  let currentFiles = [];
  let currentMode = null; // 'files' | 'folder' | null

  // viewer state for folder results
  let viewerResults = [];
  let viewerIndex = 0;
  let viewerFileMap = new Map(); // uploadName -> File

  function bytesToHuman(n) {
    if (!Number.isFinite(n)) return '';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c]));
  }

  function resetUI() {
    resultDiv.style.display = 'none';
    resultDiv.textContent = '';
    detailsDiv.style.display = 'none';
    detailsDiv.innerHTML = '';
  }

  function setFiles(files, mode) {
    currentMode = mode;
    currentFiles = Array.from(files || []);

    if (!currentFiles.length) {
      fileNameEl.textContent = '';
      return;
    }

    const totalSize = currentFiles.reduce((sum, f) => sum + (f.size || 0), 0);
    const label = mode === 'folder' ? 'Folder selected' : 'Files selected';
    fileNameEl.textContent =
      `${label}: ${currentFiles.length} file${currentFiles.length > 1 ? 's' : ''} (${bytesToHuman(totalSize)} total)`;
  }

  function clearAll() {
    fileInput.value = '';
    folderInput.value = '';
    currentFiles = [];
    currentMode = null;
    fileNameEl.textContent = '';
    viewerResults = [];
    viewerIndex = 0;
    viewerFileMap = new Map();
    resetUI();
  }

  // --------- selection UX ----------
  chooseFilesBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation(); // stop bubbling to dropzone click
    folderInput.value = '';
    currentFiles = [];
    currentMode = 'files';
    fileInput.click();
  });

  chooseFolderBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation(); // stop bubbling to dropzone click
    fileInput.value = '';
    currentFiles = [];
    currentMode = 'folder';
    folderInput.click();
  });

  fileInput.addEventListener('change', () => {
    folderInput.value = '';
    if (fileInput.files && fileInput.files.length) setFiles(fileInput.files, 'files');
    else clearAll();
  });

  folderInput.addEventListener('change', () => {
    fileInput.value = '';
    if (folderInput.files && folderInput.files.length) setFiles(folderInput.files, 'folder');
    else clearAll();
  });

  // Dropzone = files only
  dropzone.addEventListener('click', (e) => {
    // if user clicked a button (Choose Files/Folder/Clear), do nothing here
    if (e.target.closest('button')) return;

    folderInput.value = '';
    currentMode = 'files';
    fileInput.click();
  });

  dropzone.addEventListener('keydown', (e) => {
    // only trigger when the dropzone itself is focused, not a button inside it
    if (e.target.closest('button')) return;

    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      folderInput.value = '';
      currentMode = 'files';
      fileInput.click();
    }
  });

  ['dragenter', 'dragover'].forEach(evtName => {
    dropzone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(evtName => {
    dropzone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (!files || !files.length) return;
    folderInput.value = '';
    setFiles(files, 'files');
  });

  // --------- result parsing helpers ----------
  function pickThreatList(obj) {
    if (!obj) return [];
    if (Array.isArray(obj.threats)) return obj.threats;
    if (Array.isArray(obj.detections)) return obj.detections;
    if (Array.isArray(obj.threat_list)) return obj.threat_list;

    if (obj.threat) return [obj.threat];
    if (obj.signature) return [obj.signature];
    if (obj.rule) return [obj.rule];
    if (obj.yara_rule) return [obj.yara_rule];

    if (Array.isArray(obj.matches)) {
      return obj.matches.map(m =>
        m.rule || m.name || m.identifier || m.signature || JSON.stringify(m)
      );
    }

    if (obj.result) return pickThreatList(obj.result);
    if (obj.data) return pickThreatList(obj.data);
    return [];
  }

  function pickScanResults(obj) {
    if (!obj) return [];
    if (Array.isArray(obj.scan_results)) return obj.scan_results;

    if (
      Array.isArray(obj.results) &&
      obj.results.length &&
      typeof obj.results[0] === 'object' &&
      ('engine' in obj.results[0] || 'status' in obj.results[0])
    ) {
      return obj.results;
    }
    if (obj.result && Array.isArray(obj.result.scan_results)) return obj.result.scan_results;
    if (obj.data && Array.isArray(obj.data.scan_results)) return obj.data.scan_results;
    return [];
  }

  function safeFlag(r) {
    if (typeof r?.safe === 'boolean') return r.safe;
    if (typeof r?.is_safe === 'boolean') return r.is_safe;

    // If threats exist -> not safe
    const t = pickThreatList(r);
    if (t.length) return false;

    // Unknown -> treat as not safe (your original behavior)
    return false;
  }

  function filenameFromResult(r, fallback = '') {
    return r?.filename ?? r?.file ?? r?.name ?? r?.path ?? fallback;
  }

  function extractFolderResults(payload) {
    if (Array.isArray(payload)) return payload;
    if (payload && Array.isArray(payload.results)) return payload.results;
    if (payload && Array.isArray(payload.files)) return payload.files;
    if (payload && Array.isArray(payload.data)) return payload.data;
    if (payload && payload.result && Array.isArray(payload.result)) return payload.result;
    return null;
  }

  // --------- UI rendering ----------
  function renderHeaderSingle(resultObj) {
    const safe = safeFlag(resultObj);
    const msg = resultObj?.message;

    let text, cls;
    if (safe) {
      text = `✓ ${msg || 'File is clean'}`;
      cls = 'ok';
    } else {
      const threats = pickThreatList(resultObj);
      const items = threats.length ? threats.join(', ') : 'Unknown';
      text = `✗ ${msg || 'Threats detected'} — ${items}`;
      cls = 'bad';
    }

    resultDiv.style.display = 'block';
    resultDiv.innerHTML = `<div class="${cls}">${escapeHtml(text)}</div>`;
  }

  function renderFolderHeader(results, skippedCount = 0, skippedBytes = 0) {
    const totalFiles = results.length;
    const cleanFiles = results.filter(r => safeFlag(r) === true && !r.error).length;
    const threatsFound = results.filter(r => safeFlag(r) === false && !r.error).length;
    const errors = results.filter(r => !!r.error).length;

    let text, cls;
    if (threatsFound > 0) {
      text = `✗ Threats detected in ${threatsFound} of ${totalFiles} files`;
      cls = 'bad';
    } else if (errors > 0) {
      text = `⚠ Scan completed with ${errors} error(s) in ${totalFiles} files`;
      cls = 'bad';
    } else {
      text = `✓ All ${totalFiles} files are clean`;
      cls = 'ok';
    }

    const skippedLine = skippedCount > 0
      ? `<div class="muted" style="margin-top:6px;">Skipped: ${skippedCount} file(s) (${escapeHtml(bytesToHuman(skippedBytes))}) due to size limits</div>`
      : '';

    resultDiv.style.display = 'block';
    resultDiv.innerHTML = `
      <div class="${cls}">${escapeHtml(text)}</div>
      <div class="muted" style="margin-top: 8px;">
        Clean: ${cleanFiles} | Threats: ${threatsFound} | Errors: ${errors}
      </div>
      ${skippedLine}
    `;
  }

  function buildDetailsRichHtml(resultObj, fileObjOrName) {
    const when = new Date().toLocaleString();
    const safe = safeFlag(resultObj);
    const verdict = safe ? 'Clean' : 'Threats detected';
    const verdictClass = safe ? 'ok' : 'bad';

    let fname = '(unknown)';
    let fsize = '';
    let ftype = '—';

    if (fileObjOrName && typeof fileObjOrName === 'object') {
      fname = fileObjOrName.name || fname;
      fsize = fileObjOrName.size ? bytesToHuman(fileObjOrName.size) : '';
      ftype = fileObjOrName.type || '—';
    } else if (typeof fileObjOrName === 'string') {
      fname = fileObjOrName;
    } else {
      fname = filenameFromResult(resultObj, fname);
    }

    const threats = pickThreatList(resultObj);
    const threatList = threats.length
      ? `<ul>${threats.map(t => `<li>${escapeHtml(t)}</li>`).join('')}</ul>`
      : `<div class="muted">No threats listed.</div>`;

    const engines = pickScanResults(resultObj);
    const enginesHTML = engines.map(r => {
      const eng = r.engine || r.name || 'Engine';
      const status = r.status || r.result || 'unknown';

      let detail = '';
      if (r.details) {
        if (typeof r.details === 'string') {
          detail = r.details;
        } else if (Array.isArray(r.details)) {
          const rules = r.details.map(d => d.rule || d.name || JSON.stringify(d)).join('; ');
          detail = rules;
        } else if (typeof r.details === 'object') {
          detail = JSON.stringify(r.details);
        }
      } else if (r.error) {
        detail = `error: ${r.error}`;
      } else if (r.message) {
        detail = r.message;
      }

      let chips = '';
      if (Array.isArray(r.details)) {
        const allTags = r.details.flatMap(d => Array.isArray(d.tags) ? d.tags : []);
        if (allTags.length) {
          const uniq = [...new Set(allTags)];
          chips = `<div class="muted">Tags: ${uniq.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join(' ')}</div>`;
        }
      }

      return `
        <div class="engine">
          <div class="field"><label>Engine</label><div>${escapeHtml(eng)}</div></div>
          <div class="field"><label>Status</label><div>${escapeHtml(status)}</div></div>
          ${detail ? `<div class="field"><label>Details</label><div>${escapeHtml(detail)}</div></div>` : ''}
          ${chips}
        </div>
      `;
    }).join('');

    return `
      <form class="kv">
        <label>Filename</label><input type="text" value="${escapeHtml(fname)}" readonly />
        <label>Size</label><input type="text" value="${escapeHtml(fsize)}" readonly />
        <label>Type</label><input type="text" value="${escapeHtml(ftype)}" readonly />
        <label>Scanned</label><input type="text" value="${escapeHtml(when)}" readonly />
        <label>Verdict</label><input class="${verdictClass}" type="text" value="${escapeHtml(verdict)}" readonly />
        <div style="grid-column:1/-1; margin-top:8px;">
          <h3 style="margin:10px 0 4px;">Per-engine results</h3>
          ${enginesHTML || '<div class="muted">No engine data.</div>'}
        </div>
        <div style="grid-column:1/-1; margin-top:8px;">
          <h3 style="margin:10px 0 4px;">Threats</h3>
          <div class="threats">${threatList}</div>
        </div>
      </form>
    `;
  }

  function findMatchingFileForResult(r) {
    const key1 = filenameFromResult(r, '');
    if (key1 && viewerFileMap.has(key1)) return viewerFileMap.get(key1);

    if (key1) {
      const base = key1.split('/').pop();
      if (viewerFileMap.has(base)) return viewerFileMap.get(base);
    }

    if (key1) {
      const base = key1.split('/').pop();
      for (const [k, f] of viewerFileMap.entries()) {
        if (k.split('/').pop() === base) return f;
      }
    }

    return null;
  }

  function renderFolderViewer() {
    if (!viewerResults.length) {
      detailsDiv.style.display = 'none';
      detailsDiv.innerHTML = '';
      return;
    }

    const r = viewerResults[viewerIndex];
    const name = filenameFromResult(r, `File ${viewerIndex + 1}`);
    const fileObj = findMatchingFileForResult(r);

    detailsDiv.style.display = 'block';
    detailsDiv.innerHTML = `
      <div class="panel" style="margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
          <div class="muted">${escapeHtml(name)} (${viewerIndex + 1} / ${viewerResults.length})</div>
          <div style="display:flex; gap:8px;">
            <button type="button" id="prevResultBtn" class="btn btn-ghost" ${viewerIndex === 0 ? 'disabled' : ''}>Prev</button>
            <button type="button" id="nextResultBtn" class="btn btn-ghost" ${viewerIndex === viewerResults.length - 1 ? 'disabled' : ''}>Next</button>
          </div>
        </div>
      </div>

      ${buildDetailsRichHtml(r, fileObj || name)}
    `;

    const prevBtn = detailsDiv.querySelector('#prevResultBtn');
    const nextBtn = detailsDiv.querySelector('#nextResultBtn');

    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        if (viewerIndex > 0) {
          viewerIndex--;
          renderFolderViewer();
        }
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        if (viewerIndex < viewerResults.length - 1) {
          viewerIndex++;
          renderFolderViewer();
        }
      });
    }

    detailsDiv.tabIndex = 0;
    detailsDiv.onkeydown = (e) => {
      if (e.key === 'ArrowLeft' && viewerIndex > 0) {
        viewerIndex--;
        renderFolderViewer();
      } else if (e.key === 'ArrowRight' && viewerIndex < viewerResults.length - 1) {
        viewerIndex++;
        renderFolderViewer();
      }
    };
  }

  // --------- upload ----------
  async function uploadCurrentFiles() {
    if (!currentMode) {
      alert('Choose files or a folder first.');
      return;
    }
    if (!currentFiles.length) {
      alert(currentMode === 'folder' ? 'Please choose a folder.' : 'Please choose file(s).');
      return;
    }

    const userId = window.localStorage?.getItem('user_id');
    if (!userId) {
      alert('You must be logged in to scan files.');
      return;
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
      alert('All selected files were skipped due to size limits. Increase MAX_FILE_BYTES / MAX_TOTAL_BYTES in files.js.');
      return;
    }

    const formData = new FormData();
    viewerFileMap = new Map();

    for (const file of selected) {
      const uploadName = file.webkitRelativePath && file.webkitRelativePath.length
        ? file.webkitRelativePath
        : file.name;

      formData.append('file', file, uploadName);
      viewerFileMap.set(uploadName, file);
      viewerFileMap.set(file.name, file);
    }

    formData.append('user_id', userId);
    formData.append('mode', currentMode);

    resultDiv.style.display = 'block';
    resultDiv.textContent = `Scanning ${selected.length} file${selected.length > 1 ? 's' : ''}...`;
    detailsDiv.style.display = 'none';
    detailsDiv.innerHTML = '';

    try {
      const response = await fetch('http://localhost:5000/upload', {
        method: 'POST',
        body: formData
      });

      const ct = response.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await response.text();
        throw new Error('Server returned non-JSON: ' + text.slice(0, 200));
      }

      const payload = await response.json();
      console.log('Scan result payload:', payload);

      if (!response.ok) {
        throw new Error(payload.message || payload.error || 'Upload failed');
      }

      const folderResults = extractFolderResults(payload);

      if (folderResults && Array.isArray(folderResults)) {
        viewerResults = folderResults;
        viewerIndex = 0;

        renderFolderHeader(folderResults, skippedCount, skippedBytes);
        renderFolderViewer();
        return;
      }

      renderHeaderSingle(payload);
      detailsDiv.style.display = 'block';
      detailsDiv.innerHTML = buildDetailsRichHtml(payload, selected[0] || null);
    } catch (err) {
      resultDiv.style.display = 'block';
      resultDiv.innerHTML = `<span class="bad">Upload failed:</span> ${escapeHtml(err.message)}`;
      detailsDiv.style.display = 'none';
      detailsDiv.innerHTML = '';
    }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await uploadCurrentFiles();
  });

  clearBtn.addEventListener('click', clearAll);
})();
