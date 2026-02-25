(() => {
  // Element references
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

  const MAX_FILE_BYTES = 10 * 1024 * 1024;
  const MAX_TOTAL_BYTES = 50 * 1024 * 1024;

  let currentFiles = [];
  let currentMode = null;
  let viewerResults = [];
  let viewerIndex = 0;
  let viewerFileMap = new Map();

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
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
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
    fileNameEl.textContent = `${label}: ${currentFiles.length} file${currentFiles.length > 1 ? 's' : ''} (${bytesToHuman(totalSize)} total)`;
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

  chooseFilesBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    folderInput.value = '';
    currentFiles = [];
    currentMode = 'files';
    fileInput.click();
  });

  chooseFolderBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
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

  dropzone.addEventListener('click', (e) => {
    if (e.target.closest('button')) return;
    folderInput.value = '';
    currentMode = 'files';
    fileInput.click();
  });

  dropzone.addEventListener('keydown', (e) => {
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
      return obj.matches.map(m => m.rule || m.name || m.identifier || m.signature || JSON.stringify(m));
    }
    if (obj.result) return pickThreatList(obj.result);
    if (obj.data) return pickThreatList(obj.data);
    return [];
  }

  function pickScanResults(obj) {
    if (!obj) return [];
    if (Array.isArray(obj.scan_results)) return obj.scan_results;
    if (Array.isArray(obj.results) && obj.results.length && typeof obj.results[0] === 'object' && ('engine' in obj.results[0] || 'status' in obj.results[0])) {
      return obj.results;
    }
    if (obj.result && Array.isArray(obj.result.scan_results)) return obj.result.scan_results;
    if (obj.data && Array.isArray(obj.data.scan_results)) return obj.data.scan_results;
    return [];
  }

  function safeFlag(r) {
    if (typeof r?.safe === 'boolean') return r.safe;
    if (typeof r?.is_safe === 'boolean') return r.is_safe;
    const t = pickThreatList(r);
    if (t.length) return false;
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
      <div class="muted" style="margin-top: 20px;">Clean: ${cleanFiles} | Threats: ${threatsFound} | Errors: ${errors}</div>
      ${skippedLine}
    `;
  }

  function formatEngineDetail(engineName, detailObjOrString) {
    if (!detailObjOrString) return '';
    if (engineName === 'HashReputation' && typeof detailObjOrString === 'object') {
      const p = detailObjOrString.provider || 'API';
      const v = detailObjOrString.verdict || 'unknown';
      const m = detailObjOrString.malicious ?? 0;
      const s = detailObjOrString.suspicious ?? 0;
      const h = detailObjOrString.harmless ?? 0;
      const u = detailObjOrString.undetected ?? 0;
      if (detailObjOrString.error) return `${p}: error: ${detailObjOrString.error}`;
      return `${p}: verdict=${v}; malicious=${m}; suspicious=${s}; harmless=${h}; undetected=${u}`;
    }
    if (typeof detailObjOrString === 'string') return detailObjOrString;
    if (Array.isArray(detailObjOrString)) {
      return detailObjOrString.map(d => d.rule || d.name || JSON.stringify(d)).join('; ');
    }
    if (typeof detailObjOrString === 'object') return JSON.stringify(detailObjOrString);
    return String(detailObjOrString);
  }

  function buildDetailsRichHtml(resultObj, fileObjOrName) {
    const when = new Date().toLocaleString();
    const safe = safeFlag(resultObj);
    const verdict = safe ? 'Clean' : 'Threats detected';
    const verdictClass = safe ? 'ok' : 'bad';

    let fname = '(unknown)', fsize = '', ftype = '—';
    if (fileObjOrName && typeof fileObjOrName === 'object') {
      fname = fileObjOrName.name || fname;
      fsize = fileObjOrName.size ? bytesToHuman(fileObjOrName.size) : '';
      ftype = fileObjOrName.type || '—';
    } else if (typeof fileObjOrName === 'string') {
      fname = fileObjOrName;
    } else {
      fname = filenameFromResult(resultObj, fname);
    }

    const sha256 = resultObj?.sha256 || '';
    const threats = pickThreatList(resultObj);
    const engines = pickScanResults(resultObj);
    const totalEngines = engines.length;
    const cleanEngines = engines.filter(r => {
      const status = (r.status || r.result || '').toLowerCase();
      return status === 'clean' || status === 'ok' || status === 'safe';
    }).length;
    const threatEngines = engines.filter(r => {
      const status = (r.status || r.result || '').toLowerCase();
      return status === 'threat_detected' || status === 'malicious' || status === 'infected';
    }).length;

    const userFriendlyView = `
      <div class="scan-result-card ${safe ? 'result-safe' : 'result-danger'}">
        <div class="result-header">
          <div class="result-icon">
            ${safe ? 
              '<svg width="60" height="60" viewBox="0 0 60 60"><circle cx="30" cy="30" r="28" fill="#10b981" opacity="0.2"/><path d="M20 30 L27 37 L40 23" stroke="#10b981" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>' : 
              '<svg width="60" height="60" viewBox="0 0 60 60"><circle cx="30" cy="30" r="28" fill="#ef4444" opacity="0.2"/><path d="M30 18 L30 34 M30 42 L30 44" stroke="#ef4444" stroke-width="4" stroke-linecap="round"/></svg>'
            }
          </div>
          <div class="result-content">
            <h2 class="result-title">${safe ? '✓ File is Safe' : '⚠ Threats Detected!'}</h2>
            <p class="result-filename">${escapeHtml(fname)}</p>
          </div>
        </div>
        
        ${!safe ? `
          <div class="threat-alert">
            <h3 class="alert-title">⚠️ Security Alert</h3>
            <p class="alert-message">This file contains malicious content. <strong>Do not open it.</strong></p>
            
            <div class="threat-details">
              <h4>Detected Threats:</h4>
              <ul class="threat-list">
                ${threats.map(t => `<li><span class="threat-badge">${escapeHtml(t)}</span></li>`).join('')}
              </ul>
            </div>

            <div class="action-box danger">
              <h4>⚠️ What to Do:</h4>
              <ol>
                <li><strong>Delete this file immediately</strong></li>
                <li>If you opened it, run a full system scan</li>
                <li>Change passwords if you entered any credentials</li>
                <li>Monitor your accounts for unusual activity</li>
              </ol>
            </div>
          </div>
        ` : `
          <div class="safe-summary">
            <div class="scan-success">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
              <span>No threats detected</span>
            </div>
            <p class="scan-info">This file has been scanned by ${totalEngines} security engine${totalEngines !== 1 ? 's' : ''} and appears to be safe.</p>
            
            <div class="action-box safe">
              <h4>✓ You're Good to Go</h4>
              <p>This file appears safe to open and use. However, always exercise caution with files from unknown sources.</p>
            </div>
          </div>
        `}

        <div class="scan-meta-grid">
          <div class="meta-card">
            <div class="meta-icon">📄</div>
            <div class="meta-info">
              <div class="meta-label">File Size</div>
              <div class="meta-value">${escapeHtml(fsize || 'Unknown')}</div>
            </div>
          </div>
          
          <div class="meta-card">
            <div class="meta-icon">🕐</div>
            <div class="meta-info">
              <div class="meta-label">Scanned</div>
              <div class="meta-value">${escapeHtml(when.split(',')[0])}</div>
            </div>
          </div>
          
          <div class="meta-card">
            <div class="meta-icon">🛡️</div>
            <div class="meta-info">
              <div class="meta-label">Engines</div>
              <div class="meta-value">${totalEngines} scanner${totalEngines !== 1 ? 's' : ''}</div>
            </div>
          </div>

          ${!safe ? `
            <div class="meta-card danger">
              <div class="meta-icon">⚠️</div>
              <div class="meta-info">
                <div class="meta-label">Threats Found</div>
                <div class="meta-value">${threatEngines} detection${threatEngines !== 1 ? 's' : ''}</div>
              </div>
            </div>
          ` : `
            <div class="meta-card success">
              <div class="meta-icon">✓</div>
              <div class="meta-info">
                <div class="meta-label">Status</div>
                <div class="meta-value">All Clear</div>
              </div>
            </div>
          `}
        </div>
      </div>
    `;

    const threatList = threats.length
      ? `<ul class="tech-threat-list">${threats.map(t => `<li>${escapeHtml(t)}</li>`).join('')}</ul>`
      : `<div class="muted">No threats listed.</div>`;

    const enginesHTML = engines.map(r => {
      const eng = r.engine || r.name || 'Engine';
      const status = r.status || r.result || 'unknown';
      let detail = '';
      if (r.details) detail = formatEngineDetail(eng, r.details);
      else if (r.error) detail = `error: ${r.error}`;
      else if (r.message) detail = r.message;
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

    const technicalView = `
      <div class="technical-panel">
        <h3>Technical Details</h3>
        <form class="kv">
          <label>Filename</label><input type="text" value="${escapeHtml(fname)}" readonly />
          <label>Size</label><input type="text" value="${escapeHtml(fsize)}" readonly />
          <label>Type</label><input type="text" value="${escapeHtml(ftype)}" readonly />
          <label>Scanned</label><input type="text" value="${escapeHtml(when)}" readonly />
          <label>SHA-256</label><input type="text" value="${escapeHtml(sha256 || '—')}" readonly />
          <label>Verdict</label><input class="${verdictClass}" type="text" value="${escapeHtml(verdict)}" readonly />
        </form>

        <div class="tech-section">
          <h4>Per-engine results</h4>
          ${enginesHTML || '<div class="muted">No engine data.</div>'}
        </div>

        <div class="tech-section">
          <h4>Detected Threats</h4>
          ${threatList}
        </div>
      </div>
    `;

    return `
      <div class="view-toggle-container">
        <button type="button" class="view-toggle-btn active" data-view="simple" onclick="window.toggleResultView(this, 'simple')">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
            <path d="M2 3h12v2H2V3zm0 4h12v2H2V7zm0 4h12v2H2v-2z"/>
          </svg>
          Simple View
        </button>
        <button type="button" class="view-toggle-btn" data-view="technical" onclick="window.toggleResultView(this, 'technical')">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
            <path d="M5.854 4.854a.5.5 0 1 0-.708-.708l-3.5 3.5a.5.5 0 0 0 0 .708l3.5 3.5a.5.5 0 0 0 .708-.708L2.707 8l3.147-3.146zm4.292 0a.5.5 0 0 1 .708-.708l3.5 3.5a.5.5 0 0 1 0 .708l-3.5 3.5a.5.5 0 0 1-.708-.708L13.293 8l-3.147-3.146z"/>
          </svg>
          Technical Details
        </button>
      </div>
      
      <div class="view-content simple-view active">
        ${userFriendlyView}
      </div>
      
      <div class="view-content technical-view">
        ${technicalView}
      </div>
    `;
  }

  window.toggleResultView = function(btn, viewType) {
    const container = btn.closest('.view-toggle-container');
    const parent = container.parentElement;
    container.querySelectorAll('.view-toggle-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const simpleView = parent.querySelector('.simple-view');
    const technicalView = parent.querySelector('.technical-view');
    if (viewType === 'simple') {
      simpleView.classList.add('active');
      technicalView.classList.remove('active');
    } else {
      simpleView.classList.remove('active');
      technicalView.classList.add('active');
    }
  };

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
    let total = 0, skippedCount = 0, skippedBytes = 0;
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
      alert('All selected files were skipped due to size limits.');
      return;
    }
    const formData = new FormData();
    viewerFileMap = new Map();
    for (const file of selected) {
      const uploadName = file.webkitRelativePath && file.webkitRelativePath.length ? file.webkitRelativePath : file.name;
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
      const response = await fetch('http://localhost:5001/upload', {
        method: 'POST',
        body: formData
      });
      const ct = response.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await response.text();
        throw new Error('Server returned non-JSON: ' + text.slice(0, 200));
      }
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.message || payload.error || 'Upload failed');
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