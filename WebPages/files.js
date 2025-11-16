(() => {
  // Element references 
  const form = document.getElementById('uploadForm');
  const fileInput = document.getElementById('fileInput');
  const dropzone = document.getElementById('dropzone');
  const resultDiv = document.getElementById('result');
  const detailsDiv = document.getElementById('details');
  const fileNameEl = document.getElementById('fileName');
  const clearBtn = document.getElementById('clearBtn');

  let currentFile = null;

  // convert bytes to human-readable format
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

  // Set file programmatically (for drag & drop) 
  function setFile(file) {
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
    currentFile = file;
    fileNameEl.textContent = `Selected: ${file.name} (${bytesToHuman(file.size)})`;
  }

  //Render top-level result message (clean / threats detected)
  function renderHeader(result) {
    let text, cls;
    if (result.safe) {
      text = `✓ ${result.message || 'File is clean'}`;
      cls = 'ok';
    } else {
      const items = (result.threats && result.threats.length)
        ? result.threats.join(', ')
        : 'Unknown';
      text = `✗ ${result.message || 'Threats detected'} — ${items}`;
      cls = 'bad';
    }
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = `<div class="${cls}">${text}</div>`;
  }

  //Render detailed results for each scan engine 
  function renderDetailsForm(result) {
    detailsDiv.style.display = 'block';
    const when = new Date().toLocaleString();
    const verdict = result.safe ? 'Clean' : 'Threats detected';
    const verdictClass = result.safe ? 'ok' : 'bad';

    const engines = Array.isArray(result.scan_results) ? result.scan_results : [];
    const enginesHTML = engines.map(r => {
      const eng = r.engine || 'Engine';
      const status = r.status || 'unknown';

      let detail = '';
      if (r.details) {
        if (typeof r.details === 'string') {
          detail = r.details;
        } else if (Array.isArray(r.details)) {
          const rules = r.details.map(d => d.rule || JSON.stringify(d)).join('; ');
          detail = rules;
        } else if (typeof r.details === 'object') {
          detail = JSON.stringify(r.details);
        }
      } else if (r.error) {
        detail = `error: ${r.error}`;
      }

      let chips = '';
      if (Array.isArray(r.details)) {
        const allTags = r.details.flatMap(d => d.tags || []);
        if (allTags.length) {
          chips = `<div class="muted">Tags: ${[...new Set(allTags)]
            .map(t => `<span class="tag">${t}</span>`)
            .join('')}</div>`;
        }
      }

      return `
        <div class="engine">
          <div class="field"><label>Engine</label><div>${eng}</div></div>
          <div class="field"><label>Status</label><div>${status}</div></div>
          ${detail ? `<div class="field"><label>Details</label><div>${detail}</div></div>` : ''}
          ${chips}
        </div>
      `;
    }).join('');

    const threatList = (result.threats && result.threats.length)
      ? `<ul>${result.threats.map(t => `<li>${t}</li>`).join('')}</ul>`
      : `<div class="muted">No threats listed.</div>`;

    const fname = currentFile ? currentFile.name : '(unknown)';
    const fsize = currentFile ? bytesToHuman(currentFile.size) : '';
    const ftype = currentFile ? (currentFile.type || '—') : '—';

    detailsDiv.innerHTML = `
      <form id="detailsForm" class="kv">
        <label>Filename</label><input type="text" value="${fname}" readonly />
        <label>Size</label><input type="text" value="${fsize}" readonly />
        <label>Type</label><input type="text" value="${ftype}" readonly />
        <label>Scanned</label><input type="text" value="${when}" readonly />
        <label>Verdict</label><input class="${verdictClass}" type="text" value="${verdict}" readonly />
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

  // ✅ Upload file to backend and handle response (via Node, with user_id)
  async function uploadCurrentFile() {
    const file = fileInput.files[0];
    if (!file) {
      alert('Please select a file');
      return;
    }
    currentFile = file;

    // ✅ Get logged-in user_id from localStorage
    const userId = localStorage.getItem('user_id');
    if (!userId) {
      alert('You must be logged in to scan a file.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('user_id', userId); // ✅ send user_id to Node

    // Loading state
    resultDiv.style.display = 'block';
    resultDiv.textContent = 'Scanning file...';
    detailsDiv.style.display = 'none';
    detailsDiv.innerHTML = '';

    try {
      // ✅ Call Node /upload route, not Flask directly
      const response = await fetch('/upload', {
        method: 'POST',
        body: formData
      });

      const ct = response.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await response.text();
        throw new Error('Server returned non-JSON: ' + text.slice(0, 200));
      }

      const result = await response.json();

      // Render results
      renderHeader(result);
      renderDetailsForm(result);
    } catch (err) {
      resultDiv.style.display = 'block';
      resultDiv.innerHTML = `<span class="bad">Upload failed:</span> ${err.message}`;
      detailsDiv.style.display = 'none';
      detailsDiv.innerHTML = '';
    }
  }

  // Click / keyboard interaction to open file picker
  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  // Show selected file name after choosing from picker
  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    fileNameEl.textContent = f ? `Selected: ${f.name} (${bytesToHuman(f.size)})` : '';
    currentFile = f || null;
  });

  //Drag & drop setup
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

  // Handle actual file drop
  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (!files || !files.length) return;
    setFile(files[0]);
  });

  // --- Form submit triggers upload ---
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await uploadCurrentFile();
  });

  // Clear everything (reset UI) 
  clearBtn.addEventListener('click', () => {
    fileInput.value = '';
    currentFile = null;
    fileNameEl.textContent = '';
    resultDiv.style.display = 'none';
    resultDiv.textContent = '';
    detailsDiv.style.display = 'none';
    detailsDiv.innerHTML = '';
  });
})();
