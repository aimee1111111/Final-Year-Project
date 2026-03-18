(() => {
  const body = document.getElementById('scanHistoryBody');
  const modal = document.getElementById('scanDetailsModal');
  const modalBody = document.getElementById('modalBody');
  const closeModalBtn = document.getElementById('closeModal');
  const backdrop = document.getElementById('modalBackdrop');

  let cached = [];

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c]));
  }

  function formatDate(iso) {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso || '';
    }
  }

  function statusLabel(safe) {
    return safe ? 'Clean' : 'Threats / Error';
  }

  function statusClass(safe) {
    return safe ? 'ok' : 'bad';
  }

  function threatsSummary(threats) {
    if (!Array.isArray(threats) || threats.length === 0) return '—';
    const text = threats.join(', ');
    return text.length > 120 ? text.slice(0, 117) + '...' : text;
  }

  function renderLoading() {
    body.innerHTML = `
      <tr>
        <td colspan="6" class="muted">
          <span class="spinner"></span>
          Loading your scan history...
        </td>
      </tr>
    `;
  }

  function renderEmpty() {
    body.innerHTML = `
      <tr>
        <td colspan="6" class="muted">No scans yet. Scan some files first.</td>
      </tr>
    `;
  }

  function renderError(msg) {
    body.innerHTML = `
      <tr>
        <td colspan="6" class="bad">Failed to load history: ${escapeHtml(msg)}</td>
      </tr>
    `;
  }

  function renderTableRows(results) {
    if (!results.length) return renderEmpty();

    body.innerHTML = results.map((r, idx) => {
      const date = formatDate(r.created_at);
      const filename = r.filename || '(unknown)';
      const safe = !!r.safe;
      const message = r.message || '';
      const threatText = threatsSummary(r.threats);

      return `
        <tr>
          <td>${escapeHtml(date)}</td>
          <td>${escapeHtml(filename)}</td>
          <td class="${statusClass(safe)}">${escapeHtml(statusLabel(safe))}</td>
          <td>${escapeHtml(message)}</td>
          <td title="${escapeHtml((r.threats || []).join('\n'))}">${escapeHtml(threatText)}</td>
          <td>
            <button class="btn btn-ghost" data-idx="${idx}" type="button">View</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function formatDetails(details) {
    if (!details) return '';
    if (typeof details === 'string') {
      return `<pre class="details-pre">${escapeHtml(details)}</pre>`;
    }
    try {
      return `<pre class="details-pre">${escapeHtml(JSON.stringify(details, null, 2))}</pre>`;
    } catch {
      return `<pre class="details-pre">${escapeHtml(String(details))}</pre>`;
    }
  }

  function statusBadge(status) {
    const value = (status || 'unknown').toLowerCase();

    let cls = 'badge-neutral';
    if (value.includes('clean')) cls = 'badge-ok';
    else if (value.includes('threat') || value.includes('malicious') || value.includes('detected')) cls = 'badge-bad';
    else if (value.includes('error')) cls = 'badge-warn';

    return `<span class="status-badge ${cls}">${escapeHtml(status || 'unknown')}</span>`;
  }

  function openModalFor(result) {
    const file = result.filename || '(unknown)';
    const when = formatDate(result.created_at);
    const safe = !!result.safe;
    const verdict = safe ? 'Clean' : 'Threats / Error';

    const threats = Array.isArray(result.threats) && result.threats.length
      ? `
        <div class="threat-list">
          ${result.threats.map(t => `
            <div class="threat-item">${escapeHtml(t)}</div>
          `).join('')}
        </div>
      `
      : `<div class="empty-state">No threats listed.</div>`;

    const engines = Array.isArray(result.scan_results) ? result.scan_results : [];
    const enginesHtml = engines.length
      ? engines.map(e => {
          const eng = e.engine || 'Engine';
          const status = e.status || 'unknown';
          const detailsHtml = e.details ? formatDetails(e.details) : '';
          const error = e.error ? escapeHtml(e.error) : '';

          return `
            <div class="engine-card">
              <div class="engine-top">
                <div class="engine-name">${escapeHtml(eng)}</div>
                ${statusBadge(status)}
              </div>

              ${detailsHtml ? `
                <div class="engine-section">
                  <div class="engine-label">Details</div>
                  ${detailsHtml}
                </div>
              ` : ''}

              ${error ? `
                <div class="engine-section">
                  <div class="engine-label">Error</div>
                  <div class="engine-error">${error}</div>
                </div>
              ` : ''}
            </div>
          `;
        }).join('')
      : `<div class="empty-state">No engine data.</div>`;

    modalBody.innerHTML = `
      <div class="scan-summary">
        <div class="summary-card">
          <div class="summary-label">Filename</div>
          <div class="summary-value">${escapeHtml(file)}</div>
        </div>

        <div class="summary-card">
          <div class="summary-label">Scanned</div>
          <div class="summary-value">${escapeHtml(when)}</div>
        </div>

        <div class="summary-card">
          <div class="summary-label">Verdict</div>
          <div class="summary-value">
            <span class="status-badge ${safe ? 'badge-ok' : 'badge-bad'}">${escapeHtml(verdict)}</span>
          </div>
        </div>

        <div class="summary-card">
          <div class="summary-label">Message</div>
          <div class="summary-value">${escapeHtml(result.message || '—')}</div>
        </div>
      </div>

      <div class="modal-section">
        <h3>Per-engine results</h3>
        <div class="engine-list">
          ${enginesHtml}
        </div>
      </div>

      <div class="modal-section">
        <h3>Threats</h3>
        ${threats}
      </div>
    `;

    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('open');
  }

  function closeModal() {
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('open');
    modalBody.innerHTML = '';
  }

  async function loadHistory() {
    renderLoading();

    const userId = window.localStorage?.getItem('user_id');
    if (!userId) {
      return renderError('No user_id found. Please log in again.');
    }

    try {
      const res = await fetch(`http://localhost:5001/history?user_id=${encodeURIComponent(userId)}&limit=200`);
      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await res.text();
        throw new Error('Server returned non-JSON: ' + text.slice(0, 200));
      }
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.error || payload.message || 'Request failed');

      cached = Array.isArray(payload) ? payload : (payload.results || []);
      renderTableRows(cached);
    } catch (e) {
      renderError(e.message || String(e));
    }
  }

  body.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-idx]');
    if (!btn) return;
    const idx = Number(btn.dataset.idx);
    if (!Number.isFinite(idx) || !cached[idx]) return;
    openModalFor(cached[idx]);
  });

  closeModalBtn?.addEventListener('click', closeModal);
  backdrop?.addEventListener('click', closeModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) closeModal();
  });

  loadHistory();
})();