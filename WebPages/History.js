(() => {
  const body = document.getElementById('scanHistoryBody');
  const modal = document.getElementById('scanDetailsModal');
  const modalBody = document.getElementById('modalBody');
  const closeModalBtn = document.getElementById('closeModal');
  const backdrop = document.getElementById('modalBackdrop');

  let cached = []; // list from API

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

  function openModalFor(result) {
    const file = result.filename || '(unknown)';
    const when = formatDate(result.created_at);
    const verdict = result.safe ? 'Clean' : 'Threats / Error';

    const threats = Array.isArray(result.threats) && result.threats.length
      ? `<ul>${result.threats.map(t => `<li>${escapeHtml(t)}</li>`).join('')}</ul>`
      : `<div class="muted">No threats listed.</div>`;

    const engines = Array.isArray(result.scan_results) ? result.scan_results : [];
    const enginesHtml = engines.length
      ? engines.map(e => {
          const eng = e.engine || 'Engine';
          const status = e.status || 'unknown';
          const details = e.details ? escapeHtml(
            typeof e.details === 'string' ? e.details : JSON.stringify(e.details)
          ) : '';
          const error = e.error ? escapeHtml(e.error) : '';

          return `
            <div class="engine">
              <div class="row"><span class="k">Engine</span><span class="v">${escapeHtml(eng)}</span></div>
              <div class="row"><span class="k">Status</span><span class="v">${escapeHtml(status)}</span></div>
              ${details ? `<div class="row"><span class="k">Details</span><span class="v">${details}</span></div>` : ''}
              ${error ? `<div class="row"><span class="k">Error</span><span class="v bad">${error}</span></div>` : ''}
            </div>
          `;
        }).join('')
      : `<div class="muted">No engine data.</div>`;

    modalBody.innerHTML = `
      <div class="details-grid">
        <div><div class="k">Filename</div><div class="v">${escapeHtml(file)}</div></div>
        <div><div class="k">Scanned</div><div class="v">${escapeHtml(when)}</div></div>
        <div><div class="k">Verdict</div><div class="v ${statusClass(!!result.safe)}">${escapeHtml(verdict)}</div></div>
        <div><div class="k">Message</div><div class="v">${escapeHtml(result.message || '')}</div></div>
      </div>

      <h3>Per-engine results</h3>
      ${enginesHtml}

      <h3>Threats</h3>
      ${threats}
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

  // events
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
