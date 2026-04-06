/*
  This script loads and displays the user’s scan history.

  It requests previous scan results from the backend, shows them in a table,
  and allows the user to open a modal window to view full details for a
  selected scan. The script also handles loading states, empty states,
  error messages, status labels, and formatting of per-engine scan results.
*/

(() => {
  // Table body where scan history rows will be inserted
  const body = document.getElementById('scanHistoryBody');

  // Modal elements used to display full scan details
  const modal = document.getElementById('scanDetailsModal');
  const modalBody = document.getElementById('modalBody');
  const closeModalBtn = document.getElementById('closeModal');
  const backdrop = document.getElementById('modalBackdrop');

  // Stores scan history results after they are loaded from the API
  let cached = [];

  function escapeHtml(s) {
    // Escapes special HTML characters to make displayed text safe
    return String(s ?? '').replace(/[&<>"']/g, c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c]));
  }

  function formatDate(iso) {
    // Converts an ISO date string into the user's local date/time format
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso || '';
    }
  }

  function statusLabel(safe) {
    // Converts the boolean safe value into a readable label
    return safe ? 'Clean' : 'Threats / Error';
  }

  function statusClass(safe) {
    // Returns the CSS class used for colouring the status
    return safe ? 'ok' : 'bad';
  }

  function threatsSummary(threats) {
    // Creates a short one-line summary of threat names for the table
    if (!Array.isArray(threats) || threats.length === 0) return '—';
    const text = threats.join(', ');
    return text.length > 120 ? text.slice(0, 117) + '...' : text;
  }

  function renderLoading() {
    // Shows a loading row while scan history is being fetched
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
    // Shows a message if the user has no scan history yet
    body.innerHTML = `
      <tr>
        <td colspan="6" class="muted">No scans yet. Scan some files first.</td>
      </tr>
    `;
  }

  function renderError(msg) {
    // Shows an error row if loading the history fails
    body.innerHTML = `
      <tr>
        <td colspan="6" class="bad">Failed to load history: ${escapeHtml(msg)}</td>
      </tr>
    `;
  }

  function renderTableRows(results) {
    // If there are no results, show the empty state
    if (!results.length) return renderEmpty();

    // Creates a table row for each scan result
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
    // Formats engine details so they can be displayed inside a <pre> block
    if (!details) return '';

    // If details are already a string, show them directly
    if (typeof details === 'string') {
      return `<pre class="details-pre">${escapeHtml(details)}</pre>`;
    }

    // If details are an object, convert them to pretty JSON
    try {
      return `<pre class="details-pre">${escapeHtml(JSON.stringify(details, null, 2))}</pre>`;
    } catch {
      return `<pre class="details-pre">${escapeHtml(String(details))}</pre>`;
    }
  }

  function statusBadge(status) {
    // Creates a coloured status badge for each scan engine result
    const value = (status || 'unknown').toLowerCase();

    let cls = 'badge-neutral';
    if (value.includes('clean')) cls = 'badge-ok';
    else if (value.includes('threat') || value.includes('malicious') || value.includes('detected')) cls = 'badge-bad';
    else if (value.includes('error')) cls = 'badge-warn';

    return `<span class="status-badge ${cls}">${escapeHtml(status || 'unknown')}</span>`;
  }

  function openModalFor(result) {
    // Opens the modal and fills it with full details for one scan result
    const file = result.filename || '(unknown)';
    const when = formatDate(result.created_at);
    const safe = !!result.safe;
    const verdict = safe ? 'Clean' : 'Threats / Error';

    // Builds the threats section
    const threats = Array.isArray(result.threats) && result.threats.length
      ? `
        <div class="threat-list">
          ${result.threats.map(t => `
            <div class="threat-item">${escapeHtml(t)}</div>
          `).join('')}
        </div>
      `
      : `<div class="empty-state">No threats listed.</div>`;

    // Gets per-engine scan results
    const engines = Array.isArray(result.scan_results) ? result.scan_results : [];

    // Builds the HTML for each engine card
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

    // Inserts the final modal content
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

    // Makes the modal visible
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('open');
  }

  function closeModal() {
    // Hides the modal and clears its content
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('open');
    modalBody.innerHTML = '';
  }

  async function loadHistory() {
    // Shows loading state first
    renderLoading();

    // Gets the logged-in user ID from localStorage
    const userId = window.localStorage?.getItem('user_id');

    // Stops if the user ID is missing
    if (!userId) {
      return renderError('No user_id found. Please log in again.');
    }

    try {
      // Requests scan history from the backend
      const res = await fetch(`http://localhost:5001/history?user_id=${encodeURIComponent(userId)}&limit=200`);

      // Checks that the response is JSON
      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const text = await res.text();
        throw new Error('Server returned non-JSON: ' + text.slice(0, 200));
      }

      // Reads the JSON response
      const payload = await res.json();

      // Throws an error if the backend request failed
      if (!res.ok) throw new Error(payload.error || payload.message || 'Request failed');

      // Stores the results and renders the table
      cached = Array.isArray(payload) ? payload : (payload.results || []);
      renderTableRows(cached);
    } catch (e) {
      // Shows an error message if anything goes wrong
      renderError(e.message || String(e));
    }
  }

  // Opens the modal when a View button is clicked
  body.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-idx]');
    if (!btn) return;

    const idx = Number(btn.dataset.idx);
    if (!Number.isFinite(idx) || !cached[idx]) return;

    openModalFor(cached[idx]);
  });

  // Closes the modal when the close button is clicked
  closeModalBtn?.addEventListener('click', closeModal);

  // Closes the modal when the backdrop is clicked
  backdrop?.addEventListener('click', closeModal);

  // Closes the modal when the Escape key is pressed
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) closeModal();
  });

  // Loads the scan history when the script runs
  loadHistory();
})();