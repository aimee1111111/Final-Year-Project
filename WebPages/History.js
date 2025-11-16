// History.js
document.addEventListener('DOMContentLoaded', () => {
  const tableBody = document.getElementById('scanHistoryBody');
  const modal = document.getElementById('scanDetailsModal');
  const modalBody = document.getElementById('modalBody');
  const closeModalBtn = document.getElementById('closeModal');
  const modalBackdrop = document.getElementById('modalBackdrop');

  const getId = (k) => {
    const v = localStorage.getItem(k) ?? sessionStorage.getItem(k);
    return v && v !== 'undefined' && v !== 'null' ? v : null;
  };
  const userId = getId('user_id');

  if (!userId) {
    console.warn('No user_id in storage. Current storage:', {
      local_user_id: localStorage.getItem('user_id'),
      session_user_id: sessionStorage.getItem('user_id')
    });
    tableBody.innerHTML =
      '<tr><td colspan="6" class="muted">No user logged in.</td></tr>';
    return;
  }

  // Helpers
  const truncate = (text, max = 80) => {
    if (!text) return '';
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
  };

  const formatThreats = (raw) => {
    if (!raw) return 'None';
    if (Array.isArray(raw)) return raw.join(', ') || 'None';
    if (typeof raw === 'string') return raw || 'None';
    try {
      return JSON.stringify(raw);
    } catch {
      return String(raw);
    }
  };

  const createStatusBadge = (safe) => {
    if (safe === true) {
      return '<span class="status-badge status-safe">Safe</span>';
    }
    if (safe === false) {
      return '<span class="status-badge status-unsafe">Unsafe</span>';
    }
    return '<span class="status-badge status-unknown">Unknown</span>';
  };

  const openModal = () => {
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('open');
  };

  const closeModal = () => {
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('open');
  };

  closeModalBtn.addEventListener('click', closeModal);
  modalBackdrop.addEventListener('click', closeModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) {
      closeModal();
    }
  });

  const renderRows = (scans) => {
    if (!Array.isArray(scans) || scans.length === 0) {
      tableBody.innerHTML =
        '<tr><td colspan="6" class="muted">No scan history found.</td></tr>';
      return;
    }

    tableBody.innerHTML = scans
      .map((scan) => {
        const threatsText = formatThreats(scan.threats);
        const shortThreats = truncate(threatsText, 70);

        return `
          <tr>
            <td>${new Date(scan.scanned_at).toLocaleString()}</td>
            <td class="filename-cell" title="${scan.filename}">
              ${scan.filename}
            </td>
            <td>${createStatusBadge(scan.safe)}</td>
            <td>${scan.message || ''}</td>
            <td title="${threatsText}">
              ${shortThreats}
            </td>
            <td>
              <button
                class="details-btn"
                data-id="${scan.id}"
                type="button"
              >
                View
              </button>
            </td>
          </tr>
        `;
      })
      .join('');

    // Attach click handlers for details buttons
    tableBody.querySelectorAll('.details-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const scanId = btn.getAttribute('data-id');
        await loadDetails(scanId);
      });
    });
  };

  const loadDetails = async (scanId) => {
    if (!scanId) return;

    modalBody.innerHTML = '<p class="muted">Loading details...</p>';
    openModal();

    try {
      const res = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}?user_id=${encodeURIComponent(
          userId
        )}`
      );
      if (!res.ok) {
        throw new Error(`Failed to fetch details (${res.status})`);
      }
      const scan = await res.json();

      const threatsText = formatThreats(scan.threats);
      const engines = Array.isArray(scan.scan_results)
        ? scan.scan_results
        : [];

      const enginesHtml =
        engines.length === 0
          ? '<p class="muted">No per-engine data available.</p>'
          : engines
              .map((engine) => {
                const status = engine.status || 'unknown';
                const detail =
                  typeof engine.details === 'string'
                    ? engine.details
                    : engine.details
                    ? JSON.stringify(engine.details)
                    : engine.error || '';
                return `
                  <div class="engine-card">
                    <div class="engine-header">
                      <span class="engine-name">${engine.engine || 'Engine'}</span>
                      <span class="engine-status">${status}</span>
                    </div>
                    ${
                      detail
                        ? `<div class="engine-detail">${detail}</div>`
                        : ''
                    }
                  </div>
                `;
              })
              .join('');

      modalBody.innerHTML = `
        <div class="details-grid">
          <div>
            <span class="label">Filename</span>
            <span>${scan.filename}</span>
          </div>
          <div>
            <span class="label">Date</span>
            <span>${new Date(scan.scanned_at).toLocaleString()}</span>
          </div>
          <div>
            <span class="label">Status</span>
            <span>${createStatusBadge(scan.safe)}</span>
          </div>
          <div>
            <span class="label">Message</span>
            <span>${scan.message || '—'}</span>
          </div>
          <div class="details-full-row">
            <span class="label">Threats</span>
            <span>${threatsText || 'None'}</span>
          </div>
        </div>

        <h3>Per-engine results</h3>
        <div class="engine-list">
          ${enginesHtml}
        </div>
      `;
    } catch (err) {
      console.error('Error loading scan details:', err);
      modalBody.innerHTML = `<p class="muted">Error loading details: ${err.message}</p>`;
    }
  };

  const loadHistory = async () => {
    try {
      const res = await fetch(
        `/api/scans?user_id=${encodeURIComponent(userId)}`
      );
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      const scans = await res.json();
      renderRows(scans);
    } catch (err) {
      console.error('Error loading history:', err);
      tableBody.innerHTML = `<tr><td colspan="6" class="muted">Error loading history: ${err.message}</td></tr>`;
    }
  };

  loadHistory();
});
