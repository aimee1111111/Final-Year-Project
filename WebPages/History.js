
// Handles:
//  - Fetching scan history for the logged-in user
//  - Rendering the table
//  - Opening modal for individual scan details
//  - Displaying per-engine scan results

document.addEventListener('DOMContentLoaded', () => {

  const tableBody = document.getElementById('scanHistoryBody');
  const modal = document.getElementById('scanDetailsModal');
  const modalBody = document.getElementById('modalBody');
  const closeModalBtn = document.getElementById('closeModal');
  const modalBackdrop = document.getElementById('modalBackdrop');

  // USER ID RETRIEVAL
  // Retrieves user_id from localStorage OR sessionStorage.
  // Ensures invalid values like "null" or "undefined" are ignored.
  const getId = (k) => {
    const v = localStorage.getItem(k) ?? sessionStorage.getItem(k);
    return v && v !== 'undefined' && v !== 'null' ? v : null;
  };

  const userId = getId('user_id');

  // If no user is logged in, show message and stop.
  if (!userId) {
    console.warn('No user_id in storage. Current storage:', {
      local_user_id: localStorage.getItem('user_id'),
      session_user_id: sessionStorage.getItem('user_id')
    });
    tableBody.innerHTML =
      '<tr><td colspan="6" class="muted">No user logged in.</td></tr>';
    return;
  }

  // Shortens long strings for table display
  const truncate = (text, max = 80) => {
    if (!text) return '';
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
  };

  // Converts threats field to readable text
  const formatThreats = (raw) => {
    if (!raw) return 'None';
    if (Array.isArray(raw)) return raw.join(', ') || 'None';
    if (typeof raw === 'string') return raw || 'None';

    // Fallback for objects
    try {
      return JSON.stringify(raw);
    } catch {
      return String(raw);
    }
  };

  // Creates a colored badge for scan status
  const createStatusBadge = (safe) => {
    if (safe === true) {
      return '<span class="status-badge status-safe">Safe</span>';
    }
    if (safe === false) {
      return '<span class="status-badge status-unsafe">Unsafe</span>';
    }
    return '<span class="status-badge status-unknown">Unknown</span>';
  };

  // Opens the modal visually + for accessibility
  const openModal = () => {
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('open');
  };

  // Closes the modal visually + for accessibility
  const closeModal = () => {
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('open');
  };

  // Modal close handlers 
  closeModalBtn.addEventListener('click', closeModal);
  modalBackdrop.addEventListener('click', closeModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) {
      closeModal();
    }
  });

  const renderRows = (scans) => {
    // Show empty state if no scans
    if (!Array.isArray(scans) || scans.length === 0) {
      tableBody.innerHTML =
        '<tr><td colspan="6" class="muted">No scan history found.</td></tr>';
      return;
    }

    // Build table rows
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
              <!-- Button triggers modal -->
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

    // Add click listeners for all "View" buttons
    tableBody.querySelectorAll('.details-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const scanId = btn.getAttribute('data-id');
        await loadDetails(scanId);
      });
    });
  };

  // LOAD SINGLE SCAN DETAILS INTO MODAL 
  const loadDetails = async (scanId) => {
    if (!scanId) return;

    // Loading placeholder
    modalBody.innerHTML = '<p class="muted">Loading details...</p>';
    openModal();

    try {
      // Request single scan detail from API
      const res = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}?user_id=${encodeURIComponent(userId)}`
      );

      if (!res.ok) {
        throw new Error(`Failed to fetch details (${res.status})`);
      }

      const scan = await res.json();

      const threatsText = formatThreats(scan.threats);

      // Per-engine results (array or empty)
      const engines = Array.isArray(scan.scan_results)
        ? scan.scan_results
        : [];

      // Build HTML for each engine
      const enginesHtml =
        engines.length === 0
          ? '<p class="muted">No per-engine data available.</p>'
          : engines
              .map((engine) => {
                const status = engine.status || 'unknown';

                // Details may be string, object, or empty
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
                    ${detail ? `<div class="engine-detail">${detail}</div>` : ''}
                  </div>
                `;
              })
              .join('');

      // Fill modal with scan info
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

  //LOAD FULL SCAN HISTORY 
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

  // Fetch and render table on page load
  loadHistory();
});
