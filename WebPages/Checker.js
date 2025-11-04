(() => {
  'use strict';

  // Use env/config in production; localhost is fine for dev.
  const API_BASE = 'http://localhost:5050'; // Flask host/port

  // Cache DOM
  const toggle = document.getElementById('checkerToggle');
  const panel  = document.getElementById('checkerPanel');
  const body   = document.getElementById('checkerBody');
  const input  = document.getElementById('checkerInput');
  const send   = document.getElementById('checkerSend');

  // Keep the exact last analyzed text for feedback
  let lastAnalyzedText = '';

  function scrollToBottom() {
    body.scrollTop = body.scrollHeight;
  }

  function appendMsg(text, type = 'bot') {
    const wrap = document.createElement('div');
    wrap.className = `checker-msg ${type}`;
    wrap.textContent = text;
    body.appendChild(wrap);
    scrollToBottom();
    return wrap;
  }

  // Adds feedback controls under an analysis bubble
  function attachFeedbackBar(container) {
    const bar = document.createElement('div');
    bar.className = 'fb-bar';
    bar.innerHTML = `
      <button class="fb-btn phish" data-label="1" type="button">⚠️ Mark as phishing</button>
      <button class="fb-btn legit" data-label="0" type="button">✅ Mark as legit</button>
      <span class="fb-status" aria-live="polite"></span>
    `;
    container.appendChild(bar);

    const btns = bar.querySelectorAll('.fb-btn');
    const status = bar.querySelector('.fb-status');

    btns.forEach(btn => {
      btn.addEventListener('click', async () => {
        const label = Number(btn.getAttribute('data-label'));
        if (!lastAnalyzedText) return;
        btns.forEach(b => (b.disabled = true));
        status.textContent = 'Sending feedback…';

        try {
          const res = await fetch(`${API_BASE}/feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: lastAnalyzedText, label })
          });

          const ct = res.headers.get('content-type') || '';
          let data = null;
          let raw = null;

          if (ct.includes('application/json')) {
            data = await res.json();
          } else {
            raw = await res.text();
          }

          if (!res.ok) {
            const msg =
              (data && (data.error || data.message)) ||
              (raw
                ? `HTTP ${res.status} ${res.statusText}: ${raw.slice(0, 200)}`
                : `HTTP ${res.status} ${res.statusText}`);
            throw new Error(msg);
          }

          status.textContent = 'Thanks — model updated!';
        } catch (e) {
          status.textContent = 'Feedback failed: ' + e.message;
          btns.forEach(b => (b.disabled = false));
          // Keep errors in console for debugging
          console.error('Feedback error:', e);
        }
      });
    });
  }

  async function analyzeContent(content) {
    if (!content.trim()) return;

    input.value = '';
    send.disabled = true;

    const thinking = document.createElement('div');
    thinking.className = 'checker-msg thinking';
    thinking.innerHTML = '🔍 Analyzing... <div class="thinking-dots"><span></span><span></span><span></span></div>';
    body.appendChild(thinking);
    scrollToBottom();

    try {
      const res = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: content })
      });

      thinking.remove();

      const ct = res.headers.get('content-type') || '';
      let data = null;
      let raw = null;

      if (ct.includes('application/json')) {
        data = await res.json();
      } else {
        raw = await res.text();
      }

      if (!res.ok) {
        const msg =
          (data && (data.error || data.message)) ||
          (raw ? `HTTP ${res.status} ${res.statusText}: ${raw.slice(0, 200)}` : `HTTP ${res.status} ${res.statusText}`);
        appendMsg(`❌ Error: ${msg}`, 'bot');
        return;
      }

      const replyText = (data && data.reply) || 'No analysis available.';
      const bubble = appendMsg(replyText, 'analysis');

      // Remember the exact analyzed input for feedback
      lastAnalyzedText = content;

      // Attach feedback UI under this specific analysis bubble
      attachFeedbackBar(bubble);
    } catch (e) {
      thinking.remove();
      console.error('Analysis error:', e);
      appendMsg('❌ Unable to connect to analysis service. Make sure the Flask server is running on port 5050.', 'bot');
    } finally {
      send.disabled = false;
    }
  }

  // Wire up interactions
  function initEvents() {
    if (!toggle || !panel || !input || !send) return;

    toggle.addEventListener('click', () => {
      const isVisible = panel.style.display === 'flex';
      panel.style.display = isVisible ? 'none' : 'flex';
      toggle.setAttribute('aria-expanded', String(!isVisible));
      if (!isVisible) input.focus();
    });

    send.addEventListener('click', () => {
      const content = (input.value || '').trim();
      if (content) analyzeContent(content);
    });

    input.addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.ctrlKey) {
        e.preventDefault();
        const content = (input.value || '').trim();
        if (content) analyzeContent(content);
      }
    });
  }

  // Initialize when DOM is ready (script uses defer, but this is extra-safe)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initEvents);
  } else {
    initEvents();
  }
})();
