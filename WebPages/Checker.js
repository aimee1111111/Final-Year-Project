(() => {
  "use strict";

  const API_BASE = "http://localhost:5050";

  const emailCard = document.getElementById("emailCard");
  const panel = document.getElementById("checkerPanel");
  const closeBtn = document.getElementById("checkerClose");
  const bodyEl = document.getElementById("checkerBody");
  const input = document.getElementById("checkerInput");
  const sendBtn = document.getElementById("checkerSend");

  let lastAnalyzedText = "";

  function ensureElements() {
    const ok = !!(emailCard && panel && closeBtn && bodyEl && input && sendBtn);
    if (!ok) {
      console.error("Checker init failed: missing one or more required elements.", {
        emailCard: !!emailCard,
        panel: !!panel,
        closeBtn: !!closeBtn,
        bodyEl: !!bodyEl,
        input: !!input,
        sendBtn: !!sendBtn
      });
    }
    return ok;
  }

  function scrollToBottom() {
    bodyEl.scrollTop = bodyEl.scrollHeight;
  }

  function appendMsg(text, type = "bot") {
    const wrap = document.createElement("div");
    wrap.className = `checker-msg ${type}`;
    wrap.textContent = text;
    bodyEl.appendChild(wrap);
    scrollToBottom();
    return wrap;
  }

  function openPanel() {
    panel.style.display = "flex";
    emailCard.setAttribute("aria-expanded", "true");
    input.focus();
  }

  function closePanel() {
    panel.style.display = "none";
    emailCard.setAttribute("aria-expanded", "false");
  }

  function attachFeedbackBar(container) {
    const bar = document.createElement("div");
    bar.className = "fb-bar";
    bar.innerHTML = `
      <button class="fb-btn phish" data-label="1" type="button">⚠️ Mark as phishing</button>
      <button class="fb-btn legit" data-label="0" type="button">✅ Mark as legit</button>
      <span class="fb-status" aria-live="polite"></span>
    `;
    container.appendChild(bar);

    const buttons = bar.querySelectorAll(".fb-btn");
    const status = bar.querySelector(".fb-status");
    let submitted = false;

    buttons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (submitted || !lastAnalyzedText) return;

        const label = Number(btn.getAttribute("data-label"));
        buttons.forEach((b) => (b.disabled = true));
        status.textContent = "Sending feedback...";

        try {
          const res = await fetch(`${API_BASE}/feedback`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              text: lastAnalyzedText.trim(),
              label
            })
          });

          const ct = res.headers.get("content-type") || "";
          let data = null;
          let raw = "";

          if (ct.includes("application/json")) {
            data = await res.json();
          } else {
            raw = await res.text();
          }

          if (!res.ok) {
            const msg =
              (data && (data.error || data.message)) ||
              (raw ? `HTTP ${res.status} ${res.statusText}: ${raw.slice(0, 200)}` : `HTTP ${res.status} ${res.statusText}`);
            throw new Error(msg);
          }

          submitted = true;

          if (data.retrained_batch) {
            status.textContent = "Thanks — saved, online updated, and batch retrained.";
          } else if (data.rebuilt_online) {
            status.textContent = "Thanks — saved and online model rebuilt from feedback.";
          } else {
            status.textContent = "Thanks — feedback saved and model updated.";
          }
        } catch (err) {
          console.error("Feedback error:", err);
          status.textContent = `Feedback failed: ${err.message}`;
          buttons.forEach((b) => (b.disabled = false));
        }
      });
    });
  }

  async function analyzeContent(content) {
    const text = (content || "").replace(/\s+/g, " ").trim();
    if (!text) return;

    input.value = "";
    sendBtn.disabled = true;

    const thinking = document.createElement("div");
    thinking.className = "checker-msg thinking";
    thinking.innerHTML = '🔍 Analyzing... <div class="thinking-dots"><span></span><span></span><span></span></div>';
    bodyEl.appendChild(thinking);
    scrollToBottom();

    try {
      const res = await fetch(`${API_BASE}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })
      });

      thinking.remove();

      const ct = res.headers.get("content-type") || "";
      let data = null;
      let raw = "";

      if (ct.includes("application/json")) {
        data = await res.json();
      } else {
        raw = await res.text();
      }

      if (!res.ok) {
        const msg =
          (data && (data.error || data.message)) ||
          (raw ? `HTTP ${res.status} ${res.statusText}: ${raw.slice(0, 200)}` : `HTTP ${res.status} ${res.statusText}`);
        appendMsg(`❌ Error: ${msg}`, "bot");
        return;
      }

      const replyText = (data && data.reply) || "No analysis available.";
      const bubble = appendMsg(replyText, "analysis");

      lastAnalyzedText = text;
      attachFeedbackBar(bubble);
    } catch (err) {
      thinking.remove();
      console.error("Analysis error:", err);
      appendMsg("❌ Unable to connect to analysis service. Make sure Flask is running on port 5050.", "bot");
    } finally {
      sendBtn.disabled = false;
      input.focus();
    }
  }

  function init() {
    if (!ensureElements()) return;

    emailCard.addEventListener("click", openPanel);

    emailCard.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openPanel();
      }
    });

    closeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      closePanel();
    });

    sendBtn.addEventListener("click", () => analyzeContent(input.value));

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        analyzeContent(input.value);
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();