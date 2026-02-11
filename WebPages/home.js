(() => {
  "use strict";

  const emailCard = document.getElementById("emailCard");
  const checkerPanel = document.getElementById("checkerPanel");
  const checkerClose = document.getElementById("checkerClose");

  const urlButton = document.getElementById("urlButton");

  // AI panel toggle
  if (emailCard && checkerPanel) {
    emailCard.addEventListener("click", () => {
      const isVisible = checkerPanel.style.display === "flex";
      checkerPanel.style.display = isVisible ? "none" : "flex";
      emailCard.setAttribute("aria-expanded", String(!isVisible));

      if (!isVisible) {
        const input = document.getElementById("checkerInput");
        if (input) input.focus();
      }
    });

    emailCard.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        emailCard.click();
      }
    });
  }

  if (checkerClose && checkerPanel) {
    checkerClose.addEventListener("click", (e) => {
      e.stopPropagation();
      checkerPanel.style.display = "none";
      if (emailCard) emailCard.setAttribute("aria-expanded", "false");
    });
  }

  // keyboard support for URL card (click handled by url-checker.js)
  if (urlButton) {
    urlButton.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        urlButton.click();
      }
    });
  }

  // parallax
  document.addEventListener("mousemove", (e) => {
    const orbs = document.querySelectorAll(".orb");
    const x = e.clientX / window.innerWidth;
    const y = e.clientY / window.innerHeight;

    orbs.forEach((orb, index) => {
      const speed = (index + 1) * 20;
      orb.style.transform = `translate(${x * speed}px, ${y * speed}px)`;
    });
  });
 

})();