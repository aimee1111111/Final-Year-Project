(() => {
  "use strict";

  const urlButton = document.getElementById("urlButton");

  if (urlButton) {
    urlButton.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        urlButton.click();
      }
    });
  }

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