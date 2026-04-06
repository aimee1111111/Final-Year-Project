/*
  Home page interaction script

  This file adds small interactive behaviour to the page.
  It makes the URL button keyboard accessible and creates
  a mouse-follow effect for the background orb elements.
*/

(() => {
  "use strict";

  const urlButton = document.getElementById("urlButton");

  // Lets the URL button be activated with Enter or Space
  if (urlButton) {
    urlButton.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        urlButton.click();
      }
    });
  }

  // Moves the background orbs slightly based on mouse position
  document.addEventListener("mousemove", (e) => {
    const orbs = document.querySelectorAll(".orb");
    const x = e.clientX / window.innerWidth;
    const y = e.clientY / window.innerHeight;

    orbs.forEach((orb, index) => {
      // Each orb moves at a slightly different speed for a layered effect
      const speed = (index + 1) * 20;
      orb.style.transform = `translate(${x * speed}px, ${y * speed}px)`;
    });
  });
})();