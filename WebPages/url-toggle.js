window.ucToggle = function(uid, view) {
  const simpleEl = document.getElementById(uid + "_simple");
  const techEl = document.getElementById(uid + "_technical");
  const simpleBtn = document.getElementById(uid + "_btn_simple");
  const techBtn = document.getElementById(uid + "_btn_technical");

  const isSimple = view === "simple";

  simpleEl.style.display = isSimple ? "block" : "none";
  techEl.style.display = isSimple ? "none" : "block";

  simpleBtn.className =
    "uc-toggle-btn " + (isSimple ? "uc-toggle-btn--active" : "uc-toggle-btn--inactive");
  techBtn.className =
    "uc-toggle-btn " + (!isSimple ? "uc-toggle-btn--active" : "uc-toggle-btn--inactive");
};