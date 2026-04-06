window.toggleResultView = function (btn, viewType) {
  const container = btn.closest(".view-toggle-container");
  const parent = container.parentElement;

  container.querySelectorAll(".view-toggle-btn").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");

  const simpleView = parent.querySelector(".simple-view");
  const technicalView = parent.querySelector(".technical-view");

  if (viewType === "simple") {
    simpleView.classList.add("active");
    technicalView.classList.remove("active");
  } else {
    simpleView.classList.remove("active");
    technicalView.classList.add("active");
  }
};