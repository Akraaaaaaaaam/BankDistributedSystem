(function () {
  // Confirmations sur éléments ayant data-confirm
  document.addEventListener("click", function (e) {
    const el = e.target.closest("[data-confirm]");
    if (!el) return;
    const msg = el.getAttribute("data-confirm") || "Confirmer ?";
    if (!confirm(msg)) e.preventDefault();
  });

  // Auto-hide toasts (uniquement ceux marqués data-autohide)
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  setTimeout(() => {
    document.querySelectorAll(".toast[data-autohide='true']").forEach(t => {
      if (reduceMotion) {
        t.remove();
        return;
      }
      t.style.opacity = "0";
      t.style.transform = "translateY(-6px)";
      t.style.transition = "all .25s ease";
      setTimeout(() => t.remove(), 350);
    });
  }, 4500);
})();
