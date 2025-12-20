(function () {
  // Confirmations sur éléments ayant data-confirm
  document.addEventListener("click", function (e) {
    const el = e.target.closest("[data-confirm]");
    if (!el) return;
    const msg = el.getAttribute("data-confirm") || "Confirmer ?";
    if (!confirm(msg)) e.preventDefault();
  });

  // Confirmation aussi au clavier (Enter/Espace) sur liens/boutons focus
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" && e.key !== " ") return;
    const el = document.activeElement && document.activeElement.closest
      ? document.activeElement.closest("[data-confirm]")
      : null;
    if (!el) return;
    const msg = el.getAttribute("data-confirm") || "Confirmer ?";
    if (!confirm(msg)) e.preventDefault();
  });

  // Auto-hide toasts (uniquement ceux marqués data-autohide)
  const reduceMotion =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function hideToast(t) {
    if (!t || t.dataset.hiding === "1") return;
    t.dataset.hiding = "1";

    if (reduceMotion) {
      t.remove();
      return;
    }
    t.style.opacity = "0";
    t.style.transform = "translateY(-6px)";
    t.style.transition = "all .25s ease";
    setTimeout(() => t.remove(), 350);
  }

  setTimeout(() => {
    document.querySelectorAll(".toast[data-autohide='true']").forEach((t) => {
      // pause au hover/focus (lisible)
      let timer = setTimeout(() => hideToast(t), 0);

      const pause = () => {
        if (timer) clearTimeout(timer);
        timer = null;
      };
      const resume = () => {
        if (!timer) timer = setTimeout(() => hideToast(t), 800);
      };

      t.addEventListener("mouseenter", pause);
      t.addEventListener("mouseleave", resume);
      t.addEventListener("focusin", pause);
      t.addEventListener("focusout", resume);
    });

    // lancer le hide réel après 4.5s
    document.querySelectorAll(".toast[data-autohide='true']").forEach((t) => {
      if (!t.matches(":hover") && !t.contains(document.activeElement)) {
        setTimeout(() => hideToast(t), 4500);
      } else {
        setTimeout(() => hideToast(t), 5300);
      }
    });
  }, 0);
})();
