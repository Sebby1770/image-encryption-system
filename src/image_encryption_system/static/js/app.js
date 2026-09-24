// Shared page behaviour. Inline event handlers are blocked by the page CSP, so
// confirmation prompts are declared with data-confirm and wired up here.
document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });
});
