// Shared page behaviour. Inline event handlers are blocked by the page CSP, so
// confirmation prompts are declared with data-confirm and wired up here.
document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });
});

// Registration password meter. Advisory only: security.validate_password is the
// enforcement point. It mirrors exactly the structural rules the server applies,
// so it never calls a password acceptable that the server will then reject.
const passwordInput = document.querySelector("#password-input");
const meterBar = document.querySelector("#password-meter-bar");
const meterLabel = document.querySelector("#password-meter-label");

if (passwordInput && meterBar && meterLabel) {
  const minLength = Number(passwordInput.getAttribute("minlength")) || 10;

  passwordInput.addEventListener("input", () => {
    const value = passwordInput.value;
    let score = 0;
    let label = "Enter a password";

    if (value.length > 0 && value.length < minLength) {
      label = `At least ${minLength} characters`;
    } else if (value.length > 0 && new Set(value).size < 5) {
      score = 1;
      label = "Use at least five different characters";
    } else if (value.length > 0) {
      score = 1;
      if (value.length >= 14) score += 1;
      if (value.length >= 20) score += 1;
      if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1;
      if (/\d/.test(value) && /[^A-Za-z0-9]/.test(value)) score += 1;
      label = ["Weak", "Fair", "Good", "Strong", "Excellent"][Math.min(score, 5) - 1];
    }

    meterBar.value = score;
    meterLabel.textContent = label;
  });
}
