const passwordInput = document.querySelector("#password-input");
const meterBar = document.querySelector("#password-meter-bar");
const meterLabel = document.querySelector("#password-meter-label");

passwordInput?.addEventListener("input", () => {
  const value = passwordInput.value;
  let score = 0;
  if (value.length >= 10) score += 1;
  if (value.length >= 14) score += 1;
  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  const labels = ["Too short", "Fair", "Good", "Strong", "Excellent"];
  if (meterBar) meterBar.value = score;
  if (meterLabel) {
    meterLabel.textContent =
      value.length < 10
        ? "Enter at least 10 characters"
        : labels[Math.min(score, labels.length - 1)];
  }
});

document.querySelectorAll("[data-password-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.passwordToggle);
    if (!input) return;
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    button.textContent = reveal ? "Hide" : "Show";
    button.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
  });
});
