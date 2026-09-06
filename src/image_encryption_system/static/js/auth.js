/**
 * Client-side echo of the server's password policy.
 *
 * Purely advisory: `security.validate_password` is the enforcement point, and
 * this only saves a round trip. The rules mirrored here are the structural ones,
 * so the meter never tells someone a password is fine that the server will then
 * reject.
 */
const passwordInput = document.querySelector("#password-input");
const meterBar = document.querySelector("#password-meter-bar");
const meterLabel = document.querySelector("#password-meter-label");
const minLength = Number(passwordInput?.getAttribute("minlength")) || 10;

function describe(value) {
  if (!value) return { score: 0, label: "Enter a password" };
  if (value.length < minLength) {
    return { score: 0, label: `At least ${minLength} characters` };
  }
  if (new Set(value).size < 5) {
    return { score: 1, label: "Use at least five different characters" };
  }

  let score = 1;
  if (value.length >= 14) score += 1;
  if (value.length >= 20) score += 1;
  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1;
  if (/\d/.test(value) && /[^A-Za-z0-9]/.test(value)) score += 1;

  const labels = ["Weak", "Fair", "Good", "Strong", "Excellent"];
  return { score, label: labels[Math.min(score - 1, labels.length - 1)] };
}

passwordInput?.addEventListener("input", () => {
  const { score, label } = describe(passwordInput.value);
  if (meterBar) meterBar.value = score;
  if (meterLabel) meterLabel.textContent = label;
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
