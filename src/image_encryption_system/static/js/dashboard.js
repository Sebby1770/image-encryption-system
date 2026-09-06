/**
 * Dashboard behaviour.
 *
 * This lives in a file rather than inline in the template so the app can serve
 * a Content-Security-Policy of `script-src 'self'` with no inline allowance and
 * no per-request nonce. An inline block would have required either
 * 'unsafe-inline', which defeats the policy, or nonce plumbing through every
 * render.
 */
const select = document.querySelector("#algorithm-select");
const passphrase = document.querySelector("#passphrase-field input");
const note = document.querySelector("#algorithm-note");
const modal = document.querySelector("#share-modal");
const shareForm = document.querySelector("#share-form");
const sharePassField = document.querySelector("#share-passphrase-field");
const shareRsaField = document.querySelector("#share-rsa-field");
const shareFilename = document.querySelector("#share-filename");

function syncAlgorithmFields() {
  if (select.value === "RSA-HYBRID") {
    passphrase.required = false;
    passphrase.disabled = true;
    passphrase.value = "";
    note.textContent = "RSA hybrid mode wraps the image data key with your account public key.";
  } else {
    passphrase.required = true;
    passphrase.disabled = false;
    note.textContent = "AES-GCM passphrase mode derives a key with Scrypt and wraps the image data key.";
  }
}

function openShareModal(button) {
  const assetId = button.dataset.assetId;
  const algorithm = button.dataset.algorithm;
  shareForm.action = `/images/${assetId}/share`;
  shareFilename.textContent = button.dataset.filename;
  const useRsa = algorithm === "RSA-HYBRID";
  sharePassField.hidden = useRsa;
  shareRsaField.hidden = !useRsa;
  sharePassField.querySelector("input").required = !useRsa;
  shareRsaField.querySelector("input").required = useRsa;
  sharePassField.querySelector("input").value = "";
  shareRsaField.querySelector("input").value = "";
  modal.showModal();
}

select.addEventListener("change", syncAlgorithmFields);
syncAlgorithmFields();

document.querySelectorAll(".share-open").forEach((button) => {
  button.addEventListener("click", () => openShareModal(button));
});
document.querySelector("#share-cancel").addEventListener("click", () => modal.close());

const linkModal = document.querySelector("#link-modal");
const linkForm = document.querySelector("#link-form");
const linkPassField = document.querySelector("#link-passphrase-field");
const linkRsaField = document.querySelector("#link-rsa-field");
const linkFilename = document.querySelector("#link-filename");

function openLinkModal(button) {
  const assetId = button.dataset.assetId;
  const algorithm = button.dataset.algorithm;
  linkForm.action = `/images/${assetId}/link`;
  linkFilename.textContent = button.dataset.filename;
  const useRsa = algorithm === "RSA-HYBRID";
  linkPassField.hidden = useRsa;
  linkRsaField.hidden = !useRsa;
  linkPassField.querySelector("input").required = !useRsa;
  linkRsaField.querySelector("input").required = useRsa;
  linkPassField.querySelector("input").value = "";
  linkRsaField.querySelector("input").value = "";
  linkModal.showModal();
}

document.querySelectorAll(".link-open").forEach((button) => {
  button.addEventListener("click", () => openLinkModal(button));
});
document.querySelector("#link-cancel").addEventListener("click", () => linkModal.close());
