(function () {
  const select = document.querySelector("#algorithm-select");
  const passphraseField = document.querySelector("#passphrase-field input");
  const note = document.querySelector("#algorithm-note");
  if (!select || !passphraseField || !note) {
    return;
  }

  function syncAlgorithmFields() {
    if (select.value === "RSA-HYBRID") {
      passphraseField.required = false;
      passphraseField.disabled = true;
      passphraseField.value = "";
      note.textContent = "RSA hybrid mode wraps the image data key with your account public key.";
    } else {
      passphraseField.required = true;
      passphraseField.disabled = false;
      note.textContent = "AES-GCM passphrase mode derives a key with Scrypt and wraps the image data key.";
    }
  }

  select.addEventListener("change", syncAlgorithmFields);
  syncAlgorithmFields();

  document.querySelectorAll(".js-delete-asset").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm("Delete this ciphertext permanently?")) {
        event.preventDefault();
      }
    });
  });
})();
