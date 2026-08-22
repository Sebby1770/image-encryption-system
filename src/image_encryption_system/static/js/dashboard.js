const algorithmSelect = document.querySelector("#algorithm-select");
const passphraseInput = document.querySelector("#passphrase-field input");
const algorithmNote = document.querySelector("#algorithm-note");
const dropTarget = document.querySelector("#drop-target");
const imageInput = document.querySelector("#image-input");

function syncAlgorithmFields() {
  if (!algorithmSelect || !passphraseInput || !algorithmNote) return;
  const rsaMode = algorithmSelect.value === "RSA-HYBRID";
  passphraseInput.required = !rsaMode;
  passphraseInput.disabled = rsaMode;
  if (rsaMode) passphraseInput.value = "";
  algorithmNote.textContent = rsaMode
    ? "RSA hybrid mode wraps the image data key with your account public key."
    : "AES-GCM passphrase mode derives a wrapping key with Scrypt.";
}

algorithmSelect?.addEventListener("change", syncAlgorithmFields);
syncAlgorithmFields();

["dragenter", "dragover"].forEach((eventName) => {
  dropTarget?.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropTarget.classList.add("dragover");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropTarget?.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropTarget.classList.remove("dragover");
  });
});

dropTarget?.addEventListener("drop", (event) => {
  const files = event.dataTransfer?.files;
  if (!files?.length || !imageInput) return;
  imageInput.files = files;
  const title = dropTarget.querySelector(".drop-title");
  if (title) title.textContent = files[0].name;
});

imageInput?.addEventListener("change", () => {
  const file = imageInput.files?.[0];
  const title = dropTarget?.querySelector(".drop-title");
  if (file && title) title.textContent = file.name;
});

const assetChecks = () =>
  Array.from(document.querySelectorAll('#bulk-form input[name="asset_ids"]'));

document.querySelector("#select-all")?.addEventListener("change", (event) => {
  assetChecks().forEach((checkbox) => {
    checkbox.checked = event.currentTarget.checked;
  });
});

document.querySelector("#bulk-tag-form")?.addEventListener("submit", (event) => {
  const form = event.currentTarget;
  form.querySelectorAll('input[data-selected-id="true"]').forEach((input) => input.remove());
  assetChecks()
    .filter((checkbox) => checkbox.checked)
    .forEach((checkbox) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "asset_ids";
      input.value = checkbox.value;
      input.dataset.selectedId = "true";
      form.appendChild(input);
    });
});

document.querySelectorAll("[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

document.querySelectorAll("[data-unlock]").forEach((node) => {
  const unlockAt = new Date(node.dataset.unlock);
  const tick = () => {
    const remaining = unlockAt.getTime() - Date.now();
    if (!Number.isFinite(remaining)) {
      node.textContent = "Lock metadata needs attention";
      return;
    }
    if (remaining <= 0) {
      node.textContent = "Unlock window open";
      return;
    }
    const hours = Math.floor(remaining / 3_600_000);
    const minutes = Math.floor((remaining % 3_600_000) / 60_000);
    const seconds = Math.floor((remaining % 60_000) / 1_000);
    node.textContent = `Locked · ${hours}h ${minutes}m ${seconds}s remaining`;
    window.setTimeout(tick, 1_000);
  };
  tick();
});

const previewModal = document.querySelector("#preview-modal");
const previewImage = document.querySelector("#preview-image");
const previewStatus = document.querySelector("#preview-status");
let previewUrl = null;
let previewBurnTimer = null;

function clearPreview() {
  if (previewBurnTimer) window.clearTimeout(previewBurnTimer);
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  previewImage?.removeAttribute("src");
  if (previewStatus) previewStatus.textContent = "Preview cleared from this page.";
}

document.querySelector("#close-preview")?.addEventListener("click", () => {
  clearPreview();
  previewModal?.close();
});

previewModal?.addEventListener("close", clearPreview);

document.querySelectorAll(".preview-form").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector(".preview-button");
    if (button) {
      button.disabled = true;
      button.textContent = "Decrypting…";
    }
    try {
      const response = await fetch(`/images/${form.dataset.assetId}/preview`, {
        method: "POST",
        body: new FormData(form),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || "Unable to decrypt preview.");
      }
      clearPreview();
      previewUrl = URL.createObjectURL(await response.blob());
      previewImage.src = previewUrl;
      if (previewStatus) previewStatus.textContent = "This preview clears automatically in 30 seconds.";
      previewModal.showModal();
      previewBurnTimer = window.setTimeout(() => {
        clearPreview();
        previewModal.close();
      }, 30_000);
    } catch (error) {
      window.alert(error.message);
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = "Preview in vault";
      }
      form.reset();
    }
  });
});
