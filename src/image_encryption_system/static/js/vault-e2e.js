// End-to-end mode on the dashboard: images are encrypted, decrypted, shared,
// linked, and re-wrapped here, so the server only ever receives ciphertext and
// key wraps it cannot open. Loaded as a module; dashboard.js still drives the
// server-mode forms.
import * as ies from "./ies-crypto.js";
import { BROWSER_FORMATS, ImageError, prepareImage, sniffFormat } from "./ies-image.js";

// ---------------------------------------------------------------------------
// Plumbing

function installScryptWorker() {
  let worker;
  try {
    worker = new Worker(new URL("./scrypt-worker.js", import.meta.url), { type: "module" });
  } catch {
    return; // stays on the main thread
  }
  const pending = new Map();
  let next = 0;
  worker.addEventListener("message", (event) => {
    const { id, key, error } = event.data;
    const job = pending.get(id);
    pending.delete(id);
    if (!job) return;
    if (error) job.reject(new ies.CryptoError(error));
    else job.resolve(new Uint8Array(key));
  });
  worker.addEventListener("error", () => {
    // The worker could not start (old browser, blocked module workers): run
    // anything in flight, and everything after, on the main thread instead.
    ies.setScryptImplementation(null);
    for (const job of pending.values()) {
      ies.scryptRaw(...job.args).then(job.resolve, job.reject);
    }
    pending.clear();
  });
  ies.setScryptImplementation(
    (password, salt, n, r, p, length) =>
      new Promise((resolve, reject) => {
        const id = next;
        next += 1;
        pending.set(id, { resolve, reject, args: [password.slice(), salt, n, r, p, length] });
        worker.postMessage({ id, password, salt, n, r, p, length });
      }),
  );
}

const statusLine = document.querySelector("#e2e-status");

function status(message, kind = "info") {
  if (!statusLine) return;
  statusLine.hidden = !message;
  statusLine.textContent = message || "";
  statusLine.dataset.kind = kind;
}

function explain(error) {
  if (error instanceof ImageError || error instanceof ies.CryptoError) return error.message;
  return error && error.message ? error.message : String(error);
}

// Runs one end-to-end operation with progress in the status line, keeping the
// triggering button disabled so a double click cannot start two.
async function busy(button, work) {
  if (button) button.disabled = true;
  try {
    return await work();
  } catch (error) {
    status(explain(error), "error");
    throw error;
  } finally {
    if (button) button.disabled = false;
  }
}

async function readJSON(response) {
  let data = {};
  try {
    data = await response.json();
  } catch {
    // fall through to the status-based message
  }
  if (!response.ok) throw new Error(data.error || `The server refused the request (${response.status}).`);
  return data;
}

function getJSON(config, url) {
  return fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } }).then(readJSON);
}

function postJSON(config, url, body) {
  return fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": config.csrf,
    },
    body: JSON.stringify(body || {}),
  }).then(readJSON);
}

async function fetchSealed(assetId) {
  const response = await fetch(`/images/${encodeURIComponent(assetId)}/sealed`, {
    credentials: "same-origin",
  });
  if (!response.ok) await readJSON(response);
  return ies.unpackIES(new Uint8Array(await response.arrayBuffer()));
}

// The account's private key is opened once per page and kept only as a
// non-extractable CryptoKey: script on this page can use it, never read it.
let accountKey = null;

async function unlockAccountKey(config, password) {
  if (accountKey) return accountKey;
  if (!password) throw new Error("Enter your account password to unlock your private key.");
  const data = await postJSON(config, "/account/private-key");
  try {
    accountKey = await ies.openPrivateKey(data.private_key, password, { owner: config.userId });
  } catch (error) {
    if (error instanceof ies.CryptoError && /passphrase is invalid/.test(error.message)) {
      throw new Error("That is not your account password.");
    }
    throw error;
  }
  document.querySelectorAll("[data-account-secret]").forEach((input) => {
    input.required = false;
    input.placeholder = "Unlocked for this page";
  });
  return accountKey;
}

async function dataKeyFor(config, wrap, secret) {
  if (wrap && wrap.type === ies.WRAP_RSA) {
    return ies.unwrapDataKeyRSA(wrap, await unlockAccountKey(config, secret));
  }
  return ies.unwrapDataKeyPassphrase(wrap, secret);
}

function secretLabel(algorithm) {
  return algorithm === ies.RSA_HYBRID ? "Account password" : "AES passphrase";
}

// ---------------------------------------------------------------------------
// Upload

function setUpUpload(config) {
  const form = document.querySelector("#upload-form");
  const browserMode = document.querySelector("#mode-browser");
  const serverMode = document.querySelector("#mode-server");
  const note = document.querySelector("#mode-note");
  if (!form || !browserMode) return;

  const notes = {
    browser:
      "End-to-end: metadata is stripped and the image encrypted in this browser. " +
      "The server stores ciphertext it cannot open. TIFF needs server mode.",
    server: "Server mode: the image is sent to the server, stripped of metadata, and encrypted there.",
  };
  const sync = () => {
    note.textContent = browserMode.checked ? notes.browser : notes.server;
  };
  browserMode.disabled = false;
  browserMode.checked = true;
  browserMode.addEventListener("change", sync);
  serverMode.addEventListener("change", sync);
  sync();

  form.addEventListener("submit", async (event) => {
    if (!browserMode.checked) return; // plain form post, as before
    event.preventDefault();
    const button = form.querySelector("button[type=submit]");
    try {
      await busy(button, () => encryptAndUpload(config, form));
      window.location.reload();
    } catch {
      // already reported in the status line
    }
  });
}

async function encryptAndUpload(config, form) {
  const file = form.querySelector("input[name=image]").files[0];
  if (!file) throw new Error("Choose an image to encrypt.");
  // Leave room for the envelope and multipart framing under the request cap.
  if (file.size > config.maxBytes - 64 * 1024) {
    throw new Error(`File exceeds the ${Math.floor(config.maxBytes / 1048576)} MB upload limit.`);
  }
  const algorithm = form.querySelector("[name=algorithm]").value;
  const passphrase = form.querySelector("[name=passphrase]").value;
  if (algorithm === ies.AES_GCM_PASSPHRASE && !passphrase) {
    throw new Error("AES-GCM mode requires a passphrase.");
  }

  status("Stripping metadata in your browser…");
  const original = new Uint8Array(await file.arrayBuffer());
  let prepared = prepareImage(original);
  if (prepared.format === "JPEG" && prepared.orientation > 1) {
    prepared = await uprightJPEG(original);
  }
  await assertDecodes(prepared);
  if (prepared.width * prepared.height > config.maxPixels) {
    throw new ImageError(`Image is too large to process (over ${config.maxPixels.toLocaleString()} pixels).`);
  }

  let publicKey;
  if (algorithm === ies.RSA_HYBRID) {
    const own = await getJSON(config, `/users/${encodeURIComponent(config.username)}/public-key`);
    publicKey = own.public_key;
  }
  status("Deriving the key and encrypting…");
  const sealed = await ies.encryptImage(prepared.bytes, {
    algorithm,
    passphrase,
    publicKey,
    n: config.scryptN,
    context: {
      owner: config.userId,
      filename: Array.from(file.name).slice(0, 255).join(""),
      mime: prepared.mime,
      format: prepared.format,
      width: prepared.width,
      height: prepared.height,
      source: "browser",
    },
  });
  sealed.dataKey.fill(0);

  status("Uploading ciphertext…");
  const body = new FormData();
  body.append("csrf_token", config.csrf);
  body.append("envelope", JSON.stringify(sealed.metadata));
  body.append("ciphertext", new Blob([sealed.ciphertext], { type: "application/octet-stream" }), "sealed.bin");
  await fetch("/images/sealed", {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    body,
  }).then(readJSON);
  status("");
}

// A JPEG whose EXIF says "rotate me" loses that instruction when EXIF is
// stripped, so draw it upright and re-encode once, as the server does.
async function uprightJPEG(original) {
  const bitmap = await createImageBitmap(new Blob([original], { type: "image/jpeg" }), {
    imageOrientation: "from-image",
  });
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  canvas.getContext("2d").drawImage(bitmap, 0, 0);
  bitmap.close();
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.95));
  if (!blob) throw new ImageError("This JPEG could not be re-encoded upright.");
  return prepareImage(new Uint8Array(await blob.arrayBuffer()));
}

async function assertDecodes(prepared) {
  try {
    const bitmap = await createImageBitmap(new Blob([prepared.bytes], { type: prepared.mime }));
    bitmap.close();
  } catch {
    throw new ImageError("The image file is damaged or unreadable.");
  }
}

// ---------------------------------------------------------------------------
// Open (owner or share recipient)

function setUpOpen(config) {
  document.querySelectorAll("form.e2e-open").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button[type=submit]");
      const input = form.querySelector("input[name=secret]");
      try {
        await busy(button, async () => {
          status("Fetching ciphertext…");
          const { ciphertext, metadata } = await fetchSealed(form.dataset.e2eAsset);
          status("Unwrapping the key in your browser…");
          const dataKey = await dataKeyFor(config, metadata.key_wrap, input.value);
          const plaintext = await ies.decryptImage(ciphertext, metadata, dataKey);
          dataKey.fill(0);
          input.value = "";
          status("");
          showImage(plaintext, metadata.context);
        });
      } catch {
        // reported
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Viewer

const viewer = document.querySelector("#viewer");
let viewerURL = null;

function setUpViewer() {
  if (!viewer) return;
  viewer.querySelector("[data-close]").addEventListener("click", () => viewer.close());
  viewer.addEventListener("close", () => {
    const image = viewer.querySelector("#viewer-image");
    image.removeAttribute("src");
    if (viewerURL) URL.revokeObjectURL(viewerURL);
    viewerURL = null;
  });
}

// Shown only as the allow-listed type the bytes really are, the same rule the
// server applies before serving plaintext: an envelope cannot smuggle HTML or
// SVG into this origin by claiming to be a PNG.
function showImage(plaintext, context) {
  const format = sniffFormat(plaintext);
  const mime = BROWSER_FORMATS[format];
  if (!mime || format !== context.format) {
    throw new Error("Decrypted content is not the image type on record.");
  }
  if (viewerURL) URL.revokeObjectURL(viewerURL);
  viewerURL = URL.createObjectURL(new Blob([plaintext], { type: mime }));
  viewer.querySelector("#viewer-title").textContent = context.filename || "Decrypted image";
  const image = viewer.querySelector("#viewer-image");
  image.alt = context.filename || "Decrypted image";
  image.src = viewerURL;
  const save = viewer.querySelector("#viewer-save");
  save.href = viewerURL;
  save.download = context.filename || `image.${format.toLowerCase()}`;
  viewer.showModal();
}

// ---------------------------------------------------------------------------
// Share and link dialogs

function prepareDialog(dialog, button) {
  const form = dialog.querySelector("form");
  form.reset();
  form.dataset.assetId = button.dataset.assetId;
  dialog.querySelectorAll("[data-filename]").forEach((node) => {
    node.textContent = button.dataset.filename;
  });
  dialog.querySelector("[data-secret-label]").textContent = secretLabel(button.dataset.algorithm);
  const secret = form.querySelector("input[name=secret]");
  const rsa = button.dataset.algorithm === ies.RSA_HYBRID;
  secret.required = !(rsa && accountKey);
  secret.placeholder = rsa && accountKey ? "Unlocked for this page" : "";
  secret.autocomplete = rsa ? "current-password" : "off";
  const result = dialog.querySelector("[data-result]");
  if (result) result.hidden = true;
  const output = dialog.querySelector("[data-link-output]");
  if (output) output.hidden = true;
  dialog.querySelector("[data-submit]").hidden = false;
  dialog.showModal();
  return form;
}

function optionalNumber(value) {
  const text = String(value || "").trim();
  return text ? Number(text) : undefined;
}

function setUpShare(config) {
  const dialog = document.querySelector("#e2e-share-modal");
  if (!dialog) return;
  const form = dialog.querySelector("form");
  let changed = false;
  dialog.querySelector("[data-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => {
    if (changed) window.location.reload();
  });
  document.querySelectorAll(".e2e-share-open").forEach((button) => {
    button.addEventListener("click", () => prepareDialog(dialog, button));
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = dialog.querySelector("[data-submit]");
    const fields = new FormData(form);
    const username = String(fields.get("username") || "").trim().toLowerCase();
    try {
      await busy(submit, async () => {
        status("Unwrapping the key in your browser…");
        const { metadata } = await fetchSealed(form.dataset.assetId);
        const dataKey = await dataKeyFor(config, metadata.key_wrap, fields.get("secret"));
        status(`Fetching ${username}'s public key…`);
        const recipient = await getJSON(config, `/users/${encodeURIComponent(username)}/public-key`);
        const fingerprint = await ies.publicKeyFingerprint(recipient.public_key);
        const keyWrap = await ies.wrapDataKeyRSA(dataKey, recipient.public_key);
        dataKey.fill(0);
        const shared = await postJSON(config, `/images/${form.dataset.assetId}/shares/sealed`, {
          username,
          key_wrap: keyWrap,
          expires_hours: optionalNumber(fields.get("expires_hours")),
        });
        status("");
        changed = true;
        const result = dialog.querySelector("[data-result]");
        result.textContent =
          `Shared with ${shared.username}. Their key fingerprint is ${fingerprint}. ` +
          "Ask them to confirm it matches the one on their Account page.";
        result.hidden = false;
        submit.hidden = true;
        dialog.querySelector("[data-close]").textContent = "Done";
      });
    } catch {
      // reported
    }
  });
}

function setUpLink(config) {
  const dialog = document.querySelector("#e2e-link-modal");
  if (!dialog) return;
  const form = dialog.querySelector("form");
  let changed = false;
  dialog.querySelector("[data-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => {
    dialog.querySelector("[data-link-url]").value = "";
    if (changed) window.location.reload();
  });
  dialog.querySelector("[data-copy]").addEventListener("click", async () => {
    const field = dialog.querySelector("[data-link-url]");
    field.select();
    try {
      await navigator.clipboard.writeText(field.value);
      status("Link copied.");
    } catch {
      status("Select the link and copy it manually.");
    }
  });
  document.querySelectorAll(".e2e-link-open").forEach((button) => {
    button.addEventListener("click", () => {
      prepareDialog(dialog, button);
      dialog.querySelector("[data-close]").textContent = "Cancel";
    });
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = dialog.querySelector("[data-submit]");
    const fields = new FormData(form);
    try {
      await busy(submit, async () => {
        status("Unwrapping the key in your browser…");
        const { metadata } = await fetchSealed(form.dataset.assetId);
        const dataKey = await dataKeyFor(config, metadata.key_wrap, fields.get("secret"));
        // 256 random bits: Scrypt's cost adds nothing, so the floor is used.
        const linkSecret = ies.b64urlEncode(ies.randomBytes(32));
        const keyWrap = await ies.wrapDataKeyPassphrase(dataKey, linkSecret, { n: ies.MIN_SCRYPT_N });
        dataKey.fill(0);
        const link = await postJSON(config, `/images/${form.dataset.assetId}/links/sealed`, {
          key_wrap: keyWrap,
          expires_hours: optionalNumber(fields.get("expires_hours")),
          max_downloads: optionalNumber(fields.get("max_downloads")),
          label: String(fields.get("label") || ""),
        });
        status("");
        changed = true;
        dialog.querySelector("[data-link-url]").value = `${link.url}#${linkSecret}`;
        dialog.querySelector("[data-link-output]").hidden = false;
        submit.hidden = true;
        dialog.querySelector("[data-close]").textContent = "Done";
      });
    } catch {
      // reported
    }
  });
}

// ---------------------------------------------------------------------------
// Rotate a passphrase wrap

function setUpRotate(config) {
  document.querySelectorAll("form.e2e-rotate").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button[type=submit]");
      const fields = new FormData(form);
      try {
        await busy(button, async () => {
          status("Re-wrapping the key in your browser…");
          const { metadata } = await fetchSealed(form.dataset.e2eAsset);
          const dataKey = await ies.unwrapDataKeyPassphrase(metadata.key_wrap, fields.get("old_passphrase"));
          const keyWrap = await ies.wrapDataKeyPassphrase(dataKey, fields.get("new_passphrase"), {
            n: config.scryptN,
          });
          // The server cannot check a wrap it cannot open, and this replaces the
          // only primary wrap, so prove it opens before sending it.
          const check = await ies.unwrapDataKeyPassphrase(keyWrap, fields.get("new_passphrase"));
          if (ies.toHex(check) !== ies.toHex(dataKey)) throw new Error("The new wrap did not verify.");
          dataKey.fill(0);
          check.fill(0);
          await postJSON(config, `/images/${form.dataset.e2eAsset}/rewrap`, { key_wrap: keyWrap });
        });
        window.location.reload();
      } catch {
        // reported
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Start-up: last, so every module-level binding above is initialised first.

const root = document.querySelector("#vault");

if (root && globalThis.crypto && globalThis.crypto.subtle) {
  const config = {
    userId: Number(root.dataset.userId),
    username: root.dataset.username,
    scryptN: Number(root.dataset.scryptN) || ies.SCRYPT_N,
    maxBytes: Number(root.dataset.maxBytes),
    maxPixels: Number(root.dataset.maxPixels),
    csrf: root.dataset.csrf,
  };
  installScryptWorker();
  setUpViewer();
  setUpUpload(config);
  setUpOpen(config);
  setUpShare(config);
  setUpLink(config);
  setUpRotate(config);
  document.querySelectorAll(".e2e-share-open, .e2e-link-open").forEach((button) => {
    button.disabled = false;
  });
}
