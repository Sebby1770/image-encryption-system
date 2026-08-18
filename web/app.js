const enc = new TextEncoder();
const dec = new TextDecoder();
const STORE = "ies.vault.v1";

const state = {
  user: null,
  q: "",
  favoritesOnly: false,
};

function load() {
  try {
    return JSON.parse(localStorage.getItem(STORE) || '{"users":{},"assets":[],"links":[],"audit":[]}');
  } catch {
    return { users: {}, assets: [], links: [], audit: [] };
  }
}

function save(db) {
  localStorage.setItem(STORE, JSON.stringify(db));
}

function b64(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = "";
  bytes.forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s);
}

function unb64(text) {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(passphrase, salt) {
  const material = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function wrapKey(dataKeyBytes, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const wrapping = await deriveKey(passphrase, salt);
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, wrapping, dataKeyBytes);
  return { salt: b64(salt), nonce: b64(nonce), wrapped: b64(wrapped) };
}

async function unwrapKey(wrap, passphrase) {
  const wrapping = await deriveKey(passphrase, unb64(wrap.salt));
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(wrap.nonce) },
    wrapping,
    unb64(wrap.wrapped),
  );
  return new Uint8Array(raw);
}

async function encryptBytes(plain, passphrase) {
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", dataKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain);
  return {
    version: 1,
    algorithm: "AES-GCM",
    image_nonce: b64(nonce),
    key_wrap: await wrapKey(dataKey, passphrase),
    ciphertext: b64(ciphertext),
    ciphertext_sha256: await sha256Hex(ciphertext),
  };
}

async function decryptRecord(record, passphrase, wrapOverride) {
  const wrap = wrapOverride || record.key_wrap;
  const dataKey = await unwrapKey(wrap, passphrase);
  const key = await crypto.subtle.importKey("raw", dataKey, "AES-GCM", false, ["decrypt"]);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(record.image_nonce) }, key, unb64(record.ciphertext));
}

async function sha256Hex(buf) {
  const hash = await crypto.subtle.digest("SHA-256", buf instanceof ArrayBuffer ? buf : new Uint8Array(buf));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function audit(action, filename) {
  const db = load();
  db.audit.unshift({
    at: new Date().toISOString(),
    user: state.user && state.user.username,
    action,
    filename: filename || "",
  });
  db.audit = db.audit.slice(0, 200);
  save(db);
}

function $(id) { return document.getElementById(id); }

function show(view) {
  ["auth", "vault", "audit", "link"].forEach((name) => {
    const el = $(`view-${name}`);
    if (el) el.hidden = name !== view;
  });
}

function refreshChrome() {
  const authed = Boolean(state.user);
  $("nav-authed").hidden = !authed;
  $("btn-signout").hidden = !authed;
  $("who").textContent = authed ? state.user.username : "";
}

function renderVault() {
  const db = load();
  const mine = db.assets.filter((a) => a.user === state.user.username);
  const q = state.q.trim().toLowerCase();
  const shown = mine.filter((a) => {
    if (state.favoritesOnly && !a.favorite) return false;
    if (!q) return true;
    return `${a.filename} ${a.notes}`.toLowerCase().includes(q);
  });
  $("m-count").textContent = String(mine.length);
  $("m-fav").textContent = String(mine.filter((a) => a.favorite).length);
  $("asset-list").innerHTML = shown.map((a) => `
    <article class="card" data-id="${a.id}">
      <div>
        <h3>${escapeHtml(a.filename)}${a.favorite ? " ★" : ""}</h3>
        <p>${a.width}×${a.height} · ${a.algorithm} · ${a.created_at.slice(0, 19)}</p>
        ${a.notes ? `<p>${escapeHtml(a.notes)}</p>` : ""}
      </div>
      <div class="actions">
        <button class="btn" data-act="preview">Decrypt</button>
        <button class="btn" data-act="export">.ies.json</button>
        <button class="btn" data-act="link">Link</button>
        <button class="btn" data-act="fav">${a.favorite ? "Unstar" : "Star"}</button>
        <button class="btn danger" data-act="delete">Delete</button>
      </div>
    </article>
  `).join("") || `<div class="panel"><h3>No encrypted images match</h3><p class="hint">Upload a photo to create ciphertext.</p></div>`;
}

function renderAudit() {
  const db = load();
  const rows = db.audit.filter((e) => e.user === state.user.username);
  $("audit-body").innerHTML = rows.map((e) =>
    `<tr><td>${escapeHtml(e.at.slice(0, 19))}</td><td>${escapeHtml(e.action)}</td><td>${escapeHtml(e.filename || "—")}</td></tr>`
  ).join("") || `<tr><td colspan="3">No events yet.</td></tr>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

async function openAccount(username, passphrase, create) {
  const db = load();
  const key = username.trim().toLowerCase();
  if (!key || passphrase.length < 8) throw new Error("Username and an 8+ character passphrase are required.");
  if (create) {
    if (db.users[key]) throw new Error("That username is already registered.");
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const verify = await wrapKey(enc.encode("ies-ok"), passphrase);
    db.users[key] = { username: key, salt, verify, created_at: new Date().toISOString() };
    save(db);
  }
  const user = db.users[key];
  if (!user) throw new Error("No account with that username.");
  await unwrapKey(user.verify, passphrase);
  state.user = { username: key, passphrase };
  audit(create ? "register" : "login");
  refreshChrome();
  show("vault");
  renderVault();
}

async function handleEncrypt(event) {
  event.preventDefault();
  const form = event.target;
  const file = form.image.files[0];
  if (!file) return;
  const bytes = await file.arrayBuffer();
  const bitmap = await createImageBitmap(file);
  const packed = await encryptBytes(bytes, state.user.passphrase);
  const db = load();
  db.assets.unshift({
    id: crypto.randomUUID(),
    user: state.user.username,
    filename: file.name,
    notes: form.notes.value.trim(),
    favorite: form.favorite.checked,
    width: bitmap.width,
    height: bitmap.height,
    mime: file.type || "application/octet-stream",
    created_at: new Date().toISOString(),
    ...packed,
  });
  save(db);
  audit("upload", file.name);
  form.reset();
  $("enc-msg").textContent = "Image encrypted. Only ciphertext is stored.";
  renderVault();
}

async function handleAssetClick(event) {
  const btn = event.target.closest("button[data-act]");
  const card = event.target.closest("[data-id]");
  if (!btn || !card) return;
  const db = load();
  const asset = db.assets.find((a) => a.id === card.dataset.id);
  if (!asset) return;
  try {
    if (btn.dataset.act === "preview") {
      const plain = await decryptRecord(asset, state.user.passphrase);
      const blob = new Blob([plain], { type: asset.mime });
      $("preview-img").src = URL.createObjectURL(blob);
      $("preview-name").textContent = asset.filename;
      $("preview-modal").showModal();
      audit("decrypt", asset.filename);
    } else if (btn.dataset.act === "export") {
      const blob = new Blob([JSON.stringify(asset, null, 2)], { type: "application/json" });
      download(blob, `${asset.filename}.ies.json`);
    } else if (btn.dataset.act === "link") {
      const token = [...crypto.getRandomValues(new Uint8Array(24))].map((b) => b.toString(16).padStart(2, "0")).join("");
      const dataKey = await unwrapKey(asset.key_wrap, state.user.passphrase);
      const wrap = await wrapKey(dataKey, token);
      db.links.push({ token, asset_id: asset.id, wrap, created_at: new Date().toISOString() });
      save(db);
      audit("link", asset.filename);
      const url = `${location.origin}${location.pathname}#link=${token}`;
      await navigator.clipboard.writeText(url).catch(() => {});
      alert(`Capability link copied (shown once):\n${url}`);
    } else if (btn.dataset.act === "fav") {
      asset.favorite = !asset.favorite;
      save(db);
      renderVault();
    } else if (btn.dataset.act === "delete") {
      db.assets = db.assets.filter((a) => a.id !== asset.id);
      save(db);
      audit("delete", asset.filename);
      renderVault();
    }
  } catch (err) {
    alert(err.message || "That action failed.");
  }
}

function download(blob, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
}

async function openLink(token) {
  show("link");
  refreshChrome();
  const db = load();
  const link = db.links.find((l) => l.token === token);
  const asset = link && db.assets.find((a) => a.id === link.asset_id);
  if (!asset) {
    $("link-title").textContent = "Link not found";
    $("link-meta").textContent = "This capability token is unknown in this browser profile.";
    $("btn-link-decrypt").hidden = true;
    return;
  }
  $("btn-link-decrypt").hidden = false;
  $("link-title").textContent = asset.filename;
  $("link-meta").textContent = `${asset.width}×${asset.height} · AES-GCM · anyone with this URL hash can unwrap the data key.`;
  $("btn-link-decrypt").onclick = async () => {
    try {
      const plain = await decryptRecord(asset, token, link.wrap);
      download(new Blob([plain], { type: asset.mime }), asset.filename);
      $("link-msg").textContent = "Decrypted in this tab. Nothing was uploaded.";
    } catch (err) {
      $("link-msg").textContent = err.message || "Decrypt failed.";
    }
  };
}

function boot() {
  $("form-auth").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("auth-msg").textContent = "";
    try {
      await openAccount(event.target.username.value, event.target.passphrase.value, false);
    } catch (err) {
      $("auth-msg").textContent = err.message;
    }
  });
  $("btn-register").addEventListener("click", async () => {
    const form = $("form-auth");
    $("auth-msg").textContent = "";
    try {
      await openAccount(form.username.value, form.passphrase.value, true);
    } catch (err) {
      $("auth-msg").textContent = err.message;
    }
  });
  $("btn-signout").addEventListener("click", () => {
    state.user = null;
    refreshChrome();
    show("auth");
  });
  $("form-encrypt").addEventListener("submit", (event) => {
    handleEncrypt(event).catch((err) => { $("enc-msg").textContent = err.message; });
  });
  $("asset-list").addEventListener("click", handleAssetClick);
  $("filter-q").addEventListener("input", (event) => { state.q = event.target.value; renderVault(); });
  $("filter-fav").addEventListener("change", (event) => { state.favoritesOnly = event.target.checked; renderVault(); });
  document.querySelectorAll("[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.view === "audit") { show("audit"); renderAudit(); }
      else { show("vault"); renderVault(); }
    });
  });

  const hash = new URLSearchParams(location.hash.replace(/^#/, ""));
  const token = hash.get("link");
  if (token) openLink(token);
  else show("auth");
}

boot();
