// End-to-end capability links. The path token finds the link and counts the
// download; the key is the URL fragment, which the browser never sends, so the
// server hands over ciphertext it cannot open and decryption happens here.
import * as ies from "./ies-crypto.js";
import { BROWSER_FORMATS, sniffFormat } from "./ies-image.js";

const panel = document.querySelector("[data-e2e-link]");
const button = document.querySelector("#link-decrypt");
const statusLine = document.querySelector("#e2e-status");

function status(message, kind = "info") {
  statusLine.hidden = !message;
  statusLine.textContent = message || "";
  statusLine.dataset.kind = kind;
}

if (panel && button) {
  const secret = window.location.hash.slice(1);
  if (!secret) {
    button.disabled = true;
    status("This link is missing its key: the part after # was not included when it was copied.", "error");
  }
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      status("Fetching ciphertext…");
      const response = await fetch(panel.dataset.blobUrl, { credentials: "omit" });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || `The server refused the request (${response.status}).`);
      }
      const { ciphertext, metadata } = ies.unpackIES(new Uint8Array(await response.arrayBuffer()));
      status("Decrypting in this browser…");
      const dataKey = await ies.unwrapDataKeyPassphrase(metadata.key_wrap, secret);
      const plaintext = await ies.decryptImage(ciphertext, metadata, dataKey);
      dataKey.fill(0);
      const format = sniffFormat(plaintext);
      const mime = BROWSER_FORMATS[format];
      if (!mime || format !== metadata.context.format) {
        throw new Error("Decrypted content is not the image type on record.");
      }
      const url = URL.createObjectURL(new Blob([plaintext], { type: mime }));
      const image = document.querySelector("#link-image");
      image.src = url;
      image.alt = metadata.context.filename || "Shared image";
      const save = document.querySelector("#link-save");
      save.href = url;
      save.download = metadata.context.filename || `image.${format.toLowerCase()}`;
      document.querySelector("#link-result").hidden = false;
      status("Decrypted. Nothing was sent to the server but the request for ciphertext.");
    } catch (error) {
      const message =
        error instanceof ies.CryptoError && /did not unlock/.test(error.message)
          ? "This link's key does not open the image. Check that the whole link was copied."
          : error.message || String(error);
      status(message, "error");
      button.disabled = false;
    }
  });
}
