// Browser half of the vault's envelope crypto. Mirrors crypto.py byte for byte,
// so an envelope sealed here opens in the server, the `ies` CLI, and back again.
// No DOM access: the same module runs in pages, in the Scrypt worker, and under
// `node --test`.

const subtle = globalThis.crypto.subtle;

export const AES_GCM_PASSPHRASE = "AES-GCM";
export const RSA_HYBRID = "RSA-HYBRID";
export const WRAP_SCRYPT = "scrypt-aes-gcm";
export const WRAP_RSA = "rsa-oaep-sha256";
export const ENVELOPE_V3 = 3;
export const AES_KEY_BYTES = 32;
export const GCM_NONCE_BYTES = 12;
export const GCM_TAG_BYTES = 16;
export const SCRYPT_SALT_BYTES = 16;
export const SCRYPT_N = 2 ** 16;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
// Bounds mirror crypto._validate_scrypt_parameters. Wrap parameters arrive with
// the ciphertext, so a hostile blob must not be able to steer this tab into a
// multi-gigabyte allocation.
export const MIN_SCRYPT_N = 2 ** 14;
export const MAX_SCRYPT_WORK_FACTOR = 2 ** 22;
export const MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024;
export const MAX_PASSPHRASE_BYTES = 1024;
export const RSA_KEY_BITS = 3072;
export const IES_MAGIC = "IES1";
export const MAX_METADATA_BYTES = 64 * 1024;
export const MAX_CONTEXT_BYTES = 4096;
export const PRIVATE_KEY_FORMAT = "ies-private-key";

const CONTEXT_AAD_PREFIX = "IES-CONTEXT-V3\u0000";
const PRIVATE_KEY_AAD_PREFIX = "IES-PRIVATE-KEY-V1\u0000";
const DATA_KEY_AAD = "image-data-key";
const V3_ENVELOPE_KEYS = new Set([
  "version",
  "algorithm",
  "image_nonce",
  "key_wrap",
  "context",
  "ciphertext_sha256",
]);
const WRAP_KEYS = {
  [WRAP_SCRYPT]: ["n", "nonce", "p", "r", "salt", "type", "wrapped_key"],
  [WRAP_RSA]: ["type", "wrapped_key"],
};
const CONTEXT_KEYS = new Set([
  "asset",
  "algorithm",
  "wrap",
  "owner",
  "filename",
  "mime",
  "format",
  "width",
  "height",
  "source",
]);
const CONTEXT_SOURCES = new Set(["web", "cli", "browser"]);
const RSA_OAEP = { name: "RSA-OAEP", hash: "SHA-256" };

export class CryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = "CryptoError";
  }
}

// ---------------------------------------------------------------------------
// Encoding helpers

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(text) {
  return encoder.encode(text);
}

export function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function toHex(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function b64encode(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

// Strict, canonical base64, exactly like crypto._b64decode: no whitespace, no
// URL alphabet, and no stray bits in the final character, so no two distinct
// strings decode to the same bytes.
export function b64decode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4) {
    throw new CryptoError("Encrypted image metadata field is not valid base64.");
  }
  let binary;
  try {
    binary = atob(text);
  } catch {
    throw new CryptoError("Encrypted image metadata field is not valid base64.");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  if (b64encode(out) !== text) {
    throw new CryptoError("Encrypted image metadata field is not canonical base64.");
  }
  return out;
}

// URL-safe, unpadded: for secrets that travel in a link's #fragment.
export function b64urlEncode(bytes) {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) {
    throw new CryptoError("Link key is malformed.");
  }
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  return b64decode(padded + "=".repeat((4 - (padded.length % 4)) % 4));
}

// json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).
// JSON.stringify already escapes strings the way Python does with
// ensure_ascii=False; only key order and integer-only numbers need care.
export function canonicalJSON(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new CryptoError("Only integers are canonical.");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(compareCodePoints);
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  throw new CryptoError("Value cannot be canonically encoded.");
}

// Python sorts str keys by code point; JS sorts by UTF-16 unit. They differ only
// for astral characters, but the envelope is meant to be unambiguous.
function compareCodePoints(a, b) {
  const left = Array.from(a);
  const right = Array.from(b);
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    const diff = left[i].codePointAt(0) - right[i].codePointAt(0);
    if (diff) return diff;
  }
  return left.length - right.length;
}

export function contextAAD(context) {
  return utf8(CONTEXT_AAD_PREFIX + canonicalJSON(context));
}

export async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await subtle.digest("SHA-256", bytes)));
}

// ---------------------------------------------------------------------------
// Scrypt (RFC 7914). WebCrypto has no Scrypt, and the vault's envelopes are
// Scrypt-wrapped, so it is implemented here on top of WebCrypto's PBKDF2.

export function validateScryptParameters(n, r, p) {
  for (const value of [n, r, p]) {
    if (!Number.isSafeInteger(value)) throw new CryptoError("Scrypt parameters must be integers.");
  }
  if (n < MIN_SCRYPT_N || n > MAX_SCRYPT_WORK_FACTOR || n & (n - 1)) {
    throw new CryptoError("Scrypt work factor is outside the supported range.");
  }
  if (r < 1 || r > 32 || p < 1 || p > 16) {
    throw new CryptoError("Scrypt parameters are outside the supported range.");
  }
  if (128 * n * r > MAX_SCRYPT_MEMORY_BYTES) {
    throw new CryptoError("Scrypt parameters require too much memory.");
  }
  if (n * r * p > MAX_SCRYPT_WORK_FACTOR * SCRYPT_R) {
    throw new CryptoError("Scrypt parameters require too much work.");
  }
}

async function pbkdf2Sha256(password, salt, length) {
  const key = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 1 },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

function salsa208(B, x) {
  x.set(B);
  for (let i = 0; i < 8; i += 2) {
    let t;
    t = (x[0] + x[12]) | 0; x[4] ^= (t << 7) | (t >>> 25);
    t = (x[4] + x[0]) | 0; x[8] ^= (t << 9) | (t >>> 23);
    t = (x[8] + x[4]) | 0; x[12] ^= (t << 13) | (t >>> 19);
    t = (x[12] + x[8]) | 0; x[0] ^= (t << 18) | (t >>> 14);
    t = (x[5] + x[1]) | 0; x[9] ^= (t << 7) | (t >>> 25);
    t = (x[9] + x[5]) | 0; x[13] ^= (t << 9) | (t >>> 23);
    t = (x[13] + x[9]) | 0; x[1] ^= (t << 13) | (t >>> 19);
    t = (x[1] + x[13]) | 0; x[5] ^= (t << 18) | (t >>> 14);
    t = (x[10] + x[6]) | 0; x[14] ^= (t << 7) | (t >>> 25);
    t = (x[14] + x[10]) | 0; x[2] ^= (t << 9) | (t >>> 23);
    t = (x[2] + x[14]) | 0; x[6] ^= (t << 13) | (t >>> 19);
    t = (x[6] + x[2]) | 0; x[10] ^= (t << 18) | (t >>> 14);
    t = (x[15] + x[11]) | 0; x[3] ^= (t << 7) | (t >>> 25);
    t = (x[3] + x[15]) | 0; x[7] ^= (t << 9) | (t >>> 23);
    t = (x[7] + x[3]) | 0; x[11] ^= (t << 13) | (t >>> 19);
    t = (x[11] + x[7]) | 0; x[15] ^= (t << 18) | (t >>> 14);
    t = (x[0] + x[3]) | 0; x[1] ^= (t << 7) | (t >>> 25);
    t = (x[1] + x[0]) | 0; x[2] ^= (t << 9) | (t >>> 23);
    t = (x[2] + x[1]) | 0; x[3] ^= (t << 13) | (t >>> 19);
    t = (x[3] + x[2]) | 0; x[0] ^= (t << 18) | (t >>> 14);
    t = (x[5] + x[4]) | 0; x[6] ^= (t << 7) | (t >>> 25);
    t = (x[6] + x[5]) | 0; x[7] ^= (t << 9) | (t >>> 23);
    t = (x[7] + x[6]) | 0; x[4] ^= (t << 13) | (t >>> 19);
    t = (x[4] + x[7]) | 0; x[5] ^= (t << 18) | (t >>> 14);
    t = (x[10] + x[9]) | 0; x[11] ^= (t << 7) | (t >>> 25);
    t = (x[11] + x[10]) | 0; x[8] ^= (t << 9) | (t >>> 23);
    t = (x[8] + x[11]) | 0; x[9] ^= (t << 13) | (t >>> 19);
    t = (x[9] + x[8]) | 0; x[10] ^= (t << 18) | (t >>> 14);
    t = (x[15] + x[14]) | 0; x[12] ^= (t << 7) | (t >>> 25);
    t = (x[12] + x[15]) | 0; x[13] ^= (t << 9) | (t >>> 23);
    t = (x[13] + x[12]) | 0; x[14] ^= (t << 13) | (t >>> 19);
    t = (x[14] + x[13]) | 0; x[15] ^= (t << 18) | (t >>> 14);
  }
  for (let i = 0; i < 16; i += 1) B[i] = (B[i] + x[i]) | 0;
}

// BlockMix_{Salsa20/8, r}: B (2r 64-byte blocks, as words) -> Y, with Y's even
// blocks first and odd blocks second, as RFC 7914 section 4 specifies.
function blockMix(B, Y, r, X, scratch) {
  X.set(B.subarray((2 * r - 1) * 16, 2 * r * 16));
  for (let i = 0; i < 2 * r; i += 1) {
    for (let k = 0; k < 16; k += 1) X[k] ^= B[i * 16 + k];
    salsa208(X, scratch);
    Y.set(X, ((i & 1) * r + (i >> 1)) * 16);
  }
}

function roMix(block, n, r) {
  const words = 32 * r;
  let X = new Uint32Array(words);
  let Y = new Uint32Array(words);
  const V = new Uint32Array(words * n);
  const T = new Uint32Array(16);
  const scratch = new Uint32Array(16);
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  for (let k = 0; k < words; k += 1) X[k] = view.getUint32(k * 4, true);
  for (let i = 0; i < n; i += 1) {
    V.set(X, i * words);
    blockMix(X, Y, r, T, scratch);
    [X, Y] = [Y, X];
  }
  for (let i = 0; i < n; i += 1) {
    const j = X[(2 * r - 1) * 16] & (n - 1);
    const offset = j * words;
    for (let k = 0; k < words; k += 1) X[k] ^= V[offset + k];
    blockMix(X, Y, r, T, scratch);
    [X, Y] = [Y, X];
  }
  for (let k = 0; k < words; k += 1) view.setUint32(k * 4, X[k], true);
}

// Raw Scrypt with no vault policy applied; tests run it at RFC vector costs.
export async function scryptRaw(password, salt, n, r, p, length) {
  const blocks = await pbkdf2Sha256(password, salt, p * 128 * r);
  for (let i = 0; i < p; i += 1) roMix(blocks.subarray(i * 128 * r, (i + 1) * 128 * r), n, r);
  return pbkdf2Sha256(password, blocks, length);
}

let scryptOffload = null;

// Pages register a Worker-backed implementation so a 64 MiB, ~0.5 s derivation
// never freezes the UI. The worker runs scryptRaw from this same module.
export function setScryptImplementation(implementation) {
  scryptOffload = implementation;
}

export async function scrypt(passphrase, salt, n, r, p) {
  validateScryptParameters(n, r, p);
  const password = passphraseBytes(passphrase);
  if (scryptOffload) return scryptOffload(password, salt, n, r, p, AES_KEY_BYTES);
  return scryptRaw(password, salt, n, r, p, AES_KEY_BYTES);
}

function passphraseBytes(passphrase) {
  if (typeof passphrase !== "string" || !passphrase) {
    throw new CryptoError("A passphrase is required.");
  }
  const bytes = utf8(passphrase);
  if (bytes.length > MAX_PASSPHRASE_BYTES) throw new CryptoError("Passphrase is too long.");
  return bytes;
}

// ---------------------------------------------------------------------------
// AES-GCM and data-key wrapping

async function aesKey(raw, usages) {
  return subtle.importKey("raw", raw, "AES-GCM", false, usages);
}

async function aesGcmEncrypt(rawKey, nonce, plaintext, aad) {
  const key = await aesKey(rawKey, ["encrypt"]);
  const sealed = await subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
    key,
    plaintext,
  );
  return new Uint8Array(sealed);
}

async function aesGcmDecrypt(rawKey, nonce, ciphertext, aad, failure) {
  const key = await aesKey(rawKey, ["decrypt"]);
  try {
    const opened = await subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      ciphertext,
    );
    return new Uint8Array(opened);
  } catch {
    throw new CryptoError(failure);
  }
}

export function newDataKey() {
  return randomBytes(AES_KEY_BYTES);
}

export function newAssetId() {
  return toHex(randomBytes(16));
}

export async function wrapDataKeyPassphrase(dataKey, passphrase, { n = SCRYPT_N } = {}) {
  checkDataKey(dataKey);
  const salt = randomBytes(SCRYPT_SALT_BYTES);
  const wrappingKey = await scrypt(passphrase, salt, n, SCRYPT_R, SCRYPT_P);
  const nonce = randomBytes(GCM_NONCE_BYTES);
  const wrapped = await aesGcmEncrypt(wrappingKey, nonce, dataKey, utf8(DATA_KEY_AAD));
  return {
    type: WRAP_SCRYPT,
    salt: b64encode(salt),
    nonce: b64encode(nonce),
    wrapped_key: b64encode(wrapped),
    n,
    r: SCRYPT_R,
    p: SCRYPT_P,
  };
}

export async function unwrapDataKeyPassphrase(wrap, passphrase) {
  validateKeyWrap(wrap);
  if (wrap.type !== WRAP_SCRYPT) throw new CryptoError("This image is not passphrase-wrapped.");
  const wrappingKey = await scrypt(passphrase, b64decode(wrap.salt), wrap.n, wrap.r, wrap.p);
  return aesGcmDecrypt(
    wrappingKey,
    b64decode(wrap.nonce),
    b64decode(wrap.wrapped_key),
    utf8(DATA_KEY_AAD),
    "Passphrase did not unlock this image.",
  );
}

export async function importPublicKey(pem) {
  const key = await subtle
    .importKey("spki", pemBody(pem, "PUBLIC KEY"), RSA_OAEP, true, ["encrypt"])
    .catch(() => {
      throw new CryptoError("RSA public key could not be parsed.");
    });
  if (key.algorithm.modulusLength !== RSA_KEY_BITS) {
    throw new CryptoError(`Vault keys are RSA-${RSA_KEY_BITS}.`);
  }
  return key;
}

export async function wrapDataKeyRSA(dataKey, publicKey) {
  checkDataKey(dataKey);
  const key = typeof publicKey === "string" ? await importPublicKey(publicKey) : publicKey;
  const wrapped = new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, key, dataKey));
  return { type: WRAP_RSA, wrapped_key: b64encode(wrapped) };
}

export async function unwrapDataKeyRSA(wrap, privateKey) {
  validateKeyWrap(wrap);
  if (wrap.type !== WRAP_RSA) throw new CryptoError("This image is not RSA-wrapped.");
  try {
    const opened = await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, b64decode(wrap.wrapped_key));
    return checkDataKey(new Uint8Array(opened));
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError("RSA key unwrap failed.");
  }
}

// Unwraps with whichever secret matches the wrap: a passphrase string for a
// Scrypt wrap, an opened private CryptoKey for an RSA wrap.
export async function unwrapDataKey(wrap, secret) {
  if (wrap && wrap.type === WRAP_RSA) return unwrapDataKeyRSA(wrap, secret);
  return unwrapDataKeyPassphrase(wrap, secret);
}

function checkDataKey(dataKey) {
  if (!(dataKey instanceof Uint8Array) || dataKey.length !== AES_KEY_BYTES) {
    throw new CryptoError("Refusing to wrap a data key of unexpected length.");
  }
  return dataKey;
}

// Structure and lengths of a key wrap, without unwrapping it. Same rules the
// server applies to wraps a browser hands it (crypto.validate_key_wrap).
export function validateKeyWrap(wrap) {
  if (!wrap || typeof wrap !== "object" || !(wrap.type in WRAP_KEYS)) {
    throw new CryptoError("Encrypted image key wrapping metadata is invalid.");
  }
  const keys = Object.keys(wrap).sort();
  if (keys.join(",") !== WRAP_KEYS[wrap.type].join(",")) {
    throw new CryptoError("Encrypted image key wrapping metadata has unexpected fields.");
  }
  if (wrap.type === WRAP_RSA) {
    if (b64decode(wrap.wrapped_key).length !== RSA_KEY_BITS / 8) {
      throw new CryptoError("Wrapped data key has an invalid length.");
    }
    return;
  }
  validateScryptParameters(wrap.n, wrap.r, wrap.p);
  if (b64decode(wrap.salt).length !== SCRYPT_SALT_BYTES) {
    throw new CryptoError("Scrypt salt has an invalid length.");
  }
  if (b64decode(wrap.nonce).length !== GCM_NONCE_BYTES) {
    throw new CryptoError("Wrapping nonce has an invalid length.");
  }
  if (b64decode(wrap.wrapped_key).length !== AES_KEY_BYTES + GCM_TAG_BYTES) {
    throw new CryptoError("Wrapped data key has an invalid length.");
  }
}

// ---------------------------------------------------------------------------
// Envelopes

// Version 3 envelope, as crypto.encrypt_image_bytes writes it, plus the
// ciphertext digest the server checks on upload. Returns the data key too, so
// the caller can create shares or links without unwrapping again.
export async function encryptImage(plaintext, { algorithm, passphrase, publicKey, context, n }) {
  if (!(plaintext instanceof Uint8Array) || !plaintext.length) {
    throw new CryptoError("Image bytes cannot be empty.");
  }
  if (algorithm !== AES_GCM_PASSPHRASE && algorithm !== RSA_HYBRID) {
    throw new CryptoError(`Unsupported algorithm: ${algorithm}`);
  }
  const sealed = { asset: newAssetId(), ...context };
  sealed.algorithm = algorithm;
  sealed.wrap = algorithm === AES_GCM_PASSPHRASE ? WRAP_SCRYPT : WRAP_RSA;
  validateContext(sealed, algorithm);

  const dataKey = newDataKey();
  const keyWrap =
    algorithm === AES_GCM_PASSPHRASE
      ? await wrapDataKeyPassphrase(dataKey, passphrase, { n: n ?? SCRYPT_N })
      : await wrapDataKeyRSA(dataKey, publicKey);
  const imageNonce = randomBytes(GCM_NONCE_BYTES);
  const ciphertext = await aesGcmEncrypt(dataKey, imageNonce, plaintext, contextAAD(sealed));
  const metadata = {
    version: ENVELOPE_V3,
    algorithm,
    image_nonce: b64encode(imageNonce),
    key_wrap: keyWrap,
    context: sealed,
    ciphertext_sha256: await sha256Hex(ciphertext),
  };
  return { ciphertext, metadata, dataKey };
}

// Version 3 only: the browser never needs the legacy path, and refusing it
// keeps every envelope it opens fully sealed.
export async function decryptImage(ciphertext, metadata, dataKey) {
  validateEnvelope(metadata);
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < GCM_TAG_BYTES) {
    throw new CryptoError("Encrypted image ciphertext is truncated.");
  }
  if (metadata.ciphertext_sha256 !== undefined) {
    if ((await sha256Hex(ciphertext)) !== metadata.ciphertext_sha256) {
      throw new CryptoError("Ciphertext integrity check failed.");
    }
  }
  return aesGcmDecrypt(
    dataKey,
    b64decode(metadata.image_nonce),
    ciphertext,
    contextAAD(metadata.context),
    "Decryption failed. The key, passphrase, or ciphertext is invalid.",
  );
}

export function validateEnvelope(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new CryptoError("Encrypted image metadata must be an object.");
  }
  if (metadata.version !== ENVELOPE_V3) {
    throw new CryptoError("Only version 3 envelopes can be opened in the browser.");
  }
  for (const key of Object.keys(metadata)) {
    if (!V3_ENVELOPE_KEYS.has(key)) {
      throw new CryptoError("Encrypted image metadata has unexpected fields.");
    }
  }
  const { algorithm } = metadata;
  if (algorithm !== AES_GCM_PASSPHRASE && algorithm !== RSA_HYBRID) {
    throw new CryptoError("Encrypted image algorithm is not supported.");
  }
  if (b64decode(metadata.image_nonce).length !== GCM_NONCE_BYTES) {
    throw new CryptoError("Encrypted image nonce has an invalid length.");
  }
  validateKeyWrap(metadata.key_wrap);
  const digest = metadata.ciphertext_sha256;
  if (digest !== undefined && (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest))) {
    throw new CryptoError("Encrypted image ciphertext digest is malformed.");
  }
  validateContext(metadata.context, algorithm);
}

export function validateContext(context, algorithm) {
  if (!context || typeof context !== "object" || Array.isArray(context)) {
    throw new CryptoError("Encrypted image context is missing.");
  }
  for (const key of Object.keys(context)) {
    if (!CONTEXT_KEYS.has(key)) throw new CryptoError("Encrypted image context has unexpected fields.");
  }
  if (typeof context.asset !== "string" || !/^[0-9a-f]{32}$/.test(context.asset)) {
    throw new CryptoError("Encrypted image context has an invalid asset id.");
  }
  if (context.algorithm !== algorithm) {
    throw new CryptoError("Encrypted image context does not match its algorithm.");
  }
  if (context.wrap !== WRAP_SCRYPT && context.wrap !== WRAP_RSA) {
    throw new CryptoError("Encrypted image context has an invalid wrap type.");
  }
  for (const key of ["owner", "width", "height"]) {
    if (key in context) {
      const value = context[key];
      if (!Number.isSafeInteger(value) || value < 1 || value >= 2 ** 31) {
        throw new CryptoError(`Encrypted image context has an invalid ${key}.`);
      }
    }
  }
  for (const [key, limit] of [["filename", 255], ["mime", 100], ["format", 16]]) {
    if (key in context && (typeof context[key] !== "string" || Array.from(context[key]).length > limit)) {
      throw new CryptoError(`Encrypted image context has an invalid ${key}.`);
    }
  }
  if ("source" in context && !CONTEXT_SOURCES.has(context.source)) {
    throw new CryptoError("Encrypted image context has an invalid source.");
  }
  if (contextAAD(context).length > MAX_CONTEXT_BYTES) {
    throw new CryptoError("Encrypted image context is too large.");
  }
}

// b"IES1" | uint32 big-endian metadata length | metadata JSON | ciphertext
export function packIES(ciphertext, metadata) {
  const meta = utf8(canonicalJSON(metadata));
  const header = new Uint8Array(8);
  header.set(utf8(IES_MAGIC));
  new DataView(header.buffer).setUint32(4, meta.length, false);
  return concatBytes(header, meta, ciphertext);
}

export function unpackIES(blob) {
  if (!(blob instanceof Uint8Array) || blob.length < 8 || decoderLatin1(blob.subarray(0, 4)) !== IES_MAGIC) {
    throw new CryptoError("Not a valid IES vault file.");
  }
  const length = new DataView(blob.buffer, blob.byteOffset, blob.byteLength).getUint32(4, false);
  if (length > MAX_METADATA_BYTES) throw new CryptoError("IES vault file metadata is too large.");
  if (length < 2 || 8 + length > blob.length) throw new CryptoError("IES vault file metadata is truncated.");
  let metadata;
  try {
    metadata = JSON.parse(decoder.decode(blob.subarray(8, 8 + length)));
  } catch {
    throw new CryptoError("IES vault file metadata is invalid.");
  }
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new CryptoError("IES vault file metadata is invalid.");
  }
  return { ciphertext: blob.slice(8 + length), metadata };
}

function decoderLatin1(bytes) {
  return String.fromCharCode(...bytes);
}

// ---------------------------------------------------------------------------
// Account private keys (crypto.wrap_private_key's format)

export async function openPrivateKey(sealed, passphrase, { owner } = {}) {
  const wrapped = typeof sealed === "string" ? JSON.parse(sealed) : sealed;
  const required = ["ciphertext", "format", "kdf", "nonce", "version"];
  const keys = Object.keys(wrapped || {}).sort();
  const expected = "owner" in (wrapped || {}) ? [...required, "owner"].sort() : required;
  if (keys.join(",") !== expected.join(",")) {
    throw new CryptoError("Private key file has an unexpected structure.");
  }
  if (wrapped.format !== PRIVATE_KEY_FORMAT || wrapped.version !== 1) {
    throw new CryptoError("Private key file format is not supported.");
  }
  if (owner !== undefined && wrapped.owner !== owner) {
    throw new CryptoError("This private key does not belong to this account.");
  }
  const { kdf } = wrapped;
  if (!kdf || Object.keys(kdf).sort().join(",") !== "n,p,r,salt,type" || kdf.type !== "scrypt") {
    throw new CryptoError("Private key file KDF is not supported.");
  }
  const salt = b64decode(kdf.salt);
  if (salt.length !== SCRYPT_SALT_BYTES) throw new CryptoError("Scrypt salt has an invalid length.");
  if (b64decode(wrapped.nonce).length !== GCM_NONCE_BYTES) {
    throw new CryptoError("Private key nonce has an invalid length.");
  }
  const header = { format: wrapped.format, version: wrapped.version, kdf };
  if ("owner" in wrapped) header.owner = wrapped.owner;
  const wrappingKey = await scrypt(passphrase, salt, kdf.n, kdf.r, kdf.p);
  const der = await aesGcmDecrypt(
    wrappingKey,
    b64decode(wrapped.nonce),
    b64decode(wrapped.ciphertext),
    utf8(PRIVATE_KEY_AAD_PREFIX + canonicalJSON(header)),
    "Private key passphrase is invalid.",
  );
  try {
    return await subtle.importKey("pkcs8", der, RSA_OAEP, false, ["decrypt"]);
  } catch {
    throw new CryptoError("The stored private key is damaged.");
  } finally {
    der.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Public-key fingerprints: SHA-256 over the SubjectPublicKeyInfo DER, the same
// value the account page shows, so people can compare keys out of band.

export async function publicKeyFingerprint(pem) {
  const digest = new Uint8Array(await subtle.digest("SHA-256", pemBody(pem, "PUBLIC KEY")));
  return formatFingerprint(toHex(digest));
}

export function formatFingerprint(hex) {
  return hex.slice(0, 32).match(/.{4}/g).join(" ");
}

function pemBody(pem, label) {
  const match = String(pem).match(new RegExp(`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`));
  if (!match) throw new CryptoError("RSA public key could not be parsed.");
  return b64decode(match[1].replace(/\s+/g, ""));
}
