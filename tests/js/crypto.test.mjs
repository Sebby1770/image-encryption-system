// Unit tests for the browser crypto module: `node --test tests/js/`.
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  AES_GCM_PASSPHRASE,
  CryptoError,
  MIN_SCRYPT_N,
  RSA_HYBRID,
  b64decode,
  b64encode,
  b64urlDecode,
  b64urlEncode,
  canonicalJSON,
  decryptImage,
  encryptImage,
  packIES,
  scrypt,
  scryptRaw,
  toHex,
  unpackIES,
  unwrapDataKey,
  utf8,
  validateKeyWrap,
  validateScryptParameters,
  wrapDataKeyPassphrase,
} from "../../src/image_encryption_system/static/js/ies-crypto.js";

const subtle = globalThis.crypto.subtle;

// RFC 7914 section 12.
const VECTORS = [
  {
    password: "password",
    salt: "NaCl",
    n: 1024,
    r: 8,
    p: 16,
    hex:
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
      "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
  },
  {
    password: "pleaseletmein",
    salt: "SodiumChloride",
    n: 16384,
    r: 8,
    p: 1,
    hex:
      "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2" +
      "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
  },
];

for (const vector of VECTORS) {
  test(`scrypt matches RFC 7914 (N=${vector.n}, r=${vector.r}, p=${vector.p})`, async () => {
    const key = await scryptRaw(utf8(vector.password), utf8(vector.salt), vector.n, vector.r, vector.p, 64);
    assert.equal(toHex(key), vector.hex);
  });
}

test("scrypt refuses hostile cost parameters before allocating", async () => {
  for (const [n, r, p] of [
    [2 ** 30, 8, 1],
    [2 ** 13, 8, 1],
    [3 * 2 ** 14, 8, 1],
    [2 ** 16, 64, 1],
    [2 ** 16, 8, 99],
    [2 ** 16, 8.5, 1],
  ]) {
    assert.throws(() => validateScryptParameters(n, r, p), CryptoError);
    await assert.rejects(scrypt("passphrase", new Uint8Array(16), n, r, p), CryptoError);
  }
});

test("base64 decoding is strict and canonical", () => {
  assert.deepEqual(b64decode("QQ=="), new Uint8Array([65]));
  for (const bad of ["QR==", "QQ", "Q Q==", "QQ==\n", "-_8=", 7, null]) {
    assert.throws(() => b64decode(bad), CryptoError, String(bad));
  }
  const bytes = new Uint8Array([251, 255, 0, 1, 2]);
  assert.deepEqual(b64urlDecode(b64urlEncode(bytes)), bytes);
  assert.equal(b64encode(new Uint8Array(70000).fill(9)).length, 93336);
});

test("canonical JSON sorts keys recursively and refuses non-integers", () => {
  assert.equal(canonicalJSON({ b: 1, a: { d: [2, "é"], c: null } }), '{"a":{"c":null,"d":[2,"é"]},"b":1}');
  assert.equal(canonicalJSON({ "\u{1F600}": 1, "￿": 2 }), '{"￿":2,"\u{1F600}":1}');
  assert.equal(canonicalJSON("tab\tquote\"nul\u0000"), '"tab\\tquote\\"nul\\u0000"');
  assert.throws(() => canonicalJSON({ a: 1.5 }), CryptoError);
  assert.throws(() => canonicalJSON({ a: undefined }), CryptoError);
});

async function rsaPair() {
  const pair = await subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  const spki = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
  const body = b64encode(spki).match(/.{1,64}/g).join("\n");
  return { pem: `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`, privateKey: pair.privateKey };
}

const CONTEXT = { owner: 4, filename: "café ☕.png", mime: "image/png", format: "PNG", width: 3, height: 2, source: "browser" };

test("passphrase envelopes round-trip and seal their context", async () => {
  const plaintext = utf8("not really a png");
  const sealed = await encryptImage(plaintext, {
    algorithm: AES_GCM_PASSPHRASE,
    passphrase: "a long image passphrase",
    context: CONTEXT,
    n: MIN_SCRYPT_N,
  });
  assert.equal(sealed.metadata.version, 3);
  assert.equal(sealed.metadata.context.wrap, "scrypt-aes-gcm");
  assert.match(sealed.metadata.context.asset, /^[0-9a-f]{32}$/);

  const { ciphertext, metadata } = unpackIES(packIES(sealed.ciphertext, sealed.metadata));
  const dataKey = await unwrapDataKey(metadata.key_wrap, "a long image passphrase");
  assert.deepEqual(await decryptImage(ciphertext, metadata, dataKey), plaintext);

  await assert.rejects(unwrapDataKey(metadata.key_wrap, "the wrong passphrase"), CryptoError);
  const moved = structuredClone(metadata);
  moved.context.owner = 5;
  await assert.rejects(decryptImage(ciphertext, moved, dataKey), /Decryption failed/);
  const flipped = ciphertext.slice();
  flipped[0] ^= 1;
  await assert.rejects(decryptImage(flipped, metadata, dataKey), /integrity/);
  const extra = { ...metadata, original_filename: "x" };
  await assert.rejects(decryptImage(ciphertext, extra, dataKey), /unexpected fields/);
});

test("RSA envelopes round-trip through a public key PEM", async () => {
  const { pem, privateKey } = await rsaPair();
  const sealed = await encryptImage(utf8("pixels"), { algorithm: RSA_HYBRID, publicKey: pem, context: CONTEXT });
  assert.equal(sealed.metadata.key_wrap.type, "rsa-oaep-sha256");
  const dataKey = await unwrapDataKey(sealed.metadata.key_wrap, privateKey);
  assert.deepEqual(await decryptImage(sealed.ciphertext, sealed.metadata, dataKey), utf8("pixels"));
});

test("key wraps are closed and length-checked", async () => {
  const wrap = await wrapDataKeyPassphrase(new Uint8Array(32), "passphrase", { n: MIN_SCRYPT_N });
  validateKeyWrap(wrap);
  assert.throws(() => validateKeyWrap({ ...wrap, extra: 1 }), CryptoError);
  assert.throws(() => validateKeyWrap({ ...wrap, salt: b64encode(new Uint8Array(8)) }), CryptoError);
  assert.throws(() => validateKeyWrap({ type: "rsa-oaep-sha256", wrapped_key: b64encode(new Uint8Array(256)) }), CryptoError);
  await assert.rejects(wrapDataKeyPassphrase(new Uint8Array(31), "passphrase"), CryptoError);
});

test("unpackIES rejects malformed containers", () => {
  for (const blob of [utf8("nope"), utf8("IES1\u0000\u0000\u0000\u0009{}"), utf8("IES1ÿÿÿÿ")]) {
    assert.throws(() => unpackIES(blob), CryptoError);
  }
});
