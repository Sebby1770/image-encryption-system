// Bridge for tests/test_browser_crypto.py: read one JSON request on stdin, run
// the browser modules on it, and write one JSON response to stdout. Lets the
// Python suite check the browser code against crypto.py, Pillow, and hashlib.
import {
  b64decode,
  b64encode,
  canonicalJSON,
  contextAAD,
  decryptImage,
  encryptImage,
  openPrivateKey,
  packIES,
  publicKeyFingerprint,
  scryptRaw,
  unpackIES,
  unwrapDataKey,
} from "../../src/image_encryption_system/static/js/ies-crypto.js";
import { prepareImage } from "../../src/image_encryption_system/static/js/ies-image.js";

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

const ops = {
  async scrypt(requests) {
    const out = [];
    for (const { password, salt, n, r, p, length } of requests) {
      out.push(b64encode(await scryptRaw(b64decode(password), b64decode(salt), n, r, p, length)));
    }
    return out;
  },
  canonical(values) {
    return values.map((value) => canonicalJSON(value));
  },
  aad(contexts) {
    return contexts.map((context) => b64encode(contextAAD(context)));
  },
  async encrypt({ plaintext, algorithm, passphrase, public_key: publicKey, context, n }) {
    const sealed = await encryptImage(b64decode(plaintext), {
      algorithm,
      passphrase,
      publicKey,
      context,
      n,
    });
    return {
      ies: b64encode(packIES(sealed.ciphertext, sealed.metadata)),
      metadata: sealed.metadata,
    };
  },
  async decrypt({ ies, passphrase, private_key: privateKey, password, owner }) {
    const { ciphertext, metadata } = unpackIES(b64decode(ies));
    const secret = privateKey ? await openPrivateKey(privateKey, password, { owner }) : passphrase;
    const dataKey = await unwrapDataKey(metadata.key_wrap, secret);
    return { plaintext: b64encode(await decryptImage(ciphertext, metadata, dataKey)) };
  },
  prepare({ image }) {
    const prepared = prepareImage(b64decode(image));
    return { ...prepared, bytes: b64encode(prepared.bytes) };
  },
  async fingerprint({ pem }) {
    return publicKeyFingerprint(pem);
  },
};

const request = await readStdin();
try {
  const result = await ops[request.op](request.args);
  process.stdout.write(JSON.stringify({ ok: true, result }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, error: `${error.name}: ${error.message}` }));
}
