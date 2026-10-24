// Runs Scrypt off the main thread: at the vault's cost (2^16, r=8) one
// derivation holds 64 MiB and takes about half a second, long enough to freeze
// a page. Parameters are already bounded by the caller (ies-crypto.scrypt).
import { scryptRaw } from "./ies-crypto.js";

self.addEventListener("message", async (event) => {
  const { id, password, salt, n, r, p, length } = event.data;
  try {
    const key = await scryptRaw(password, salt, n, r, p, length);
    self.postMessage({ id, key }, [key.buffer]);
  } catch (error) {
    self.postMessage({ id, error: String(error && error.message ? error.message : error) });
  } finally {
    password.fill(0);
  }
});
