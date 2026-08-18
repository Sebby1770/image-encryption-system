# Security Model

## Goals

The system protects image confidentiality at rest by encrypting uploaded image
bytes before they are written to storage. Access is limited to the authenticated
owner and to users the owner explicitly shares with. Sharing never writes
plaintext and never hands the owner's passphrase to the recipient.

## Non-Goals

- It does not provide production cloud security by default.
- It does not scan uploaded files for malware.
- It does not implement OAuth provider login out of the box.
- It does not protect decrypted images after they are sent to the user's browser.
- It does not hide metadata such as original filenames from the vault operator.

## Trust Boundaries

- Browser to Flask app: session cookies, CSRF tokens on HTML POSTs, and
  optional JWT bearer tokens.
- Flask app to local vault: encrypted files and SQLite metadata.
- User password to RSA private key: private keys are encrypted at registration.
- AES passphrase to AES data key: passphrases derive key-wrapping keys with
  Scrypt.
- Owner to recipient: the same AES data key is re-wrapped with the recipient's
  RSA public key. The ciphertext blob is unchanged.

## Encryption Design

Uploaded images are never stored as plaintext. The app generates a fresh
256-bit random data key for each image. Image bytes are encrypted with
AES-GCM using a unique 96-bit nonce.

The data key is protected in one of two ways:

- AES-GCM passphrase mode derives a 256-bit wrapping key from a passphrase using
  Scrypt and uses that key to encrypt the data key.
- RSA hybrid mode encrypts the data key with the user's RSA public key using
  RSA-OAEP with SHA-256.

Sharing unwraps that data key in memory and wraps it again with RSA-OAEP for
the recipient. Recipients always decrypt on the RSA path with their own
password-protected private key.

AES-GCM provides confidentiality and integrity. If ciphertext or metadata is
modified, decryption fails.

## Access Control

The web dashboard requires login. Each encrypted image record is tied to a
`user_id`. Decryption routes allow the owner or a row in `shares`. API routes
require a valid signed JWT. Audit events are scoped to the signed-in user.

## Operational Controls

- Login attempts are rate limited (5 / 10 minutes per IP+username).
- Eight failed passwords lock the username for 15 minutes. Counters live in
  the `login_guard` SQLite table so a process restart does not reset them.
- HTML POST forms require a session CSRF token; missing or invalid tokens
  return 400. JSON `/api/*` routes are exempt and use JWTs instead.
- Password changes re-encrypt the RSA private key PEM with the new password.
- Owners can revoke a share (delete the per-recipient wrap row) and rotate a
  passphrase wrap without rewriting ciphertext.
- Uploads are capped at 8 MB by default.
- Passwords are compared with Werkzeug's constant-time `check_password_hash`.
- Backups export ciphertext and wrap metadata only — never private keys.

## Recommended Production Hardening

- Use HTTPS everywhere.
- Store secrets in a managed secret store.
- Terminate sessions after a password change if cookies may be stolen.
- Move encrypted objects to S3 with SSE-KMS or a similar managed storage layer.
- Add malware and file-type scanning for uploads.
- Consider envelope encryption with a managed KMS instead of local key files.
- Add OAuth using a trusted identity provider if the app will be multi-user.
