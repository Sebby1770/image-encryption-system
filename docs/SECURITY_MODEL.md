# Security Model

## Goals

The system protects image confidentiality at rest by encrypting uploaded image
bytes before they are written to storage. It also restricts image access to the
authenticated user who uploaded the file.

## Non-Goals

- It does not provide production cloud security by default.
- It does not scan uploaded files for malware.
- It does not implement OAuth provider login out of the box.
- It does not protect decrypted images after they are sent to the user's browser.

## Trust Boundaries

- Browser to Flask app: session cookies and optional JWT bearer tokens.
- Flask app to local vault: encrypted files and SQLite metadata.
- User password to RSA private key: private keys are encrypted at registration.
- AES passphrase to AES data key: passphrases derive key-wrapping keys with
  Scrypt.

## Encryption Design

Uploaded images are never stored as plaintext. The app generates a fresh
256-bit random data key for each image. Image bytes are encrypted with
AES-GCM using a unique 96-bit nonce.

The data key is protected in one of two ways:

- AES-GCM passphrase mode derives a 256-bit wrapping key from a passphrase using
  Scrypt and uses that key to encrypt the data key.
- RSA hybrid mode encrypts the data key with the user's RSA public key using
  RSA-OAEP with SHA-256.

AES-GCM provides confidentiality and integrity. If ciphertext or metadata is
modified, decryption fails.

## Access Control

The web dashboard requires login. Each encrypted image record is tied to a
`user_id`. Decryption routes check ownership before reading encrypted bytes.
API routes require a valid signed JWT.

## Local File Permissions

On POSIX hosts, generated key and vault directories are restricted to the owning
user. Per-user PEM files and encrypted vault blobs are written with owner-only
read/write permissions.

## Recommended Production Hardening

- Use HTTPS everywhere.
- Store secrets in a managed secret store.
- Extend rate limiting to registration and decrypt endpoints.
- Add audit logs for encryption, decryption, and failed access attempts.
- Move encrypted objects to S3 with SSE-KMS or a similar managed storage layer.
- Add malware and file-type scanning for uploads.
- Consider envelope encryption with a managed KMS instead of local key files.
- Add OAuth using a trusted identity provider if the app will be multi-user.
