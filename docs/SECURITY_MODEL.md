# Security model

## Protected assets

The vault protects image confidentiality and integrity at rest, RSA private-key
confidentiality, account-scoped authorization, and the integrity of recorded
security events. Decrypted bytes exist in application and browser memory only
for the duration of a request/preview and are returned with `no-store` headers.

## Trust boundaries

- Browser to Flask: signed, HTTP-only, same-site sessions plus CSRF tokens.
- API client to Flask: short-lived HS256 JWTs with required issuer, audience,
  timestamps, subject, and credential-version claims.
- Flask to SQLite and the local vault: ownership checks, restricted paths,
  owner-only permissions, atomic blob writes, and authenticated encryption.
- Password to RSA private key: PKCS#8 `BestAvailableEncryption`.
- Image passphrase to wrapping key: bounded Scrypt parameters followed by
  AES-GCM key wrapping.
- Event writer to audit history: a per-deployment HMAC key protects the chain.

## Cryptographic envelope

Each image receives a fresh 256-bit data key and 96-bit nonce. AES-256-GCM
encrypts the untouched upload. Version 2 serializes these immutable values into
associated data:

- owner id;
- algorithm;
- original upload filename;
- detected MIME type and image format;
- dimensions; and
- optional time-lock value.

Changing ciphertext or any bound context makes decryption fail. Mutable labels
such as display rename, tags, and notes are intentionally outside the envelope.
Version 1 remains readable for migration compatibility.

Passphrase mode derives a 256-bit wrapping key with Scrypt and wraps the data key
with a second AES-GCM operation. Metadata-supplied Scrypt cost, salt, nonce, and
wrapped-key lengths are validated before expensive work. RSA mode uses a
3072-bit account key and OAEP with SHA-256/MGF1-SHA256.

## Authorization and credential lifecycle

Every asset operation compares the authenticated user with the database owner;
version 2 also binds that owner to the ciphertext. Password changes re-encrypt
the private key, increment `auth_version`, preserve the initiating session, and
invalidate older sessions and JWTs. Login, token issuance, decryption, and
registration have bounded in-process throttles.

The in-memory throttles are suitable for a single-process demonstration. A
multi-worker or distributed deployment must replace them with a shared limiter.

## Audit integrity

Audit v2 uses HMAC-SHA256 over a canonical event payload and the previous event
digest. Verification reads the complete per-user history rather than a truncated
window. Legacy unkeyed chains are upgraded once on startup.

`AUDIT_HMAC_KEY` must be stable and secret. The chain detects database changes by
an actor who lacks that key; it cannot provide non-repudiation against an actor
who controls both the database and application secrets.

## Parser and storage controls

- Requests are capped at 16 MiB and Pillow enforces a pixel ceiling.
- Images are verified and decoded before encryption.
- ZIP import inspection limits member count and expanded manifest bytes; archive
  members are never extracted.
- Bundle base64 and versions are strict; KDF cost is bounded.
- Embedded CLI filenames are reduced to safe basenames and existing files are
  not replaced without `--force`.
- Database, key, ciphertext, bundle, and decrypted output files receive
  owner-only permissions on POSIX.
- Stored ciphertext filenames must match an internally generated UUID form.

## Browser controls

State-changing browser requests require CSRF tokens. Responses set a restrictive
Content Security Policy, `nosniff`, clickjacking protection, a no-referrer policy,
and a minimal permissions policy. Non-static responses are private and
non-cacheable. Hosted environments should enable secure cookies and HSTS behind
correct HTTPS termination.

## Non-goals and residual risks

- This project does not scan uploads for malware or protect a host already
  compromised while plaintext is being decrypted.
- It has no password/key recovery mechanism. Losing a passphrase or RSA password
  can make data unrecoverable.
- The workflow time-lock is server policy, not cryptographic trusted time.
- Exported ciphertext can be copied, deleted, or attacked offline.
- Local SQLite and filesystem storage are not a managed KMS, HSM, backup, or
  disaster-recovery system.
- Metadata such as filenames and dimensions is visible to a local operator.
- A public deployment requires TLS, a production WSGI server, shared rate
  limiting, secret management, backups, monitoring, and independent review.
