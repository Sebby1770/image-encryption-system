# Security policy

## Supported version

Security fixes are developed against the latest release. Version 1 envelopes
remain readable for migration, but new assets use the hardened version 2 format.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting feature for this repository and include:

- the affected route, command, or file;
- reproduction steps or a minimal proof of concept;
- the expected and observed result; and
- any assumptions required for impact.

Do not test against systems or data you do not own. This educational project has
no bug-bounty program, but good-faith, responsibly disclosed reports are welcome.

## Browser-side controls

Every response carries a strict `Content-Security-Policy` (`script-src 'self'`
with no inline allowance and no nonce), `frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a
restrictive `Permissions-Policy`. HSTS is asserted on HTTPS requests only.

Responses carrying plaintext, key material, or vault archives are served
`no-store`, so a proxy or a browser disk cache never retains a decrypted image.

Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` by default. Set
`IES_SESSION_COOKIE_SECURE=0` only for local HTTP development.

## Signing secret

The application refuses to start if `SECRET_KEY` is shorter than 32 characters
or matches a value previously published in this repository. With no `SECRET_KEY`
set it generates a random one and persists it to `$IES_INSTANCE_DIR/secret.key`
with owner-only permissions.

## Rate limiting

Beyond the login throttle and account lockout, registration, decryption
attempts, and capability-link resolution are each throttled. Registration is
included because it generates an RSA-3072 key pair and is therefore a CPU
amplifier available to unauthenticated callers. Counters live in SQLite, so a
restart does not reset them.

## Key derivation

New passphrase wrappings use Scrypt at N=2**16, r=8, p=1. The *accepted* floor is
a separate constant (N=2**14) so the default can be raised in future without
rejecting vault files written by an earlier release; `ies rewrap` upgrades an
existing file in place.

## Deployment note

The repository demonstrates secure design patterns but is not an independently
audited production vault. Review `docs/SECURITY_MODEL.md` before deployment.
