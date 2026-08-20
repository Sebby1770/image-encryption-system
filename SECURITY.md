# Security

This project is a local image vault. It encrypts image bytes before they are
written to disk and restricts decryption to the owning account.

## Reporting

Open a private GitHub security advisory on this repository, or email the
maintainer listed on the GitHub profile. Please do not file public issues for
unpatched cryptographic bugs.

## Hardening checklist

- Keep `IES_DEBUG` / `FLASK_DEBUG` unset in any shared environment.
- Set `SECRET_KEY` and `JWT_SECRET` to long random values.
- Serve the app behind HTTPS and set `IES_SECURE_COOKIES=1`.
- Keep `IES_INSTANCE_DIR` on a disk only the service account can read.
- Generated private keys are written with mode `0600` and the key directory
  with `0700` where the OS allows it.

## What this is not

It is not a multi-tenant cloud KMS. Decrypted images are sent to the caller's
browser or HTTP client and are then outside the vault's control.
