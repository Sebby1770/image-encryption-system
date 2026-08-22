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

## Deployment note

The repository demonstrates secure design patterns but is not an independently
audited production vault. Review `docs/SECURITY_MODEL.md` before deployment.
