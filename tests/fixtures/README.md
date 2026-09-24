# Legacy envelope fixtures

Generated with the version 1 envelope code (commit on `claude/vault-rescue-phase0`)
**before** envelope version 3 existed. Tests decrypt them to prove old files stay
readable. Do not regenerate them with newer code.

| File | Contents |
| --- | --- |
| `legacy-v1-cli.ies` | `ies encrypt` of `legacy-v1-cli.png`, passphrase `legacy fixture passphrase` |
| `legacy-v1-web.ies` | `.ies` download of a web upload by user id 1 (`alice`) of `helpers.sample_png()` as `legacy-web.png`, same passphrase |
| `legacy-v1-backup.zip` | `/backup` export of that same vault |

The passphrase is a test value, not a secret.
