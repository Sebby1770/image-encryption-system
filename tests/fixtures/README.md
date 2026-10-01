# Legacy envelope fixtures

Generated with the version 1 envelope code (commit on `claude/vault-rescue-phase0`)
**before** envelope version 3 existed. Tests decrypt them to prove old files stay
readable. Do not regenerate them with newer code.

| File | Contents |
| --- | --- |
| `legacy-v1-cli.ies` | `ies encrypt` of `legacy-v1-cli.png`, passphrase `legacy fixture passphrase` |
| `legacy-v1-web.ies` | `.ies` download of a web upload by user id 1 (`alice`) of `helpers.sample_png()` as `legacy-web.png`, same passphrase |
| `legacy-v1-backup.zip` | `/backup` export of that same vault |
| `legacy-v1-web.png` | The exact plaintext sealed in `legacy-v1-web.ies` |

`legacy-v1-web.png` was recovered by decrypting `legacy-v1-web.ies`: the AES-GCM
tag guarantees those are the bytes sealed when the fixture was made, and it was
checked independently to decode to the 80 x 48 `#b7791f` sample image. Tests
compare against this file rather than calling `helpers.sample_png()` again,
because PNG encoding differs between Pillow releases.

The passphrase is a test value, not a secret.
