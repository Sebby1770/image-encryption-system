#!/usr/bin/env bash
# SessionStart hook for Claude Code on the web: make sure every cloud session
# has a working virtualenv with the package, Pillow, and the test/lint tools.
#
# The base image ships Debian-managed PyJWT and cryptography that pip cannot
# uninstall, so installing into the system interpreter fails. A project-local
# venv sidesteps that and keeps the environment identical to CI.
set -euo pipefail

# Local sessions manage their own environment.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/..}"

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --quiet --upgrade pip
# The e2e extra only installs the Playwright Python package. Browsers are
# preinstalled under $PLAYWRIGHT_BROWSERS_PATH; never run `playwright install`.
.venv/bin/python -m pip install --quiet -e ".[dev,e2e]"

# Fail loudly now rather than at test collection time.
.venv/bin/python -c "import PIL, cryptography, flask, jwt, hypothesis"

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export VIRTUAL_ENV=\"$PWD/.venv\""
    echo "export PATH=\"$PWD/.venv/bin:\$PATH\""
  } >> "$CLAUDE_ENV_FILE"
fi
