#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
exec xvfb-run -a "$ROOT/.venv/bin/python" "$ROOT/grok_register_ttk.py" autostart
