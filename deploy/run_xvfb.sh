#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"

DISPLAY_NUM="${GROK_VNC_DISPLAY:-1}"
export DISPLAY=":${DISPLAY_NUM}"
GEOMETRY="${GROK_VNC_GEOMETRY:-1280x900}"

if ! xdpyinfo -display "$DISPLAY" >/dev/null 2>&1; then
  vncserver ":${DISPLAY_NUM}" -geometry "$GEOMETRY" -depth 24 -localhost yes
  for _ in $(seq 1 30); do
    if xdpyinfo -display "$DISPLAY" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
fi

if ! xdpyinfo -display "$DISPLAY" >/dev/null 2>&1; then
  echo "VNC display ${DISPLAY} is not available" >&2
  exit 1
fi

exec "$ROOT/.venv/bin/python" "$ROOT/grok_register_ttk.py" autostart
