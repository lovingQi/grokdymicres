#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行: sudo bash $0" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

apt-get update
apt-get install -y xfce4 xfce4-terminal tigervnc-standalone-server tigervnc-common dbus-x11 x11-utils

install -d -m 700 /root/.vnc
install -m 755 "$ROOT/deploy/xstartup" /root/.vnc/xstartup

if [[ ! -f /root/.vnc/passwd ]]; then
  umask 077
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12 | vncpasswd -f >/root/.vnc/passwd
  chmod 600 /root/.vnc/passwd
fi

echo "VNC xstartup and passwd are ready under /root/.vnc"
