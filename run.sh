#!/bin/bash
# Terminal alternative to double-clicking "JPEG Recovery.app".
# Admin rights are needed to read the raw card data (nothing is written to it).
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$DIR/JPEG Recovery.app/Contents/Resources/app.py"
PY="$(command -v python3 || true)"

if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
  echo "Python 3.8+ is needed. Install Apple's Command Line Tools, then run this again:"
  echo "    xcode-select --install"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "JPEG Recovery needs your Mac password to read the card (nothing is written to it)."
  exec sudo "$PY" -I "$APP" "$@"
fi
exec "$PY" -I "$APP" "$@"
