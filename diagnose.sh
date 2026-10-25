#!/bin/bash
# Checks the plugged-in card and saves jpeg-recovery-report.txt to your Desktop.
# Read-only: nothing is written to the card.
#   ./diagnose.sh               (auto-picks the card if only one is plugged in)
#   ./diagnose.sh /dev/rdisk4   (pick a specific drive)
DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || true)"

if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
  echo "Python 3.8+ is needed. Install Apple's Command Line Tools, then run this again:"
  echo "    xcode-select --install"
  exit 1
fi

echo "Checking the card. This needs your Mac password and takes about a minute."
sudo "$PY" -I "$DIR/diagnose.py" "$@"
STATUS=$?

REPORT="$HOME/Desktop/jpeg-recovery-report.txt"
if [ -f "$REPORT" ]; then
  open -R "$REPORT"   # show the report in Finder, ready to send
fi
exit $STATUS
