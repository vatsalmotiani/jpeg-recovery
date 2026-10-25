#!/bin/bash
# Double-click in Finder to check the card and create a report on your Desktop.
"$(cd "$(dirname "$0")" && pwd)/diagnose.sh"
echo
read -n 1 -s -r -p "Done. Press any key to close this window."
