#!/bin/bash
# macOS: Doppelklick startet die Browser-Oberflaeche.
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
    exec python3 -m scanip --web
fi
osascript -e 'display alert "Python 3 fehlt" message "Bitte Python 3 von python.org installieren."'
