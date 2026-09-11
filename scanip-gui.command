#!/bin/bash
# macOS: Doppelklick startet die Oberflaeche.
# Sucht ein Python mit brauchbarem Tk (>= 8.6); Apples Tk 8.5.9 zeichnet auf
# aktuellem macOS nur ein weisses Fenster.
cd "$(dirname "$0")" || exit 1

hat_gutes_tk() {
    "$1" -c 'import sys,tkinter
v=tkinter.Tcl().eval("info patchlevel").split(".")
sys.exit(0 if (int(v[0]),int(v[1]))>=(8,6) else 1)' 2>/dev/null
}

for kandidat in \
    /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 \
    /opt/homebrew/bin/python3 /usr/local/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/Current/bin/python3 \
    python3
do
    command -v "$kandidat" >/dev/null 2>&1 || continue
    if hat_gutes_tk "$kandidat"; then
        exec "$kandidat" -m scanip --gui
    fi
done

# Kein brauchbares Tk gefunden -> Browser-Oberflaeche
if command -v python3 >/dev/null 2>&1; then
    echo "Kein Python mit aktuellem Tk gefunden - starte die Browser-Oberflaeche."
    echo "Aktuelles Tk nachruesten:  brew install python-tk@3.14"
    exec python3 -m scanip --web
fi
osascript -e 'display alert "Python 3 fehlt" message "Bitte Python 3 von python.org installieren."'
