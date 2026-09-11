"""Einstiegspunkt der gepackten Anwendung.

Ohne Argumente startet die Oberfläche (Tk, mit automatischem Ausweichen auf die
Browser-Oberfläche). Mit Argumenten verhält sich die Anwendung wie das
Kommandozeilenwerkzeug.
"""

import os
import sys

if __name__ == "__main__":
    # Im gepackten Zustand liegt das Paket neben dieser Datei
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scanip.cli import main

    sys.exit(main(sys.argv[1:] or ["--gui"]))
