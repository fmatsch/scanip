"""Baut eine doppelklickbare Anwendung: scanip.app (macOS) bzw. scanip.exe (Windows).

    python3 tools/build_app.py            eigenständig (PyInstaller, kein Python nötig)
    python3 tools/build_app.py --light    nur macOS: schlanke Hülle (~4 KB, braucht Python)
    python3 tools/build_app.py --keep     Zwischendateien behalten

Hinweise:
* Eine Windows-.exe lässt sich nur auf Windows bauen, eine macOS-.app nur auf
  macOS - PyInstaller kann nicht über Plattformgrenzen hinweg packen.
* Für die Tk-Oberfläche wird automatisch ein Python mit Tk >= 8.6 gesucht.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
import venv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
ASSETS = os.path.join(ROOT, "assets")
APP_NAME = "scanip"
BUNDLE_ID = "de.local.scanip"

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"


def log(message: str) -> None:
    print("==> %s" % message, flush=True)


# --------------------------------------------------------------------------- #
# Python-Auswahl
# --------------------------------------------------------------------------- #

TK_CHECK = ("import sys,tkinter;"
            "v=tkinter.Tcl().eval('info patchlevel').split('.');"
            "sys.exit(0 if (int(v[0]),int(v[1]))>=(8,6) else 1)")


def has_modern_tk(python: str) -> bool:
    try:
        return subprocess.run([python, "-c", TK_CHECK], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def pick_python() -> str:
    """Python mit brauchbarem Tk - sonst das laufende."""
    candidates = []
    if IS_MAC:
        candidates += ["/opt/homebrew/bin/python3.14", "/opt/homebrew/bin/python3.13",
                       "/opt/homebrew/bin/python3", "/usr/local/bin/python3",
                       "/Library/Frameworks/Python.framework/Versions/Current/bin/python3"]
    candidates.append(sys.executable)
    for candidate in candidates:
        if os.path.exists(candidate) and has_modern_tk(candidate):
            return candidate
    print("Warnung: kein Python mit Tk >= 8.6 gefunden. Die gepackte Anwendung\n"
          "         weicht dann auf die Browser-Oberfläche aus.", file=sys.stderr)
    return sys.executable


# --------------------------------------------------------------------------- #
# Schlanke macOS-Hülle (ohne Fremdwerkzeuge)
# --------------------------------------------------------------------------- #

def build_light_app() -> str:
    """Ein echtes .app-Bündel, das das installierte Python aufruft.

    Winzig und sofort gebaut, setzt aber Python auf dem Rechner voraus.
    """
    app_path = os.path.join(DIST, APP_NAME + ".app")
    if os.path.exists(app_path):
        shutil.rmtree(app_path)
    macos_dir = os.path.join(app_path, "Contents", "MacOS")
    resources = os.path.join(app_path, "Contents", "Resources")
    os.makedirs(macos_dir)
    os.makedirs(resources)

    info = {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": "scanip",
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleVersion": "1.0.0",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleExecutable": APP_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleIconFile": "scanip.icns",
        "LSMinimumSystemVersion": "10.13",
        "NSHighResolutionCapable": True,
        "LSApplicationCategoryType": "public.app-category.utilities",
    }
    with open(os.path.join(app_path, "Contents", "Info.plist"), "wb") as handle:
        plistlib.dump(info, handle)

    icon = os.path.join(ASSETS, "scanip.icns")
    if os.path.exists(icon):
        shutil.copy2(icon, os.path.join(resources, "scanip.icns"))

    launcher = os.path.join(macos_dir, APP_NAME)
    with open(launcher, "w", encoding="utf-8") as handle:
        handle.write('''#!/bin/bash
# Startet scanip aus dem Projektordner. Sucht ein Python mit aktuellem Tk.
PROJEKT="%s"
cd "$PROJEKT" || exit 1

hat_tk() {
    "$1" -c 'import sys,tkinter
v=tkinter.Tcl().eval("info patchlevel").split(".")
sys.exit(0 if (int(v[0]),int(v[1]))>=(8,6) else 1)' 2>/dev/null
}

for kandidat in /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 \\
                /opt/homebrew/bin/python3 /usr/local/bin/python3 python3
do
    command -v "$kandidat" >/dev/null 2>&1 || continue
    if hat_tk "$kandidat"; then exec "$kandidat" -m scanip --gui; fi
done
command -v python3 >/dev/null 2>&1 && exec python3 -m scanip --web
osascript -e 'display alert "Python 3 fehlt" message "Bitte Python 3 installieren."'
''' % ROOT)
    os.chmod(launcher, 0o755)
    return app_path


# --------------------------------------------------------------------------- #
# Eigenständiges Paket per PyInstaller
# --------------------------------------------------------------------------- #

def build_venv_cache() -> str:
    """Baut die Build-Umgebung außerhalb des Projektordners.

    Gründe: kein Ballast im Projekt und keine Synchronisation hunderter Dateien,
    falls das Projekt in einem Cloud-Ordner liegt.
    """
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif IS_MAC:
        base = os.path.expanduser("~/Library/Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "scanip-build")


def ensure_pyinstaller(python: str) -> str:
    """Legt bei Bedarf eine Build-Umgebung an und liefert deren PyInstaller."""
    env_dir = build_venv_cache()
    bin_dir = os.path.join(env_dir, "Scripts" if IS_WINDOWS else "bin")
    env_python = os.path.join(bin_dir, "python.exe" if IS_WINDOWS else "python")

    if not os.path.exists(env_python):
        log("lege Build-Umgebung an: %s" % env_dir)
        builder = venv.EnvBuilder(with_pip=True, symlinks=not IS_WINDOWS)
        # Umgebung vom gewählten Interpreter aus erzeugen
        subprocess.run([python, "-m", "venv", env_dir], check=True)

    check = subprocess.run([env_python, "-c", "import PyInstaller"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode != 0:
        log("installiere PyInstaller (einmalig, einige MB) ...")
        subprocess.run([env_python, "-m", "pip", "install", "--quiet",
                        "--upgrade", "pip"], check=True)
        subprocess.run([env_python, "-m", "pip", "install", "--quiet",
                        "pyinstaller"], check=True)
    return env_python


def build_standalone(keep: bool = False) -> str:
    python = pick_python()
    log("verwende Python: %s" % python)
    env_python = ensure_pyinstaller(python)

    work = os.path.join(build_venv_cache(), "work")
    spec_dir = os.path.join(build_venv_cache(), "spec")
    entry = os.path.join(ROOT, "tools", "app_entry.py")

    command = [env_python, "-m", "PyInstaller", "--noconfirm", "--clean",
               "--name", APP_NAME, "--windowed",
               "--distpath", DIST, "--workpath", work, "--specpath", spec_dir,
               "--paths", ROOT,
               "--hidden-import", "tkinter", "--hidden-import", "tkinter.ttk",
               "--hidden-import", "tkinter.filedialog",
               "--hidden-import", "tkinter.messagebox",
               "--collect-submodules", "scanip"]

    icon = os.path.join(ASSETS, "scanip.ico" if IS_WINDOWS else "scanip.icns")
    if os.path.exists(icon):
        command += ["--icon", icon]
    if IS_MAC:
        command += ["--osx-bundle-identifier", BUNDLE_ID]
    if IS_WINDOWS:
        command += ["--onefile"]
    command.append(entry)

    log("baue Anwendung ...")
    subprocess.run(command, check=True)

    if not keep:
        shutil.rmtree(work, ignore_errors=True)

    if IS_MAC:
        return os.path.join(DIST, APP_NAME + ".app")
    if IS_WINDOWS:
        return os.path.join(DIST, APP_NAME + ".exe")
    return os.path.join(DIST, APP_NAME)


# --------------------------------------------------------------------------- #

def main() -> int:
    light = "--light" in sys.argv
    keep = "--keep" in sys.argv

    if not os.path.exists(os.path.join(ASSETS, "icon.png")):
        log("erzeuge Symbol ...")
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_icon.py"),
                        ASSETS], check=True)

    os.makedirs(DIST, exist_ok=True)

    if light:
        if not IS_MAC:
            print("--light gibt es nur für macOS. Ohne die Option wird eine "
                  "eigenständige Anwendung gebaut.", file=sys.stderr)
            return 2
        path = build_light_app()
    else:
        try:
            path = build_standalone(keep)
        except subprocess.CalledProcessError as exc:
            print("\nBau fehlgeschlagen (Exitcode %d)." % exc.returncode,
                  file=sys.stderr)
            return 1

    size = 0
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            size += sum(os.path.getsize(os.path.join(root, f)) for f in files)
    elif os.path.exists(path):
        size = os.path.getsize(path)

    print()
    log("fertig: %s  (%.1f MB)" % (path, size / 1048576.0))
    if IS_MAC:
        print("    Doppelklick startet die Anwendung. Da sie nicht signiert ist,")
        print("    beim ersten Start ggf. Rechtsklick > Öffnen wählen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
