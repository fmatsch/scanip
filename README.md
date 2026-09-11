# scanip

[![Tests](https://github.com/fmatsch/scanip/actions/workflows/tests.yml/badge.svg)](https://github.com/fmatsch/scanip/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/release/fmatsch/scanip?label=Download)](https://github.com/fmatsch/scanip/releases/latest)
[![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-blue.svg)](LICENSE)

**Projektseite: [fmatsch.github.io/scanip](https://fmatsch.github.io/scanip/)**

Netzwerk-Scanner für **Windows, macOS und Linux**. Zeigt für jedes Gerät im Netz:

| Spalte | Inhalt |
|---|---|
| **IP-Adresse** | gefunden über ARP, ICMP und TCP |
| **Offene Ports** | TCP-Connect-Scan mit Dienstnamen (`9100/printer-raw`) |
| **MAC-Adresse** | aus der ARP-Tabelle bzw. per NetBIOS |
| **Gerätekategorie** | Drucker, Computer, Switch, Telefon, Kamera, NAS, … (heuristisch, mit Begründung) |
| **Gerätename** | aus DNS, mDNS/Bonjour, NetBIOS, SNMP und UPnP |

Ohne Fremdbibliotheken (nur Python-Standardbibliothek), **ohne Administrator- oder
Root-Rechte**. Drei Bedienwege: Kommandozeile, Browser-Oberfläche und Tk-Fenster.

---

## Fertige Anwendung herunterladen

| Plattform | Datei | Hinweis |
|---|---|---|
| macOS | [`scanip-macos.zip`](https://github.com/fmatsch/scanip/releases/latest/download/scanip-macos.zip) | Entpacken, beim ersten Start Rechtsklick → Öffnen |
| Windows | [`scanip.exe`](https://github.com/fmatsch/scanip/releases/latest/download/scanip.exe) | Einzelne Datei; SmartScreen: „Weitere Informationen“ → „Trotzdem ausführen“ |

Beide Pakete bringen Python und Tk mit — es muss nichts installiert werden.
Prüfsummen liegen jedem [Release](https://github.com/fmatsch/scanip/releases/latest)
als `SHA256SUMS.txt` bei.

## Installation aus dem Quellcode

Voraussetzung ist Python 3.8 oder neuer.

* **Windows:** Python von [python.org](https://www.python.org/downloads/) installieren
  (bei der Installation „Add Python to PATH“ ankreuzen).
* **macOS:** Python ist vorinstalliert und genügt für Kommandozeile und
  Browser-Oberfläche. Für das **Tk-Fenster** wird ein Python mit aktuellem Tk
  benötigt — siehe „Weißes Fenster“ weiter unten.

Danach genügt es, den Ordner zu kopieren; eine Installation ist nicht nötig:

```bash
cd scanip
python3 -m scanip
```

Optional als Programm installieren (macht `scanip` und `scanip-gui` systemweit verfügbar):

```bash
pip install -e .
```

---

## Schnellstart

### Browser-Oberfläche (empfohlen)

Plattformunabhängig, unabhängig von Tk, mit Live-Fortschritt:

```bash
python3 -m scanip --web
```

Zum Doppelklicken: `scanip-web.command` (macOS) bzw. `scanip-web.bat` (Windows).

Es startet ein lokaler Server und der Browser öffnet sich. Die Seite bietet
Netz- und Portauswahl, Fortschrittsanzeige mit Abbruch, sortierbare Tabelle,
Mehrwort-Filter, aufklappbare Details je Gerät und Export als HTML/CSV/JSON.

> **Absicherung:** Der Server lauscht ausschließlich auf `127.0.0.1` und verlangt
> für jeden Aufruf ein beim Start erzeugtes Zufallstoken, das nur in der
> geöffneten URL steht. Von außen ist er nicht erreichbar, und keine fremde
> Webseite kann den Scanner fernsteuern.

### Tk-Fenster

```bash
python3 -m scanip --gui
```

Zum Doppelklicken: `scanip-gui.command` (macOS) bzw. `scanip-gui.bat` (Windows).
Der macOS-Starter sucht selbstständig ein Python mit brauchbarem Tk.

### Kommandozeile

```bash
python3 -m scanip
```

```
IP-Adresse     MAC-Adresse        Hersteller   Gerätename                 Kategorie            Offene Ports
-------------  -----------------  -----------  -------------------------  -------------------  --------------------
192.168.1.1    78:20:51:AA:BB:01  TP-Link      Archer AX53               Router / Gateway     53, 80, 443, 1900
192.168.1.50   3C:2A:F4:11:22:33  Brother      BRN3C2AF4                  Drucker / MFP        80, 443, 515, 631, 9100
192.168.1.68   C8:69:CD:AA:BB:02  Apple        Apple-TV-Wohnzimmer.local           Smart-TV / Media     5000, 7000, 62078
192.168.1.152  28:2E:89:AA:BB:03  Intel        PC-BUERO-01                Computer (Windows)   135, 139, 445
192.168.1.172  94:9F:3E:AA:BB:04  Sonos        Sonos Play:1               Smart-TV / Media     1400, 3689
```

---

## Beispiele

```bash
python3 -m scanip                        # eigenes Netz automatisch
python3 -m scanip 192.168.1.0/24         # bestimmtes Netz
python3 -m scanip 10.0.0.1-10.0.0.50     # IP-Bereich
python3 -m scanip 10.0.0.1-50            # Kurzform des Bereichs
python3 -m scanip 192.168.1.5            # einzelner Host

python3 -m scanip --fast                 # Schnellscan (12 Ports, ~10 s)
python3 -m scanip -p 1-1024              # eigener Portbereich
python3 -m scanip -p all --thorough      # alle 65535 Ports (dauert lange)

python3 -m scanip --why                  # Begründung der Kategorie anzeigen
python3 -m scanip --services             # Portnamen mit anzeigen

python3 -m scanip -o bericht.html        # HTML-Report (sortierbar, filterbar)
python3 -m scanip -o geraete.csv         # CSV für Excel (Semikolon-getrennt)
python3 -m scanip -o scan.json           # JSON für Weiterverarbeitung

python3 -m scanip --web                  # Browser-Oberfläche
python3 -m scanip --gui                  # Tk-Fenster
python3 -m scanip --list-interfaces      # erkannte Schnittstellen anzeigen
python3 -m scanip --update-oui           # Herstellerliste vervollständigen
```

### Wichtige Optionen

| Option | Wirkung |
|---|---|
| `-p, --ports` | `top` (Standard, 96 Ports), `all`, oder `22,80,8000-8100` |
| `-o, --output` | Datei; Format aus der Endung (`.html`, `.csv`, `.json`, `.txt`) |
| `--fast` | nur Discovery-Ports, ohne SNMP/NetBIOS/Banner |
| `--thorough` | längere Timeouts, Ports 1–10000 |
| `--why` | Spalte mit der Begründung der Kategorie |
| `--timeout` | TCP-Timeout pro Port (Standard 0,6 s) |
| `--workers` | parallele Hosts bei der Suche (Standard 128) |
| `--snmp-community` | SNMP-Community (Standard `public`) |
| `--web` / `--web-port` / `--no-browser` | Browser-Oberfläche, fester Port, Browser nicht öffnen |
| `--gui` / `--force-tk` | Tk-Fenster; zweites erzwingt es auch bei veraltetem Tk |
| `--no-ping`, `--no-mdns`, `--no-netbios`, `--no-snmp`, `--no-ssdp`, `--no-banner`, `--no-dns` | einzelne Verfahren abschalten |
| `-q, --quiet` | keine Fortschrittsanzeige |

Maximal 65.536 Adressen pro Scan. Größere Angaben wie `10.0.0.0/8` werden sofort
abgelehnt, statt Millionen Adressen aufzuzählen.

---

## Wie die Erkennung funktioniert

**1. Hosts finden** — für jede Adresse parallel: ein UDP-Paket (löst die
ARP-Auflösung aus), ein ICMP-Ping und ein TCP-Verbindungsversuch auf 12 gängige
Ports. Anschließend wird die ARP-Tabelle des Betriebssystems ausgelesen. So werden
auch Geräte gefunden, die Pings ignorieren.

**2. Ports prüfen** — TCP-Connect-Scan (keine Rohsockets, daher keine
Administratorrechte nötig).

**3. Namen ermitteln** — parallel über fünf Quellen:

| Quelle | Liefert typischerweise |
|---|---|
| Reverse-DNS | Namen aus dem Router/DNS-Server (`drucker.fritz.box`) |
| mDNS / Bonjour | Apple- und Linux-Geräte, Drucker (`Apple-TV.local`) |
| NetBIOS | Windows-Rechnernamen und zusätzlich die MAC-Adresse |
| SNMP | Drucker, Switches, Router, USV (`sysName`, `sysDescr`) |
| SSDP / UPnP | Smart-TVs, Router, Media-Player (`Archer AX53`, `Sonos Play:1`) |

**4. Kategorie bestimmen** — jedes Indiz vergibt Punkte auf Kategorien; die
Kategorie mit der höchsten Summe gewinnt. Bewertet werden offene Ports, der
MAC-Hersteller, Textmuster in Namen und Bannern, angebotene Bonjour-Dienste sowie
die Rolle im Netz (Standardgateway). Gegenregeln verhindern typische
Fehleinordnungen — ein Gerät mit Port 9100 *und* Port 3389 ist zum Beispiel ein
Windows-Rechner mit Druckerfreigabe, kein Drucker.

Weil mehrere Quellen zusammenwirken, bleibt die Erkennung robust: Ein Apple TV mit
schlafendem AirPlay-Dienst wird über seinen mDNS-Namen trotzdem richtig eingeordnet.

`--why`, der Klick auf eine Zeile in der Browser-Oberfläche bzw. der Doppelklick im
Tk-Fenster zeigen, welche Indizien zur Einordnung geführt haben.

### Erkannte Kategorien

Router / Gateway · Switch · WLAN Access Point · Firewall / UTM · Drucker / MFP ·
Computer (Windows / macOS / Linux) · Server · NAS / Storage · IP-Telefon ·
IP-Kamera · Smart-TV / Media · Smartphone / Tablet · Spielkonsole ·
Smart-Home / IoT · Industrie / SPS · USV · Virtuelle Maschine

Die Kategorie ist eine **begründete Vermutung**. Bei schwacher Beweislage wird sie
mit `(?)` markiert und grau dargestellt.

---

## Herstellerliste vervollständigen

Eingebaut sind rund 1.500 MAC-Präfixe der gängigsten Hersteller. Steht bei vielen
Geräten kein Hersteller, lädt

```bash
python3 -m scanip --update-oui
```

die vollständige IEEE-Registrierung (~5 MB, rund 35.000 Einträge) in den
Benutzer-Cache. Alternativ wird eine vorhandene `manuf`-Datei von Wireshark
automatisch genutzt, oder eine eigene Datei per `--oui-file` geladen.

---

## Häufige Fragen

**Das Tk-Fenster ist weiß und leer (macOS).** Das mitgelieferte `python3` der Xcode
Command Line Tools nutzt Tk 8.5.9 von 2010. Diese Version ist seit macOS 10.15
abgekündigt und zeichnet auf aktuellem macOS nichts mehr. Abhilfe:

```bash
brew install python@3.14 python-tk@3.14
```

`scanip-gui.command` findet das neue Python danach automatisch. `python3 -m scanip
--gui` erkennt die alte Tk-Version ebenfalls und weicht auf die Browser-Oberfläche
aus; `--force-tk` erzwingt das Tk-Fenster trotzdem. Die Browser-Oberfläche
(`--web`) ist von all dem nicht betroffen.

**Ein Gerät zeigt keinen Namen.** Nicht jedes Gerät verrät einen. Drucker, Windows-PCs,
Apple-Geräte und Smart-TVs tun es fast immer; einfache IoT-Module oft nicht.

**Ein Gerät zeigt keine offenen Ports, taucht aber auf.** Es wurde über ARP oder Ping
gefunden, hat aber keinen der geprüften Ports offen. Mit `-p all` weiter suchen.

**Die MAC-Adresse fehlt.** MAC-Adressen sind nur im eigenen Subnetz sichtbar. Bei
Geräten hinter einem Router liefert das ARP-Verfahren prinzipbedingt nichts.

**Der Hersteller passt nicht zum Gerät.** Viele Geräte verwenden WLAN-Module von
Drittanbietern (Intel, Espressif, Realtek). Der Hersteller ist ein Indiz, kein Beweis.

**Smartphones wechseln ständig die MAC-Adresse.** iOS und Android verwenden
zufällige MAC-Adressen pro WLAN. scanip weist das als
„zufällige MAC (Privatsphäre)“ aus.

**Ergebnisse schwanken zwischen zwei Durchläufen.** WLAN-Geräte schlafen und
antworten dann nicht. Ein zweiter Durchlauf oder `--thorough` hilft.

**Der Scan ist langsam.** `--fast` nutzen oder mit `--timeout 0.3` das
TCP-Zeitlimit senken.

**Windows-Firewall / macOS-Firewall.** Eingehende Antworten auf mDNS und NetBIOS
können blockiert werden. Der Scan funktioniert trotzdem, liefert dann aber
weniger Namen.

---

## Als Anwendung verpacken (.app / .exe)

```bash
python3 tools/build_app.py            # eigenständig: kein Python auf dem Zielrechner nötig
python3 tools/build_app.py --light    # nur macOS: schlanke Hülle (~0,4 MB, nutzt lokales Python)
```

Das Ergebnis landet in `dist/` — `scanip.app` unter macOS, `scanip.exe` unter
Windows. Doppelklick startet die Oberfläche; mit Argumenten aufgerufen verhält
sich die Anwendung wie das Kommandozeilenwerkzeug.

Das Symbol wird von `tools/make_icon.py` erzeugt (reines Python, ohne
Bildbibliothek) und liegt als PNG, ICNS und ICO in `assets/`.

**Zwei Varianten:**

| | eigenständig | `--light` (nur macOS) |
|---|---|---|
| Größe | ~30–60 MB | ~0,4 MB |
| Python auf dem Zielrechner | nicht nötig | nötig |
| Weitergabe an andere | ja | nein (verweist auf diesen Projektordner) |
| Bauzeit | einige Minuten | sofort |

**Wichtig:** PyInstaller kann nicht über Plattformgrenzen hinweg packen — eine
Windows-`.exe` muss auf Windows gebaut werden, eine macOS-`.app` auf macOS. Für
beides aus einem Durchlauf eignet sich eine CI mit `windows-latest` und
`macos-latest` (z. B. GitHub Actions), die `tools/build_app.py` ausführt.

PyInstaller wird beim ersten Bau automatisch in eine Build-Umgebung unter
`~/Library/Caches/scanip-build` (macOS) bzw. `%LOCALAPPDATA%\scanip-build`
(Windows) installiert — bewusst außerhalb des Projektordners, damit ein
Cloud-Ordner wie Dropbox nicht hunderte Dateien synchronisiert.

**Signatur:** Die gebaute Anwendung ist nicht signiert. Lokal gebaut startet sie
normal. Wird sie weitergegeben (heruntergeladen, per Mail verschickt), meldet
Gatekeeper unter macOS „nicht verifizierter Entwickler“ — dann beim ersten Start
Rechtsklick → Öffnen. Für reibungslose Weitergabe wären eine Developer-ID-Signatur
und Notarisierung nötig; unter Windows entsprechend ein Code-Signing-Zertifikat,
sonst warnt SmartScreen.

---

## Aufbau

| Datei | Aufgabe |
|---|---|
| `scanip/netinfo.py` | Schnittstellen, ARP-Tabelle, Gateway, Ping (plattformabhängig) |
| `scanip/ports.py` | Portscan, Dienstnamen, HTTP-/Banner-Abfrage |
| `scanip/names.py` | mDNS, NetBIOS, SNMP, SSDP/UPnP (selbst implementiert) |
| `scanip/oui.py` | MAC-Herstellerdatenbank |
| `scanip/classify.py` | Punktesystem für die Gerätekategorie |
| `scanip/scanner.py` | Ablaufsteuerung, Parallelisierung |
| `scanip/report.py` | Texttabelle, CSV, JSON, HTML-Report |
| `scanip/cli.py` | Kommandozeile |
| `scanip/web.py` | Browser-Oberfläche (Server + Seite) |
| `scanip/gui.py` | Tk-Fenster |
| `tools/make_icon.py` | erzeugt Symbol als PNG/ICNS/ICO |
| `tools/build_app.py` | baut `.app` bzw. `.exe` |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

71 Tests, komplett offline (unter einer Sekunde) — Protokollkodierung (DNS,
NetBIOS, SNMP/BER), ARP-Auswertung für Windows- und macOS-Format, Zielexpansion
samt Größengrenze, Kategorisierung anhand von 15 Geräteprofilen, alle
Ausgabeformate sowie Routen und Token-Absicherung des Webservers.

---

## Rechtlicher Hinweis

Portscans nur in Netzen durchführen, für die eine Berechtigung vorliegt — also im
eigenen Netz oder mit ausdrücklicher Erlaubnis des Betreibers. In fremden Netzen
kann ein Scan unzulässig sein.
