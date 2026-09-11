"""Kommandozeile von scanip."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

from . import __version__, netinfo, notes, oui, ports as portscan, report
from .scanner import ScanOptions, Scanner, expand_targets

EPILOG = """\
Beispiele:
  python -m scanip                          eigenes Netz automatisch scannen
  python -m scanip 192.168.1.0/24           bestimmtes Netz scannen
  python -m scanip 10.0.0.1-10.0.0.50       IP-Bereich scannen
  python -m scanip --fast                   Schnellscan (wenige Ports)
  python -m scanip -p 1-1024 --why          Portbereich + Begründung anzeigen
  python -m scanip -o bericht.html          HTML-Report schreiben
  python -m scanip --web                    Browser-Oberfläche starten (empfohlen)
  python -m scanip --note 192.168.1.50 "Drucker Buchhaltung"
                                            Notiz zu einem Gerät speichern
  python -m scanip --gui                    Tk-Oberfläche starten
  python -m scanip --update-oui             Hersteller-Datenbank aktualisieren

Hinweis: Nur Netze scannen, für die eine Berechtigung vorliegt.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanip",
        description="Netzwerk-Scanner: IP, offene Ports, MAC, Gerätekategorie, Name.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", metavar="ZIEL",
                        help="Netz (192.168.1.0/24), Bereich (10.0.0.1-50) oder "
                             "einzelne IP. Ohne Angabe: eigenes Netz.")
    parser.add_argument("-p", "--ports", default="top", metavar="LISTE",
                        help="'top' (Standard, ~96 Ports), 'all', oder z.B. '22,80,8000-8100'")
    parser.add_argument("-o", "--output", metavar="DATEI",
                        help="Ergebnis in Datei schreiben (Format aus Endung: "
                             ".html .json .csv .txt)")
    parser.add_argument("-f", "--format", choices=["text", "json", "csv", "html"],
                        help="Ausgabeformat erzwingen")
    parser.add_argument("--fast", action="store_true",
                        help="Schnellscan: nur Discovery-Ports, ohne SNMP/NetBIOS")
    parser.add_argument("--thorough", action="store_true",
                        help="Gründlich: längere Timeouts, mehr Ports (1-10000)")
    parser.add_argument("--note", nargs=2, metavar=("GERÄT", "TEXT"),
                        help="Notiz setzen; GERÄT ist eine IP oder MAC-Adresse. "
                             "Leerer TEXT löscht die Notiz.")
    parser.add_argument("--notes", action="store_true",
                        help="Notizspalte immer anzeigen")
    parser.add_argument("--list-notes", action="store_true",
                        help="gespeicherte Notizen auflisten und beenden")
    parser.add_argument("--why", action="store_true",
                        help="Spalte mit der Begründung der Kategorie anzeigen")
    parser.add_argument("--services", action="store_true",
                        help="Portnamen mit anzeigen (z.B. 80/http)")
    parser.add_argument("--timeout", type=float, default=0.6, metavar="SEK",
                        help="TCP-Timeout pro Port (Standard: 0.6)")
    parser.add_argument("--workers", type=int, default=128, metavar="N",
                        help="Parallele Hosts bei der Suche (Standard: 128)")
    parser.add_argument("--snmp-community", default="public", metavar="NAME",
                        help="SNMP-Community für die Abfrage (Standard: public)")
    parser.add_argument("--no-ping", action="store_true", help="kein ICMP-Ping")
    parser.add_argument("--no-mdns", action="store_true", help="kein mDNS/Bonjour")
    parser.add_argument("--no-netbios", action="store_true", help="kein NetBIOS")
    parser.add_argument("--no-snmp", action="store_true", help="kein SNMP")
    parser.add_argument("--no-ssdp", action="store_true", help="kein SSDP/UPnP")
    parser.add_argument("--no-banner", action="store_true",
                        help="keine Dienst-/Bannerabfrage")
    parser.add_argument("--no-dns", action="store_true", help="kein Reverse-DNS")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="keine Fortschrittsanzeige")
    parser.add_argument("--gui", action="store_true",
                        help="grafische Oberfläche starten (Tk)")
    parser.add_argument("--web", action="store_true",
                        help="Browser-Oberfläche starten (empfohlen, plattformunabhängig)")
    parser.add_argument("--web-port", type=int, default=0, metavar="PORT",
                        help="fester Port für die Browser-Oberfläche (Standard: frei gewählt)")
    parser.add_argument("--force-tk", action="store_true",
                        help="Tk-Oberfläche auch bei veralteter Tk-Version starten")
    parser.add_argument("--no-browser", action="store_true",
                        help="Browser bei --web nicht automatisch öffnen")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="erkannte Netzwerkschnittstellen anzeigen und beenden")
    parser.add_argument("--update-oui", action="store_true",
                        help="vollstaendige IEEE-Herstellerliste herunterladen")
    parser.add_argument("--oui-file", metavar="DATEI",
                        help="zusätzliche OUI-Datei laden (IEEE-CSV oder Wireshark-manuf)")
    parser.add_argument("-V", "--version", action="version",
                        version="scanip %s" % __version__)
    return parser


class ProgressPrinter:
    """Einzeilige Fortschrittsanzeige auf stderr."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stderr.isatty()
        self._last = 0.0

    def __call__(self, phase: str, done: int, total: int, message: str = "") -> None:
        if not self.enabled:
            return
        now = time.time()
        if phase != "done" and now - self._last < 0.08:
            return
        self._last = now
        label = {"discovery": "Suche", "detail": "Analyse", "done": "Fertig"}.get(phase, phase)
        share = (done / total) if total else 1.0
        filled = int(share * 24)
        bar = "#" * filled + "." * (24 - filled)
        line = "\r%-8s [%s] %4d/%-4d %s" % (label, bar, done, total, message[:40])
        sys.stderr.write(line.ljust(88)[:88])
        sys.stderr.flush()
        if phase == "done":
            sys.stderr.write("\r" + " " * 88 + "\r")
            sys.stderr.flush()


def _resolve_targets(args_targets: List[str]) -> List[str]:
    if args_targets:
        return expand_targets(args_targets)
    networks = netinfo.default_networks()
    if not networks:
        return []
    network = networks[0]
    if network.num_addresses > 8192:
        sys.stderr.write(
            "Hinweis: %s ist sehr groß (%d Adressen). Es wird nur das /24 um die "
            "eigene Adresse gescannt.\n" % (network, network.num_addresses))
        own = netinfo.primary_ip()
        if own:
            return expand_targets(["%s/24" % own])
    return expand_targets([str(network)])


def _write_output(text: str, path: Optional[str]) -> None:
    if not path:
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    sys.stderr.write("Gespeichert: %s\n" % os.path.abspath(path))


def _force_utf8_output() -> None:
    """Verhindert UnicodeEncodeError in alten Windows-Konsolen (cp850/cp437)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_output()
    args = build_parser().parse_args(argv)

    if args.web:
        from .web import run_web
        return run_web(args.web_port, not args.no_browser)

    if args.gui:
        from .gui import run_gui, tk_is_usable
        if not tk_is_usable() and not args.force_tk:
            from .gui import tk_version
            from .web import run_web
            sys.stderr.write(
                "Dieses Python nutzt Tk %s - Versionen vor 8.6 zeigen auf aktuellem\n"
                "macOS nur ein weißes Fenster. Es startet daher die Browser-Oberfläche.\n"
                "  Tk-Oberfläche trotzdem erzwingen:  --gui --force-tk\n"
                "  Aktuelles Tk installieren:         brew install python-tk@3.14\n"
                % ".".join(str(v) for v in tk_version()))
            return run_web(args.web_port, not args.no_browser)
        return run_gui()

    if args.update_oui:
        sys.stderr.write("Lade IEEE-Herstellerdatenbank ...\n")
        ok, message = oui.update_from_ieee()
        sys.stderr.write(message + "\n")
        return 0 if ok else 1

    if args.oui_file:
        count = oui.load_external(args.oui_file)
        sys.stderr.write("%d Hersteller-Präfixe geladen.\n" % count)

    if args.list_notes:
        eintraege = notes.format_list()
        if eintraege:
            print("\n".join(eintraege))
        else:
            print("Keine Notizen gespeichert.")
        sys.stderr.write("Datei: %s\n" % notes.notes_path())
        return 0

    if args.note:
        ziel, text = args.note
        mac = netinfo.normalize_mac(ziel)
        ip = None if mac else ziel
        if not mac:
            try:
                import ipaddress as _ip
                _ip.IPv4Address(ziel)
            except ValueError:
                sys.stderr.write("'%s' ist weder eine IP- noch eine MAC-Adresse.\n" % ziel)
                return 2
        if notes.set_note(mac, ip, text):
            sys.stderr.write("Notiz %s für %s.\n"
                             % ("gelöscht" if not text.strip() else "gespeichert", ziel))
            return 0
        sys.stderr.write("Notiz konnte nicht gespeichert werden (%s).\n"
                         % notes.notes_path())
        return 1

    if args.list_interfaces:
        gateways = netinfo.default_gateways()
        for iface in netinfo.interfaces():
            print("%-12s %-18s Netz %-20s %s" % (
                iface.name, "%s/%d" % (iface.ip, iface.prefixlen),
                str(iface.network), iface.mac or ""))
        print("Standardgateway: %s" % (", ".join(gateways) or "-"))
        return 0

    try:
        targets = _resolve_targets(args.targets)
    except ValueError as exc:
        sys.stderr.write("Fehler: %s\n" % exc)
        return 2
    if not targets:
        sys.stderr.write("Kein Netzwerk gefunden. Ziel bitte angeben, "
                         "z.B.: python -m scanip 192.168.1.0/24\n")
        return 2

    if args.fast:
        port_list = list(portscan.DISCOVERY_PORTS)
    elif args.thorough:
        port_list = portscan.parse_port_spec("1-10000") if args.ports == "top" \
            else portscan.parse_port_spec(args.ports)
    else:
        port_list = portscan.parse_port_spec(args.ports)

    options = ScanOptions(
        ports=port_list,
        discovery_timeout=0.25 if args.fast else (0.6 if args.thorough else 0.35),
        port_timeout=1.2 if args.thorough else args.timeout,
        host_workers=args.workers,
        use_ping=not args.no_ping,
        use_mdns=not args.no_mdns,
        use_netbios=not (args.no_netbios or args.fast),
        use_snmp=not (args.no_snmp or args.fast),
        use_ssdp=not args.no_ssdp,
        use_banner=not (args.no_banner or args.fast),
        snmp_community=args.snmp_community,
        resolve_dns=not args.no_dns,
    )

    scanner = Scanner(options)
    started = time.time()
    if not args.quiet:
        sys.stderr.write("Scanne %d Adressen, %d Ports pro Host ...\n"
                         % (len(targets), len(port_list)))
    try:
        devices = scanner.scan(targets, ProgressPrinter(not args.quiet))
    except KeyboardInterrupt:
        scanner.cancel()
        sys.stderr.write("\nAbgebrochen.\n")
        return 130
    duration = time.time() - started

    fmt = args.format
    if not fmt and args.output:
        extension = os.path.splitext(args.output)[1].lower()
        fmt = {".html": "html", ".htm": "html", ".json": "json",
               ".csv": "csv"}.get(extension, "text")
    fmt = fmt or "text"

    meta = {
        "Netz": ", ".join(args.targets) if args.targets else "automatisch",
        "Adressen": len(targets),
        "Dauer": "%.1f s" % duration,
    }

    if fmt == "json":
        _write_output(report.to_json(devices, meta), args.output)
    elif fmt == "csv":
        _write_output(report.to_csv(devices), args.output)
    elif fmt == "html":
        _write_output(report.to_html(devices, meta), args.output)
    else:
        try:
            width = os.get_terminal_size().columns
        except OSError:
            width = 200
        table = report.text_table(devices, args.services, max(80, width - 1),
                                  args.why, True if args.notes else None)
        _write_output(table, args.output)
        if not args.quiet and not args.output:
            sys.stderr.write("\n" + report.summary(devices, duration) + "\n")
    if not args.quiet:
        missing = sum(1 for d in devices if d.mac and not d.vendor)
        if missing >= 3 and not os.path.exists(oui.OUI_CACHE_FILE):
            sys.stderr.write(
                "Tipp: bei %d Geräten ist der Hersteller unbekannt. "
                "'python -m scanip --update-oui' laedt die vollstaendige "
                "IEEE-Liste nach.\n" % missing)
    return 0
