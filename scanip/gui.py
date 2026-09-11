"""Grafische Oberfläche (tkinter - auf Windows und macOS vorinstalliert)."""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from . import __version__, netinfo, oui, ports as portscan, report
from .scanner import Device, ScanOptions, Scanner, expand_targets

PORT_PRESETS = [
    ("Schnell (12 Ports)", "12"),
    ("Standard (96 Ports)", "top"),
    ("Erweitert (1-1024)", "1-1024"),
    ("Gründlich (1-10000)", "1-10000"),
    ("Alle (1-65535)", "all"),
]

COLUMNS = [
    ("ip", "IP-Adresse", 130),
    ("mac", "MAC-Adresse", 145),
    ("vendor", "Hersteller", 165),
    ("hostname", "Gerätename", 220),
    ("category", "Kategorie", 160),
    ("ports", "Offene Ports", 320),
]


class ScanApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("scanip %s - Netzwerk-Scanner" % __version__)
        self.root.minsize(880, 420)
        self._center_window(1180, 640)

        self.queue: "queue.Queue" = queue.Queue()
        self.scanner: Optional[Scanner] = None
        self.thread: Optional[threading.Thread] = None
        self.devices: List[Device] = []
        self.started = 0.0
        self._sort_column = "ip"
        self._sort_reverse = False

        self._build_widgets()
        self._prefill_target()
        self._refresh_table()
        self.root.after(80, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ #
    # Aufbau
    # ------------------------------------------------------------------ #

    def _center_window(self, width: int, height: int) -> None:
        """Fenster mittig auf dem Bildschirm - nie ausserhalb des sichtbaren Bereichs."""
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        width = min(width, max(880, screen_width - 80))
        height = min(height, max(420, screen_height - 120))
        x = max(0, (screen_width - width) // 2)
        y = max(0, (screen_height - height) // 3)
        self.root.geometry("%dx%d+%d+%d" % (width, height, x, y))

    def bring_to_front(self) -> None:
        """Holt das Fenster nach vorn.

        Aus einem Shell-Skript gestartete Tk-Programme landen unter macOS sonst
        hinter dem Terminal-Fenster.
        """
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.attributes("-topmost", True)
            self.root.after(600, lambda: self.root.attributes("-topmost", False))
            self.root.focus_force()
        except tk.TclError:
            pass

    def _build_widgets(self) -> None:
        top = ttk.Frame(self.root, padding=(10, 10, 10, 6))
        top.pack(fill="x")

        ttk.Label(top, text="Netz / Bereich:").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(top, textvariable=self.target_var, width=30)
        self.target_entry.grid(row=0, column=1, padx=(6, 14), sticky="w")

        ttk.Label(top, text="Ports:").grid(row=0, column=2, sticky="w")
        self.preset_var = tk.StringVar(value=PORT_PRESETS[1][0])
        preset = ttk.Combobox(top, textvariable=self.preset_var, width=20,
                              state="readonly",
                              values=[label for label, _spec in PORT_PRESETS])
        preset.grid(row=0, column=3, padx=(6, 14), sticky="w")

        self.deep_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Namen & Dienste ermitteln (mDNS, NetBIOS, SNMP, UPnP)",
                        variable=self.deep_var).grid(row=0, column=4, sticky="w")

        self.start_button = ttk.Button(top, text="Scan starten", command=self._toggle_scan)
        self.start_button.grid(row=0, column=5, padx=(14, 0), sticky="e")
        top.columnconfigure(4, weight=1)

        # Filter
        filter_row = ttk.Frame(self.root, padding=(10, 0, 10, 6))
        filter_row.pack(fill="x")
        ttk.Label(filter_row, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_a: self._refresh_table())
        ttk.Entry(filter_row, textvariable=self.filter_var, width=34).pack(
            side="left", padx=(6, 12))
        self.count_label = ttk.Label(filter_row, text="")
        self.count_label.pack(side="left")

        ttk.Button(filter_row, text="HTML-Report",
                   command=lambda: self._export("html")).pack(side="right")
        ttk.Button(filter_row, text="CSV",
                   command=lambda: self._export("csv")).pack(side="right", padx=6)
        ttk.Button(filter_row, text="JSON",
                   command=lambda: self._export("json")).pack(side="right")

        # Tabelle
        table_frame = ttk.Frame(self.root, padding=(10, 0, 10, 0))
        table_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table_frame, columns=[c[0] for c in COLUMNS],
                                 show="headings", selectmode="browse")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title,
                              command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, anchor="w",
                             stretch=(key in ("hostname", "ports")))
        vbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vbar.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._show_details)
        self.tree.tag_configure("gateway", font=("TkDefaultFont", 10, "bold"))
        self.tree.tag_configure("unknown", foreground="#888888")

        # Fußleiste
        bottom = ttk.Frame(self.root, padding=(10, 6, 10, 10))
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="determinate", length=240)
        self.progress.pack(side="left")
        self.status_var = tk.StringVar(value="Bereit.")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left", padx=12)
        ttk.Label(bottom, text="Doppelklick auf eine Zeile zeigt Details",
                  foreground="#888888").pack(side="right")

    def _prefill_target(self) -> None:
        networks = netinfo.default_networks()
        if networks:
            network = networks[0]
            if network.num_addresses > 8192:
                own = netinfo.primary_ip()
                self.target_var.set("%s/24" % own if own else str(network))
            else:
                self.target_var.set(str(network))
        else:
            self.target_var.set("192.168.1.0/24")

    # ------------------------------------------------------------------ #
    # Scan-Steuerung
    # ------------------------------------------------------------------ #

    def _toggle_scan(self) -> None:
        if self.thread and self.thread.is_alive():
            if self.scanner:
                self.scanner.cancel()
            self.status_var.set("Wird abgebrochen ...")
            return
        self._start_scan()

    def _start_scan(self) -> None:
        spec = self.target_var.get().strip()
        try:
            targets = expand_targets([spec])
        except ValueError as exc:
            messagebox.showerror("Ungültiges Ziel", str(exc))
            return
        if not targets:
            messagebox.showerror("Ungültiges Ziel", "Bitte ein Netz angeben.")
            return
        if len(targets) > 20000 and not messagebox.askyesno(
                "Großer Bereich",
                "%d Adressen werden gescannt. Das dauert sehr lange. Fortfahren?"
                % len(targets)):
            return

        spec_value = dict(PORT_PRESETS)[self.preset_var.get()]
        port_list = (list(portscan.DISCOVERY_PORTS) if spec_value == "12"
                     else portscan.parse_port_spec(spec_value))
        deep = self.deep_var.get()
        options = ScanOptions(
            ports=port_list,
            use_mdns=deep, use_netbios=deep, use_snmp=deep,
            use_ssdp=deep, use_banner=deep,
        )
        self.scanner = Scanner(options)
        self.devices = []
        self.tree.delete(*self.tree.get_children())
        self.progress.configure(value=0, maximum=len(targets))
        self.start_button.configure(text="Abbrechen")
        self.status_var.set("Scan läuft ...")
        self.started = time.time()

        def work() -> None:
            try:
                oui.load_external()
                devices = self.scanner.scan(targets, self._progress_from_thread)
                self.queue.put(("result", devices))
            except Exception as exc:                            # noqa: BLE001
                self.queue.put(("error", str(exc)))

        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()

    def _progress_from_thread(self, phase: str, done: int, total: int,
                              message: str) -> None:
        self.queue.put(("progress", (phase, done, total, message)))

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "progress":
                    phase, done, total, message = payload
                    self.progress.configure(maximum=max(1, total), value=done)
                    label = {"discovery": "Suche aktive Hosts",
                             "detail": "Analysiere Geräte",
                             "done": "Fertig"}.get(phase, phase)
                    self.status_var.set("%s: %d/%d  %s" % (label, done, total, message))
                elif kind == "result":
                    self.devices = payload
                    self._finish()
                elif kind == "error":
                    self.start_button.configure(text="Scan starten")
                    messagebox.showerror("Fehler beim Scan", payload)
                    self.status_var.set("Fehler.")
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _finish(self) -> None:
        duration = time.time() - self.started
        self.start_button.configure(text="Scan starten")
        self.progress.configure(value=self.progress.cget("maximum"))
        self._refresh_table()
        unknown_vendor = sum(1 for d in self.devices if d.mac and not d.vendor)
        hint = ""
        if unknown_vendor >= 3 and not os.path.exists(oui.OUI_CACHE_FILE):
            hint = "  (Tipp: 'python -m scanip --update-oui' ergaenzt fehlende Hersteller)"
        self.status_var.set("%d Geräte in %.1f s.%s" % (len(self.devices), duration, hint))

    # ------------------------------------------------------------------ #
    # Tabelle
    # ------------------------------------------------------------------ #

    def _visible_devices(self) -> List[Device]:
        devices = report.filter_devices(self.devices, self.filter_var.get())
        return report.sort_devices(devices, self._sort_column, self._sort_reverse)

    def _refresh_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        devices = self._visible_devices()
        if not devices:
            if not self.devices:
                hint = "Noch kein Scan durchgeführt \u2013 oben auf \u201eScan starten\u201c klicken"
            elif self.filter_var.get().strip():
                hint = "Kein Gerät passt zum Filter \u201e%s\u201c" % self.filter_var.get().strip()
            else:
                hint = "Keine Geräte gefunden"
            self.tree.insert("", "end", iid="__hinweis__", tags=("unknown",),
                             values=("", "", "", hint, "", ""))
            self.count_label.configure(
                text="0 von %d Geräten" % len(self.devices) if self.devices else "")
            return
        for device in devices:
            name = device.hostname or ""
            if device.is_self:
                name = (name + "  (dieser Rechner)").strip()
            elif device.is_gateway:
                name = (name + "  (Gateway)").strip()
            tags = []
            if device.is_gateway:
                tags.append("gateway")
            if device.category == "Unbekannt":
                tags.append("unknown")
            self.tree.insert("", "end", iid=device.ip, tags=tags, values=(
                device.ip,
                device.mac or "-",
                device.vendor or "-",
                name or "-",
                device.category + (" (?)" if device.confidence == "niedrig"
                                   and device.category != "Unbekannt" else ""),
                portscan.format_ports(device.open_ports, True),
            ))
        self.count_label.configure(
            text="%d von %d Geräten" % (len(devices), len(self.devices))
            if self.devices else "")

    def _sort_by(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False
        self._refresh_table()

    def _show_details(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection or selection[0] == "__hinweis__":
            return
        device = next((d for d in self.devices if d.ip == selection[0]), None)
        if device is None:
            return

        window = tk.Toplevel(self.root)
        window.title("Details - %s" % device.ip)
        window.geometry("620x520")
        text = tk.Text(window, wrap="word", padx=12, pady=10, height=24)
        scroll = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        lines = [
            "IP-Adresse:   %s" % device.ip,
            "MAC-Adresse:  %s" % (device.mac or "-"),
            "Hersteller:   %s" % (device.vendor or "unbekannt"),
            "Gerätename:  %s" % (device.hostname or "-"),
            "Kategorie:    %s (Sicherheit: %s)" % (device.category, device.confidence),
            "Antwortzeit:  %s" % ("%.1f ms" % device.rtt_ms if device.rtt_ms else "-"),
            "Gefunden über: %s" % (", ".join(sorted(device.sources)) or "-"),
            "",
            "Begründung der Kategorie:",
        ]
        lines += ["  - %s" % reason for reason in device.reasons] or ["  - keine"]
        lines += ["", "Offene Ports (%d):" % len(device.open_ports)]
        for port in device.open_ports:
            name = portscan.service_name(port)
            lines.append("  %-6d %s" % (port, name or ""))
        if device.names:
            lines += ["", "Namensquellen:"]
            lines += ["  %-14s %s" % (key, value) for key, value in device.names.items()]
        if device.evidence:
            lines += ["", "Erkannte Kennungen:"]
            lines += ["  %-18s %s" % (key, value)
                      for key, value in sorted(device.evidence.items())]

        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")

        buttons = ttk.Frame(window, padding=8)
        buttons.pack(side="bottom", fill="x")
        for port in device.open_ports:
            if port in portscan.HTTP_PORTS or port in portscan.HTTPS_PORTS:
                scheme = "https" if port in portscan.HTTPS_PORTS else "http"
                url = "%s://%s%s" % (scheme, device.ip,
                                     "" if port in (80, 443) else ":%d" % port)
                ttk.Button(buttons, text="Weboberfläche %d" % port,
                           command=lambda u=url: webbrowser.open(u)).pack(side="left", padx=4)
                break

    # ------------------------------------------------------------------ #

    def _export(self, fmt: str) -> None:
        if not self.devices:
            messagebox.showinfo("Kein Ergebnis", "Bitte zuerst einen Scan ausführen.")
            return
        extensions = {"html": ".html", "csv": ".csv", "json": ".json"}
        path = filedialog.asksaveasfilename(
            defaultextension=extensions[fmt],
            initialfile="netzwerk-scan" + extensions[fmt],
            filetypes=[(fmt.upper(), "*" + extensions[fmt]), ("Alle Dateien", "*.*")])
        if not path:
            return
        meta = {"Netz": self.target_var.get(), "Geräte": len(self.devices)}
        content = {"html": lambda: report.to_html(self.devices, meta),
                   "csv": lambda: report.to_csv(self.devices),
                   "json": lambda: report.to_json(self.devices, meta)}[fmt]()
        try:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
        except OSError as exc:
            messagebox.showerror("Speichern fehlgeschlagen", str(exc))
            return
        self.status_var.set("Gespeichert: %s" % path)
        if fmt == "html" and messagebox.askyesno("Report gespeichert",
                                                 "Report jetzt im Browser öffnen?"):
            webbrowser.open("file://" + os.path.abspath(path))

    def _on_close(self) -> None:
        if self.scanner:
            self.scanner.cancel()
        self.root.destroy()


MIN_TK_VERSION = (8, 6)


def tk_version() -> tuple:
    """Tk-Version dieses Python - ohne ein Fenster zu öffnen."""
    try:
        patchlevel = tk.Tcl().eval("info patchlevel")
        return tuple(int(part) for part in patchlevel.split(".")[:2])
    except Exception:                                       # noqa: BLE001
        return (0, 0)


def tk_is_usable() -> bool:
    """Apples Tk 8.5.9 zeichnet auf aktuellem macOS nur ein weißes Fenster."""
    return tk_version() >= MIN_TK_VERSION


def run_gui() -> int:
    if not tk_is_usable():
        version = ".".join(str(v) for v in tk_version())
        sys.stderr.write(
            "Warnung: Dieses Python nutzt Tk %s. Versionen vor 8.6 zeichnen auf\n"
            "aktuellem macOS nur ein leeres Fenster. Starte stattdessen die\n"
            "Browser-Oberfläche (--force-tk erzwingt trotzdem die Tk-Version).\n"
            % (version or "unbekannt"))
    root = tk.Tk()
    try:
        if sys.platform == "darwin":
            root.tk.call("tk", "scaling", 1.4)
        style = ttk.Style(root)
        if "aqua" in style.theme_names():
            style.theme_use("aqua")
        elif "vista" in style.theme_names():
            style.theme_use("vista")
    except tk.TclError:
        pass
    app = ScanApp(root)
    root.after(100, app.bring_to_front)
    root.mainloop()
    return 0
