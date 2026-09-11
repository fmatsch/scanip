"""Browser-Oberfläche: lokaler Webserver mit Live-Fortschritt.

Startet einen HTTP-Server auf 127.0.0.1 (nur lokal erreichbar) und öffnet den
Standardbrowser. Unabhängig von Tk und damit auf jedem Rechner mit Python
identisch nutzbar.

Sicherheit: Der Server lauscht ausschließlich auf der Loopback-Adresse und
verlangt für jeden API-Aufruf ein zufälliges Token, das beim Start erzeugt und
nur in der geöffneten URL übergeben wird. Damit kann keine fremde Webseite im
Browser den Scanner fernsteuern.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from . import __version__, netinfo, oui, ports as portscan, report
from .scanner import Device, ScanOptions, Scanner, expand_targets

PORT_PRESETS = {
    "fast": ("Schnell (12 Ports)", None),
    "top": ("Standard (96 Ports)", "top"),
    "1024": ("Erweitert (1-1024)", "1-1024"),
    "10000": ("Gründlich (1-10000)", "1-10000"),
    "all": ("Alle (1-65535)", "all"),
}


class ScanState:
    """Gemeinsamer Zustand zwischen Scan-Thread und Webserver."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.scanner: Optional[Scanner] = None
        self.thread: Optional[threading.Thread] = None
        self.devices: List[Device] = []
        self.phase = "idle"
        self.done = 0
        self.total = 0
        self.message = ""
        self.started = 0.0
        self.duration = 0.0
        self.error: Optional[str] = None
        self.target_spec = ""

    @property
    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def snapshot(self) -> Dict:
        with self.lock:
            return {
                "running": self.running,
                "phase": self.phase,
                "done": self.done,
                "total": self.total,
                "message": self.message,
                "duration": round(self.duration, 1),
                "error": self.error,
                "target": self.target_spec,
                "devices": [self._device_row(d) for d in self.devices],
            }

    @staticmethod
    def _device_row(device: Device) -> Dict:
        data = device.to_dict()
        data["ports_text"] = portscan.format_ports(device.open_ports, True)
        data["name_suffix"] = ("dieser Rechner" if device.is_self
                               else "Gateway" if device.is_gateway else "")
        data["web_url"] = next(
            ("%s://%s%s" % ("https" if p in portscan.HTTPS_PORTS else "http",
                            device.ip, "" if p in (80, 443) else ":%d" % p)
             for p in device.open_ports
             if p in portscan.HTTP_PORTS or p in portscan.HTTPS_PORTS), None)
        return data

    def start(self, target_spec: str, preset: str, deep: bool) -> Optional[str]:
        if self.running:
            return "Es läuft bereits ein Scan."
        try:
            targets = expand_targets([target_spec])
        except ValueError as exc:
            return "Ungültiges Ziel: %s" % exc
        if not targets:
            return "Kein gültiges Ziel angegeben."

        spec = PORT_PRESETS.get(preset, PORT_PRESETS["top"])[1]
        port_list = (list(portscan.DISCOVERY_PORTS) if spec is None
                     else portscan.parse_port_spec(spec))
        options = ScanOptions(
            ports=port_list,
            use_mdns=deep, use_netbios=deep, use_snmp=deep,
            use_ssdp=deep, use_banner=deep,
        )
        with self.lock:
            self.scanner = Scanner(options)
            self.devices = []
            self.phase = "discovery"
            self.done = 0
            self.total = len(targets)
            self.message = "Scan wird gestartet ..."
            self.error = None
            self.duration = 0.0
            self.started = time.time()
            self.target_spec = target_spec

        def progress(phase: str, done: int, total: int, message: str) -> None:
            with self.lock:
                self.phase = phase
                self.done = done
                self.total = total
                self.message = message
                self.duration = time.time() - self.started

        def work() -> None:
            try:
                oui.load_external()
                devices = self.scanner.scan(targets, progress)
                with self.lock:
                    self.devices = devices
                    self.phase = "done"
                    self.duration = time.time() - self.started
            except Exception as exc:                            # noqa: BLE001
                with self.lock:
                    self.error = str(exc)
                    self.phase = "error"

        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()
        return None

    def cancel(self) -> None:
        with self.lock:
            if self.scanner:
                self.scanner.cancel()
            self.message = "Wird abgebrochen ..."


def _default_target() -> str:
    networks = netinfo.default_networks()
    if not networks:
        return "192.168.1.0/24"
    network = networks[0]
    if network.num_addresses > 8192:
        own = netinfo.primary_ip()
        return "%s/24" % own if own else str(network)
    return str(network)


class Handler(BaseHTTPRequestHandler):
    server_version = "scanip/" + __version__
    state: ScanState
    token: str

    def log_message(self, fmt, *args):            # Zugriffe nicht protokollieren
        pass

    # -- Hilfsfunktionen ------------------------------------------------- #

    def _send(self, code: int, body: bytes, content_type: str,
              filename: Optional[str] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"' % filename)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data: Dict, code: int = 200) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _authorized(self, query: Dict[str, List[str]]) -> bool:
        """Token aus Query oder Header - schützt vor Zugriff fremder Webseiten."""
        supplied = (query.get("token", [""])[0]
                    or self.headers.get("X-Scanip-Token", ""))
        if not secrets.compare_digest(supplied, self.token):
            return False
        # Zusätzlich: nur Anfragen an die eigene Loopback-Adresse akzeptieren
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]", "::1")

    # -- Routen ---------------------------------------------------------- #

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            token = query.get("token", [""])[0]
            if not secrets.compare_digest(token, self.token):
                self._send(403, b"Zugriff verweigert: ungueltiges Token.",
                           "text/plain; charset=utf-8")
                return
            page = PAGE_TEMPLATE % {
                "version": __version__,
                "token": self.token,
                "target": _default_target(),
                "presets": "".join(
                    '<option value="%s"%s>%s</option>'
                    % (key, " selected" if key == "top" else "", label)
                    for key, (label, _spec) in PORT_PRESETS.items()),
            }
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return

        if not self._authorized(query):
            self._json({"error": "nicht autorisiert"}, 403)
            return

        if path == "/api/status":
            self._json(self.state.snapshot())
            return

        if path == "/api/export":
            fmt = query.get("format", ["html"])[0]
            devices = self.state.devices
            meta = {"Netz": self.state.target_spec or "-",
                    "Geräte": len(devices)}
            if fmt == "csv":
                body, ctype, name = (report.to_csv(devices),
                                     "text/csv; charset=utf-8", "netzwerk-scan.csv")
            elif fmt == "json":
                body, ctype, name = (report.to_json(devices, meta),
                                     "application/json; charset=utf-8",
                                     "netzwerk-scan.json")
            else:
                body, ctype, name = (report.to_html(devices, meta),
                                     "text/html; charset=utf-8", "netzwerk-scan.html")
            self._send(200, body.encode("utf-8"), ctype, name)
            return

        self._json({"error": "unbekannter Pfad"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._authorized(query):
            self._json({"error": "nicht autorisiert"}, 403)
            return

        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            payload = {}

        if parsed.path == "/api/scan":
            error = self.state.start(
                str(payload.get("target", "")).strip(),
                str(payload.get("preset", "top")),
                bool(payload.get("deep", True)))
            self._json({"error": error} if error else {"ok": True},
                       400 if error else 200)
            return

        if parsed.path == "/api/cancel":
            self.state.cancel()
            self._json({"ok": True})
            return

        if parsed.path == "/api/quit":
            self._json({"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        self._json({"error": "unbekannter Pfad"}, 404)


def run_web(port: int = 0, open_browser: bool = True,
            host: str = "127.0.0.1") -> int:
    """Startet die Browser-Oberfläche. Liefert den Exitcode."""
    state = ScanState()
    token = secrets.token_urlsafe(24)

    handler = type("BoundHandler", (Handler,), {"state": state, "token": token})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    actual_port = server.server_address[1]
    url = "http://127.0.0.1:%d/?token=%s" % (actual_port, token)

    print("scanip %s - Browser-Oberfläche" % __version__)
    print("Adresse: %s" % url)
    print("Nur lokal erreichbar. Beenden mit Strg+C.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        server.server_close()
    return 0


# --------------------------------------------------------------------------- #
# Oberfläche (einzelne Seite, keine externen Abhängigkeiten)
# --------------------------------------------------------------------------- #

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>scanip - Netzwerk-Scanner</title>
<style>
  :root {
    --bg:#f6f7f9; --fg:#1b1f24; --muted:#5c6570; --card:#fff; --line:#dfe3e8;
    --accent:#2b6cb0; --accent-fg:#fff; --chip:#eef2f7; --ok:#2f855a; --warn:#c05621;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171a; --fg:#e8eaed; --muted:#9aa4af; --card:#1d2125;
            --line:#2e343b; --accent:#3b82f6; --accent-fg:#fff; --chip:#262c33;
            --ok:#68d391; --warn:#f6ad55; }
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:20px; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  h1 { font-size:19px; margin:0 0 2px; }
  .sub { color:var(--muted); font-size:12px; margin-bottom:16px; }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:10px;
           padding:14px; margin-bottom:14px; }
  .row { display:flex; flex-wrap:wrap; gap:12px; align-items:flex-end; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  input[type=text], select, input[type=search] {
    padding:8px 10px; border:1px solid var(--line); border-radius:8px;
    background:var(--bg); color:var(--fg); font-size:14px; font-family:inherit; }
  input[type=text] { width:200px; }
  input[type=search] { width:100%%; max-width:380px; }
  button { padding:9px 16px; border:1px solid transparent; border-radius:8px;
           background:var(--accent); color:var(--accent-fg); font-size:14px;
           font-weight:600; cursor:pointer; font-family:inherit; }
  button:hover { filter:brightness(1.08); }
  button.ghost { background:transparent; color:var(--fg); border-color:var(--line);
                 font-weight:400; }
  button:disabled { opacity:.5; cursor:default; }
  .check { display:flex; align-items:center; gap:6px; font-size:13px; padding-bottom:9px; }
  .bar { height:6px; background:var(--chip); border-radius:99px; overflow:hidden;
         margin-top:12px; }
  .bar > div { height:100%%; width:0; background:var(--accent); border-radius:99px;
               transition:width .25s; }
  .status { font-size:13px; color:var(--muted); margin-top:8px; min-height:20px; }
  .stats { display:flex; flex-wrap:wrap; gap:6px; margin:10px 0 0; }
  .chip { background:var(--chip); border:1px solid var(--line); border-radius:99px;
          padding:3px 10px; font-size:12px; }
  .wrap { background:var(--card); border:1px solid var(--line); border-radius:10px;
          overflow-x:auto; }
  table { border-collapse:collapse; width:100%%; min-width:700px; }
  th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line);
           vertical-align:top; }
  th { position:sticky; top:0; background:var(--card); cursor:pointer; font-size:11px;
       text-transform:uppercase; letter-spacing:.04em; color:var(--muted);
       white-space:nowrap; user-select:none; }
  th:hover { color:var(--accent); }
  tbody tr { cursor:pointer; }
  tbody tr:hover td { background:var(--chip); }
  tr:last-child td { border-bottom:none; }
  code { font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  .ports code { display:inline-block; background:var(--chip); border-radius:4px;
                padding:1px 5px; margin:1px 2px 1px 0; }
  .cat { white-space:nowrap; font-weight:600; }
  .dim { color:var(--muted); font-weight:400; }
  .empty { padding:28px 14px; text-align:center; color:var(--muted); }
  .detail td { background:var(--chip); }
  .detail dl { display:grid; grid-template-columns:max-content 1fr; gap:3px 16px;
               margin:0 0 10px; font-size:13px; }
  .detail dt { color:var(--muted); }
  .detail h4 { margin:10px 0 4px; font-size:12px; text-transform:uppercase;
               letter-spacing:.04em; color:var(--muted); }
  .detail ul { margin:0; padding-left:18px; }
  .spacer { flex:1; }
  a.btn { text-decoration:none; }
  @media (max-width:900px) { .why-col { display:none; } }
</style>
</head>
<body>
<h1>Netzwerk-Scanner</h1>
<div class="sub">scanip %(version)s &middot; lokal auf diesem Rechner</div>

<div class="panel">
  <div class="row">
    <div>
      <label for="target">Netz / Bereich</label>
      <input type="text" id="target" value="%(target)s"
             placeholder="192.168.1.0/24">
    </div>
    <div>
      <label for="preset">Ports</label>
      <select id="preset">%(presets)s</select>
    </div>
    <div class="check">
      <input type="checkbox" id="deep" checked>
      <label for="deep" style="margin:0">Namen &amp; Dienste ermitteln
        (mDNS, NetBIOS, SNMP, UPnP)</label>
    </div>
    <div class="spacer"></div>
    <button id="go">Scan starten</button>
  </div>
  <div class="bar"><div id="progress"></div></div>
  <div class="status" id="status">Bereit.</div>
  <div class="stats" id="stats"></div>
</div>

<div class="panel">
  <div class="row">
    <input type="search" id="filter" placeholder="Filtern (IP, Name, Hersteller, Kategorie, Port) ...">
    <div class="spacer"></div>
    <a class="btn" id="exp-html"><button class="ghost">HTML-Report</button></a>
    <a class="btn" id="exp-csv"><button class="ghost">CSV</button></a>
    <a class="btn" id="exp-json"><button class="ghost">JSON</button></a>
  </div>
</div>

<div class="wrap">
  <table id="table">
    <thead><tr>
      <th data-key="ip">IP-Adresse</th>
      <th data-key="mac">MAC-Adresse</th>
      <th data-key="vendor">Hersteller</th>
      <th data-key="hostname">Gerätename</th>
      <th data-key="category">Kategorie</th>
      <th data-key="ports">Offene Ports</th>
      <th data-key="why" class="why-col">Begründung</th>
    </tr></thead>
    <tbody id="body"><tr><td colspan="7" class="empty">
      Noch kein Scan durchgeführt &ndash; oben auf &bdquo;Scan starten&ldquo; klicken.
    </td></tr></tbody>
  </table>
</div>

<script>
var TOKEN = "%(token)s";
var devices = [], sortKey = "ip", sortDesc = false, running = false, openRow = null;

function api(path, options) {
  options = options || {};
  options.headers = Object.assign({"X-Scanip-Token": TOKEN,
                                   "Content-Type": "application/json"},
                                  options.headers || {});
  return fetch(path + (path.indexOf("?") < 0 ? "?" : "&") +
               "token=" + encodeURIComponent(TOKEN), options);
}

function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function ipKey(ip) {
  return ip.split(".").map(function (p) {
    return ("00" + p).slice(-3); }).join("");
}

function sortValue(device, key) {
  if (key === "ip") return ipKey(device.ip);
  if (key === "ports") return ("0000" + device.open_ports.length).slice(-4) + ipKey(device.ip);
  if (key === "why") return (device.reasons[0] || "").toLowerCase();
  return String(device[key] || "\\uffff").toLowerCase() + ipKey(device.ip);
}

function visible() {
  var terms = document.getElementById("filter").value.toLowerCase().split(/\\s+/)
              .filter(Boolean);
  var list = devices.filter(function (device) {
    if (!terms.length) return true;
    var hay = [device.ip, device.mac, device.vendor, device.hostname,
               device.category, device.ports_text].join(" ").toLowerCase();
    return terms.every(function (term) { return hay.indexOf(term) >= 0; });
  });
  list.sort(function (a, b) {
    var x = sortValue(a, sortKey), y = sortValue(b, sortKey);
    return sortDesc ? (x < y ? 1 : x > y ? -1 : 0) : (x > y ? 1 : x < y ? -1 : 0);
  });
  return list;
}

function detailHtml(device) {
  var rows = [["IP-Adresse", device.ip], ["MAC-Adresse", device.mac || "-"],
              ["Hersteller", device.vendor || "unbekannt"],
              ["Gerätename", device.hostname || "-"],
              ["Kategorie", device.category + " (Sicherheit: " + device.confidence + ")"],
              ["Antwortzeit", device.rtt_ms ? device.rtt_ms + " ms" : "-"],
              ["Gefunden über", (device.sources || []).join(", ") || "-"]];
  var html = "<dl>";
  rows.forEach(function (row) {
    html += "<dt>" + esc(row[0]) + "</dt><dd>" + esc(row[1]) + "</dd>";
  });
  html += "</dl>";
  if (device.reasons.length) {
    html += "<h4>Begründung der Kategorie</h4><ul>";
    device.reasons.forEach(function (r) { html += "<li>" + esc(r) + "</li>"; });
    html += "</ul>";
  }
  if (device.open_ports.length) {
    html += "<h4>Offene Ports (" + device.open_ports.length + ")</h4><div class='ports'>";
    device.open_ports.forEach(function (port) {
      var name = device.services[String(port)];
      html += "<code>" + port + (name ? "/" + esc(name) : "") + "</code> ";
    });
    html += "</div>";
  }
  var keys = Object.keys(device.evidence || {});
  if (keys.length) {
    html += "<h4>Erkannte Kennungen</h4><dl>";
    keys.sort().forEach(function (key) {
      html += "<dt>" + esc(key) + "</dt><dd>" + esc(device.evidence[key]) + "</dd>";
    });
    html += "</dl>";
  }
  if (device.web_url) {
    html += "<p><a href='" + esc(device.web_url) + "' target='_blank' rel='noopener'>" +
            "Weboberfläche öffnen &rarr;</a></p>";
  }
  return "<div class='detail-inner'>" + html + "</div>";
}

function render() {
  var body = document.getElementById("body");
  var list = visible();
  if (!list.length) {
    body.innerHTML = "<tr><td colspan='7' class='empty'>" +
      (devices.length ? "Kein Gerät passt zum Filter."
       : running ? "Suche läuft ..."
       : "Noch kein Scan durchgeführt &ndash; oben auf &bdquo;Scan starten&ldquo; klicken.") +
      "</td></tr>";
    return;
  }
  var html = "";
  list.forEach(function (device) {
    var name = esc(device.hostname || "-");
    if (device.name_suffix) {
      name += " <span class='dim'>(" + esc(device.name_suffix) + ")</span>";
    }
    var ports = device.open_ports.map(function (port) {
      var service = device.services[String(port)];
      return "<code>" + port + (service ? "/" + esc(service) : "") + "</code>";
    }).join(" ") || "<span class='dim'>-</span>";
    html += "<tr data-ip='" + esc(device.ip) + "'>" +
      "<td><code>" + esc(device.ip) + "</code></td>" +
      "<td><code>" + esc(device.mac || "-") + "</code></td>" +
      "<td>" + esc(device.vendor || "-") + "</td>" +
      "<td>" + name + "</td>" +
      "<td class='cat" + (device.confidence === "niedrig" ? " dim" : "") + "'>" +
        esc(device.category) + (device.confidence === "niedrig" &&
          device.category !== "Unbekannt" ? " (?)" : "") + "</td>" +
      "<td class='ports'>" + ports + "</td>" +
      "<td class='why-col dim'>" + esc((device.reasons || []).slice(0, 2).join("; ") || "-") +
      "</td></tr>";
    if (openRow === device.ip) {
      html += "<tr class='detail'><td colspan='7'>" + detailHtml(device) + "</td></tr>";
    }
  });
  body.innerHTML = html;
}

function renderStats(data) {
  var counts = {};
  devices.forEach(function (device) {
    counts[device.category] = (counts[device.category] || 0) + 1;
  });
  var keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
  document.getElementById("stats").innerHTML = keys.map(function (key) {
    return "<span class='chip'>" + esc(key) + " &middot; " + counts[key] + "</span>";
  }).join("");
}

function poll() {
  api("/api/status").then(function (r) { return r.json(); }).then(function (data) {
    running = data.running;
    devices = data.devices || [];
    var share = data.total ? Math.round(data.done * 100 / data.total) : 0;
    document.getElementById("progress").style.width =
      (data.running || data.phase === "done" ? share : 0) + "%%";
    var label = {discovery: "Suche aktive Hosts", detail: "Analysiere Geräte",
                 done: "Fertig", error: "Fehler", idle: "Bereit."}[data.phase] || data.phase;
    var text;
    if (data.error) {
      text = "Fehler: " + data.error;
    } else if (data.running) {
      text = label + ": " + data.done + "/" + data.total +
             (data.message ? "  \\u2013  " + data.message : "");
    } else if (data.phase === "done") {
      text = devices.length + " Geräte in " + data.duration + " s gefunden.";
    } else {
      text = "Bereit.";
    }
    document.getElementById("status").textContent = text;
    document.getElementById("go").textContent = data.running ? "Abbrechen" : "Scan starten";
    render();
    renderStats(data);
  }).catch(function () {
    document.getElementById("status").textContent =
      "Verbindung zum Scanner verloren \\u2013 läuft das Programm noch?";
  });
}

document.getElementById("go").addEventListener("click", function () {
  if (running) {
    api("/api/cancel", {method: "POST"}).then(poll);
    return;
  }
  openRow = null;
  api("/api/scan", {method: "POST", body: JSON.stringify({
    target: document.getElementById("target").value,
    preset: document.getElementById("preset").value,
    deep: document.getElementById("deep").checked
  })}).then(function (r) { return r.json(); }).then(function (data) {
    if (data.error) { document.getElementById("status").textContent = data.error; }
    poll();
  });
});

document.getElementById("filter").addEventListener("input", render);

document.querySelectorAll("th").forEach(function (th) {
  th.addEventListener("click", function () {
    var key = th.dataset.key;
    if (sortKey === key) { sortDesc = !sortDesc; } else { sortKey = key; sortDesc = false; }
    render();
  });
});

document.getElementById("body").addEventListener("click", function (event) {
  var row = event.target.closest("tr[data-ip]");
  if (!row) return;
  openRow = (openRow === row.dataset.ip) ? null : row.dataset.ip;
  render();
});

["html", "csv", "json"].forEach(function (fmt) {
  document.getElementById("exp-" + fmt).href =
    "/api/export?format=" + fmt + "&token=" + encodeURIComponent(TOKEN);
});

document.getElementById("target").addEventListener("keydown", function (event) {
  if (event.key === "Enter") { document.getElementById("go").click(); }
});

poll();
setInterval(poll, 700);
</script>
</body>
</html>
"""
