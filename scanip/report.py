"""Ausgabeformate: Texttabelle, CSV, JSON und HTML-Report."""

from __future__ import annotations

import csv
import html
import io
import json
import time
from typing import Dict, List, Optional, Sequence

from .ports import format_ports, service_name
from .scanner import Device

COLUMNS = [
    ("ip", "IP-Adresse"),
    ("mac", "MAC-Adresse"),
    ("vendor", "Hersteller"),
    ("hostname", "Gerätename"),
    ("category", "Kategorie"),
    ("ports", "Offene Ports"),
]


def _cell(device: Device, key: str, with_services: bool = False,
          port_limit: int = 0) -> str:
    if key == "ports":
        return format_ports(device.open_ports, with_services, port_limit)
    if key == "category":
        text = device.category
        if device.confidence == "niedrig" and text != "Unbekannt":
            text += " (?)"
        return text
    value = getattr(device, key, None)
    if key == "hostname" and device.is_gateway and not value:
        return "(Gateway)"
    return value if value else "-"


def _visible_len(text: str) -> int:
    return len(text)


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[:max(1, width - 1)] + "…" if width > 1 else text[:width]


def text_table(devices: Sequence[Device], with_services: bool = False,
               max_width: int = 200, show_why: bool = False) -> str:
    """ASCII-Tabelle (funktioniert in jeder Konsole)."""
    columns = list(COLUMNS)
    if show_why:
        columns.append(("why", "Begründung"))

    rows: List[List[str]] = []
    for device in devices:
        row = []
        for key, _title in columns:
            if key == "why":
                row.append("; ".join(device.reasons[:2]) or "-")
            else:
                row.append(_cell(device, key, with_services))
        rows.append(row)

    headers = [title for _key, title in columns]
    widths = [max(_visible_len(headers[i]), *(_visible_len(r[i]) for r in rows))
              if rows else _visible_len(headers[i]) for i in range(len(columns))]

    # Zu breite Tabelle: die Port-/Begründungsspalte zuerst kürzen
    limits = {"ports": 46, "why": 40, "vendor": 26, "hostname": 30, "category": 22}
    for index, (key, _title) in enumerate(columns):
        if key in limits:
            widths[index] = min(widths[index], limits[key])
    # Passt die Tabelle nicht in die Konsole, wird jeweils die breiteste
    # Spalte um ein Zeichen gekürzt, bis es passt (Mindestbreite 8).
    separator = 2
    minimum = 8

    def total() -> int:
        return sum(widths) + separator * (len(widths) - 1)

    shrinkable = {"why", "ports", "vendor", "hostname", "category", "mac"}
    while total() > max_width:
        candidates = [i for i, (key, _t) in enumerate(columns)
                      if key in shrinkable and widths[i] > minimum]
        if not candidates:
            break
        widest = max(candidates, key=lambda i: widths[i])
        widths[widest] -= 1

    out = io.StringIO()
    header = "  ".join(_truncate(headers[i], widths[i]).ljust(widths[i])
                        for i in range(len(columns)))
    out.write(header.rstrip() + "\n")
    out.write("  ".join("-" * widths[i] for i in range(len(columns))) + "\n")
    for row in rows:
        cells = [_truncate(row[i], widths[i]).ljust(widths[i])
                 for i in range(len(columns))]
        out.write("  ".join(cells).rstrip() + "\n")
    return out.getvalue()


def summary(devices: Sequence[Device], duration: Optional[float] = None) -> str:
    """Kurze Zusammenfassung nach Kategorie."""
    counts: Dict[str, int] = {}
    for device in devices:
        counts[device.category] = counts.get(device.category, 0) + 1
    parts = ["%s: %d" % (category, count)
             for category, count in sorted(counts.items(), key=lambda kv: -kv[1])]
    text = "%d Geräte gefunden" % len(devices)
    if duration is not None:
        text += " in %.1f s" % duration
    if parts:
        text += "\n" + " | ".join(parts)
    return text


def to_json(devices: Sequence[Device], meta: Optional[Dict] = None) -> str:
    payload = {
        "scan": meta or {},
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(devices),
        "devices": [device.to_dict() for device in devices],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_csv(devices: Sequence[Device], delimiter: str = ";") -> str:
    out = io.StringIO()
    writer = csv.writer(out, delimiter=delimiter, lineterminator="\n")
    writer.writerow(["IP-Adresse", "MAC-Adresse", "Hersteller", "Gerätename",
                     "Kategorie", "Sicherheit", "Offene Ports", "Dienste",
                     "Begründung", "Gateway"])
    for device in devices:
        writer.writerow([
            device.ip,
            device.mac or "",
            device.vendor or "",
            device.hostname or "",
            device.category,
            device.confidence,
            " ".join(str(p) for p in device.open_ports),
            " ".join("%d/%s" % (p, service_name(p)) for p in device.open_ports
                     if service_name(p)),
            "; ".join(device.reasons),
            "ja" if device.is_gateway else "",
        ])
    return out.getvalue()


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Netzwerk-Scan %(title)s</title>
<style>
  :root {
    --bg: #f6f7f9; --fg: #1b1f24; --muted: #5c6570; --card: #ffffff;
    --line: #dfe3e8; --accent: #2b6cb0; --chip: #eef2f7;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171a; --fg:#e8eaed; --muted:#9aa4af; --card:#1d2125;
            --line:#2e343b; --accent:#79b8ff; --chip:#262c33; }
  }
  * { box-sizing: border-box; }
  body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  h1 { font-size:20px; margin:0 0 4px; }
  .meta { color:var(--muted); margin-bottom:16px; font-size:13px; }
  .stats { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:18px; }
  .chip { background:var(--chip); border:1px solid var(--line); border-radius:999px;
          padding:4px 12px; font-size:12px; }
  .wrap { background:var(--card); border:1px solid var(--line); border-radius:10px;
          overflow-x:auto; }
  table { border-collapse:collapse; width:100%%; min-width:700px; }
  th, td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line);
           vertical-align:top; }
  th { position:sticky; top:0; background:var(--card); cursor:pointer;
       font-size:12px; text-transform:uppercase; letter-spacing:.04em;
       color:var(--muted); white-space:nowrap; }
  th:hover { color:var(--accent); }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:var(--chip); }
  code { font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  .ports code { display:inline-block; background:var(--chip); border-radius:4px;
                padding:1px 5px; margin:1px 2px 1px 0; }
  .cat { white-space:nowrap; font-weight:600; }
  .low { font-weight:400; color:var(--muted); }
  .why { color:var(--muted); font-size:12px; max-width:320px; }
  /* Auf schmalen Fenstern die Begründungsspalte ausblenden, damit die
     Tabelle ohne Querscrollen lesbar bleibt und die Zeilen flach werden. */
  @media (max-width: 950px) {
    .why, th.why-head { display:none; }
    table { min-width:600px; }
  }
  input { width:100%%; max-width:340px; padding:8px 12px; margin-bottom:14px;
          border:1px solid var(--line); border-radius:8px; background:var(--card);
          color:var(--fg); font-size:14px; }
  footer { color:var(--muted); font-size:12px; margin-top:14px; }
</style>
</head>
<body>
<h1>Netzwerk-Scan</h1>
<div class="meta">%(meta)s</div>
<div class="stats">%(stats)s</div>
<input id="q" type="search" placeholder="Filtern (IP, Name, Hersteller, Kategorie) ...">
<div class="wrap">
<table id="t">
<thead><tr>%(head)s</tr></thead>
<tbody>%(rows)s</tbody>
</table>
</div>
<footer>Erstellt mit scanip &middot; Spalten sind per Klick sortierbar</footer>
<script>
var table = document.getElementById('t');
var dir = {};
table.querySelectorAll('th').forEach(function (th, index) {
  th.addEventListener('click', function () {
    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    dir[index] = !dir[index];
    rows.sort(function (a, b) {
      var x = a.cells[index].dataset.sort || a.cells[index].innerText;
      var y = b.cells[index].dataset.sort || b.cells[index].innerText;
      var nx = parseFloat(x), ny = parseFloat(y);
      var cmp = (!isNaN(nx) && !isNaN(ny)) ? nx - ny : x.localeCompare(y, 'de');
      return dir[index] ? cmp : -cmp;
    });
    rows.forEach(function (row) { body.appendChild(row); });
  });
});
document.getElementById('q').addEventListener('input', function (event) {
  var needle = event.target.value.toLowerCase();
  Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
    row.style.display = row.innerText.toLowerCase().indexOf(needle) === -1 ? 'none' : '';
  });
});
</script>
</body>
</html>
"""


def to_html(devices: Sequence[Device], meta: Optional[Dict] = None) -> str:
    meta = meta or {}
    counts: Dict[str, int] = {}
    for device in devices:
        counts[device.category] = counts.get(device.category, 0) + 1

    titles = ["IP-Adresse", "MAC-Adresse", "Hersteller", "Gerätename",
              "Kategorie", "Offene Ports", "Begründung"]
    head = "".join("<th%s>%s</th>" % (" class='why-head'" if title == "Begründung"
                                      else "", html.escape(title))
                   for title in titles)

    rows = []
    for device in devices:
        ports_html = " ".join(
            "<code>%d%s</code>" % (port, "/" + service_name(port)
                                   if service_name(port) else "")
            for port in device.open_ports) or "<span class='low'>-</span>"
        name = device.hostname or ""
        if device.is_gateway:
            name = (name + " (Gateway)").strip()
        if device.is_self:
            name = (name + " (dieser Rechner)").strip()
        category_class = "cat low" if device.confidence == "niedrig" else "cat"
        sort_ip = "%03d%03d%03d%03d" % tuple(int(p) for p in device.ip.split("."))
        rows.append(
            "<tr>"
            "<td data-sort='%s'><code>%s</code></td>"
            "<td><code>%s</code></td><td>%s</td><td>%s</td>"
            "<td class='%s'>%s</td><td class='ports'>%s</td><td class='why'>%s</td>"
            "</tr>" % (
                sort_ip, html.escape(device.ip),
                html.escape(device.mac or "-"),
                html.escape(device.vendor or "-"),
                html.escape(name or "-"),
                category_class,
                html.escape(device.category),
                ports_html,
                html.escape("; ".join(device.reasons[:3]) or "-"),
            ))

    stats = "".join("<span class='chip'>%s &middot; %d</span>"
                    % (html.escape(category), count)
                    for category, count in sorted(counts.items(), key=lambda kv: -kv[1]))
    meta_text = " &middot; ".join(
        html.escape("%s: %s" % (key, value)) for key, value in meta.items())
    meta_text = (meta_text + " &middot; " if meta_text else "") + \
                time.strftime("%d.%m.%Y %H:%M")

    return _HTML_TEMPLATE % {
        "title": html.escape(str(meta.get("Netz", ""))),
        "meta": meta_text,
        "stats": stats,
        "head": head,
        "rows": "".join(rows),
    }

# --------------------------------------------------------------------------- #
# Filtern und Sortieren (von GUI und CLI gemeinsam genutzt)
# --------------------------------------------------------------------------- #

def device_haystack(device: Device) -> str:
    """Alle durchsuchbaren Textbestandteile eines Geräts."""
    parts = [device.ip, device.mac or "", device.vendor or "",
             device.hostname or "", device.category,
             " ".join(str(p) for p in device.open_ports),
             " ".join(service_name(p) for p in device.open_ports)]
    return " ".join(parts).lower()


def filter_devices(devices: Sequence[Device], needle: str) -> List[Device]:
    """Freitextfilter über IP, MAC, Hersteller, Name, Kategorie und Ports.

    Mehrere Begriffe müssen alle zutreffen ("drucker 192.168.1").
    """
    terms = [t for t in (needle or "").lower().split() if t]
    if not terms:
        return list(devices)
    result = []
    for device in devices:
        haystack = device_haystack(device)
        if all(term in haystack for term in terms):
            result.append(device)
    return result


def sort_devices(devices: Sequence[Device], key: str = "ip",
                 reverse: bool = False) -> List[Device]:
    """Sortiert nach Spalte; die IP dient immer als zweites Kriterium."""
    def sort_key(device: Device):
        if key == "ip":
            return ((), device.sort_key)
        if key == "ports":
            return ((len(device.open_ports),), device.sort_key)
        value = getattr(device, key, "") or ""
        return ((str(value).lower(),), device.sort_key)
    return sorted(devices, key=sort_key, reverse=reverse)
