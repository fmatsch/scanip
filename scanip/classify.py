"""Heuristische Gerätekategorisierung.

Bewertet mehrere unabhängige Indizien (offene Ports, MAC-Hersteller, Hostname,
SNMP-/HTTP-/SSDP-/mDNS-Kennungen) und wählt die Kategorie mit der hoechsten
Punktzahl. Jeder Treffer wird begründet (Feld 'reasons'), damit nachvollziehbar
bleibt, warum ein Gerät so eingeordnet wurde.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Kategorienamen (Anzeige)
ROUTER = "Router / Gateway"
SWITCH = "Switch"
AP = "WLAN Access Point"
FIREWALL = "Firewall / UTM"
PRINTER = "Drucker / MFP"
WIN_PC = "Computer (Windows)"
MAC_PC = "Computer (macOS)"
NIX_PC = "Computer (Linux/Unix)"
SERVER = "Server"
NAS = "NAS / Storage"
PHONE = "IP-Telefon"
CAMERA = "IP-Kamera"
MEDIA = "Smart-TV / Media"
MOBILE = "Smartphone / Tablet"
CONSOLE = "Spielkonsole"
IOT = "Smart-Home / IoT"
INDUSTRIAL = "Industrie / SPS"
UPS = "USV"
VM = "Virtuelle Maschine"
UNKNOWN = "Unbekannt"

# Hersteller-Hinweis (aus oui.py) -> Kategorie
HINT_TO_CATEGORY = {
    "printer": PRINTER, "computer": NIX_PC, "phone": PHONE, "camera": CAMERA,
    "network": ROUTER, "nas": NAS, "media": MEDIA, "iot": IOT,
    "mobile": MOBILE, "console": CONSOLE, "vm": VM, "industrial": INDUSTRIAL,
}

# Port -> [(Kategorie, Punkte, Begründung)]
PORT_RULES: Dict[int, List[Tuple[str, int, str]]] = {
    9100: [(PRINTER, 60, "Port 9100 (RAW-Druck)")],
    9101: [(PRINTER, 30, "Port 9101 (RAW-Druck)")],
    9102: [(PRINTER, 30, "Port 9102 (RAW-Druck)")],
    515: [(PRINTER, 45, "Port 515 (LPD-Druckdienst)")],
    631: [(PRINTER, 25, "Port 631 (IPP)")],
    9295: [(PRINTER, 25, "Port 9295 (Scan-Dienst)")],
    5060: [(PHONE, 55, "Port 5060 (SIP)")],
    5061: [(PHONE, 35, "Port 5061 (SIP/TLS)")],
    2000: [(PHONE, 25, "Port 2000 (Cisco SCCP)")],
    554: [(CAMERA, 45, "Port 554 (RTSP-Videostream)")],
    8554: [(CAMERA, 30, "Port 8554 (RTSP)")],
    37777: [(CAMERA, 55, "Port 37777 (Dahua-DVR)")],
    8000: [(CAMERA, 8, "Port 8000 (häufig bei Kameras)")],
    445: [(WIN_PC, 30, "Port 445 (SMB)"), (NAS, 12, "Port 445 (SMB)")],
    135: [(WIN_PC, 35, "Port 135 (MS-RPC)")],
    139: [(WIN_PC, 20, "Port 139 (NetBIOS)")],
    3389: [(WIN_PC, 45, "Port 3389 (Remotedesktop)")],
    5985: [(WIN_PC, 30, "Port 5985 (WinRM)"), (SERVER, 15, "WinRM")],
    5986: [(WIN_PC, 25, "Port 5986 (WinRM/TLS)")],
    5357: [(WIN_PC, 20, "Port 5357 (WSD)")],
    8172: [(SERVER, 25, "Port 8172 (IIS-Verwaltung)")],
    3283: [(MAC_PC, 40, "Port 3283 (Apple Remote Desktop)")],
    5009: [(MAC_PC, 25, "Port 5009 (AirPort-Verwaltung)")],
    548: [(MAC_PC, 25, "Port 548 (AFP)"), (NAS, 20, "Port 548 (AFP)")],
    # lockdownd läuft auf iPhone/iPad, aber auch auf Apple TV und HomePod
    62078: [(MOBILE, 45, "Port 62078 (Apple-Gerät)"),
            (MEDIA, 12, "Port 62078 (Apple-Gerät)")],
    22: [(NIX_PC, 18, "Port 22 (SSH)")],
    23: [(SWITCH, 10, "Port 23 (Telnet)")],
    111: [(NIX_PC, 12, "Port 111 (RPC)"), (NAS, 10, "Port 111 (RPC)")],
    2049: [(NAS, 45, "Port 2049 (NFS)")],
    3260: [(NAS, 40, "Port 3260 (iSCSI)")],
    5000: [(NAS, 10, "Port 5000 (Synology/UPnP)")],
    5001: [(NAS, 15, "Port 5001 (Synology HTTPS)")],
    873: [(NAS, 15, "Port 873 (rsync)")],
    32400: [(MEDIA, 45, "Port 32400 (Plex-Server)")],
    8009: [(MEDIA, 50, "Port 8009 (Chromecast)")],
    7000: [(MEDIA, 18, "Port 7000 (AirPlay-Empfang)")],
    7100: [(MEDIA, 10, "Port 7100 (AirPlay/Schriftdienst)")],
    3689: [(MEDIA, 25, "Port 3689 (DAAP/iTunes)")],
    1400: [(MEDIA, 35, "Port 1400 (Sonos)")],
    8883: [(IOT, 25, "Port 8883 (MQTT/TLS)")],
    1883: [(IOT, 30, "Port 1883 (MQTT)")],
    8123: [(IOT, 45, "Port 8123 (Home Assistant)")],
    5555: [(MOBILE, 25, "Port 5555 (Android ADB)")],
    7547: [(ROUTER, 45, "Port 7547 (TR-069 Fernwartung)")],
    8291: [(ROUTER, 50, "Port 8291 (MikroTik Winbox)")],
    8728: [(ROUTER, 30, "Port 8728 (MikroTik API)")],
    1723: [(ROUTER, 20, "Port 1723 (PPTP)")],
    500: [(ROUTER, 12, "Port 500 (IPsec)"), (FIREWALL, 12, "Port 500 (IPsec)")],
    53: [(ROUTER, 18, "Port 53 (DNS-Dienst)")],
    67: [(ROUTER, 20, "Port 67 (DHCP-Server)")],
    161: [(SWITCH, 12, "Port 161 (SNMP)")],
    502: [(INDUSTRIAL, 50, "Port 502 (Modbus/TCP)")],
    44818: [(INDUSTRIAL, 50, "Port 44818 (EtherNet/IP)")],
    102: [(INDUSTRIAL, 45, "Port 102 (S7comm)")],
    623: [(SERVER, 35, "Port 623 (IPMI/BMC)")],
    3306: [(SERVER, 20, "Port 3306 (MySQL)")],
    5432: [(SERVER, 20, "Port 5432 (PostgreSQL)")],
    1433: [(SERVER, 20, "Port 1433 (MS SQL)"), (WIN_PC, 10, "MS SQL")],
    9200: [(SERVER, 15, "Port 9200 (Elasticsearch)")],
    27017: [(SERVER, 15, "Port 27017 (MongoDB)")],
    6379: [(SERVER, 12, "Port 6379 (Redis)")],
    2375: [(SERVER, 20, "Port 2375 (Docker)")],
    8006: [(SERVER, 35, "Port 8006 (Proxmox)")],
    10000: [(NAS, 12, "Port 10000 (Webmin)")],
    25: [(SERVER, 12, "Port 25 (SMTP)")],
    389: [(SERVER, 18, "Port 389 (LDAP)"), (WIN_PC, 12, "LDAP")],
    88: [(SERVER, 15, "Port 88 (Kerberos)")],
}

# Textmuster in Hostnamen/Bannern -> (Kategorie, Punkte)
TEXT_RULES: List[Tuple[str, str, int, str]] = [
    # Drucker
    (r"laserjet|officejet|deskjet|designjet|pagewide|envy\b|photosmart", PRINTER, 55, "Druckermodell im Namen"),
    (r"\bprinter\b|drucker|\bmfp\b|imagerunner|imageclass|workcentre|versalink|altalink", PRINTER, 55, "Druckerbezeichnung"),
    (r"\bbrother\b|\bkyocera\b|\blexmark\b|\bricoh\b|\bxerox\b|konica|\bepson\b|\bcanon\b|\boki\b|utax|develop ineo", PRINTER, 35, "Druckerhersteller im Text"),
    (r"jetdirect|pdl-datastream|ipp\b|\blpd\b|taskalfa|ecosys|aficio|bizhub", PRINTER, 45, "Druckdienst-Kennung"),
    # Netzwerk
    (r"fritz!?box|fritz\.box", ROUTER, 65, "FRITZ!Box"),
    (r"routeros|mikrotik", ROUTER, 55, "MikroTik RouterOS"),
    (r"openwrt|dd-wrt|pfsense|opnsense|ipfire", ROUTER, 55, "Router-Betriebssystem"),
    (r"\brouter\b|gateway|speedport|easybox|connect ?box|cable ?box|homebox|\bcpe\b", ROUTER, 35, "Routerbezeichnung"),
    (r"fortigate|sophos|sonicwall|watchguard|checkpoint|palo ?alto", FIREWALL, 60, "Firewall-Produkt"),
    (r"\bswitch\b|procurve|aruba|catalyst|netgear gs|\bsg[0-9]{3}\b|powerconnect", SWITCH, 45, "Switch-Bezeichnung"),
    (r"cisco ios|nx-os|junos|comware|\bswos\b", SWITCH, 45, "Netzwerk-Betriebssystem"),
    (r"unifi|\bu[6ap]-|accesspoint|access ?point|\bap[0-9]{2,}\b|\bwap\b|repeater|extender", AP, 45, "Access-Point-Bezeichnung"),
    # Rechner
    (r"macbook|imac|mac ?mini|mac ?pro|mac ?studio|macos|osx", MAC_PC, 60, "Apple-Rechner im Namen"),
    (r"windows|win(10|11|7|8)|\bpc\b|desktop-[a-z0-9]{7}|notebook|laptop|thinkpad|latitude|elitebook|probook|optiplex|precision", WIN_PC, 40, "Windows-Rechner im Namen"),
    (r"ubuntu|debian|fedora|centos|\barch\b|linux|raspberry|raspberrypi|\brpi\b|proxmox|\besxi\b|vmware", NIX_PC, 40, "Linux/Unix im Namen"),
    (r"\bserver\b|\bsrv\b|\bdc[0-9]?\b|domain ?controller|\bhost[0-9]+\b", SERVER, 35, "Serverbezeichnung"),
    # Speicher
    (r"diskstation|synology|\bqnap\b|\bnas\b|readynas|truenas|freenas|mybook|mycloud|terastation|unraid", NAS, 60, "NAS-Bezeichnung"),
    # Telefonie
    (r"\bsnom\b|yealink|grandstream|polycom|\bvvx\b|gigaset|\bsip\b|telefon|\bphone\b(?!.*smart)|fanvil|\bcp-?[0-9]{3,4}\b", PHONE, 45, "Telefon-Bezeichnung"),
    # Kameras
    (r"hikvision|\bdahua\b|\baxis\b|mobotix|reolink|\bdvr\b|\bnvr\b|ipcam|ip-?camera|kamera|\bcam[0-9]*\b|doorbell|\bring\b|\bnest ?cam\b|wyze|foscam|instar", CAMERA, 55, "Kamera-Bezeichnung"),
    # Medien
    (r"\btv\b|smart-?tv|bravia|viera|\bwebos\b|tizen|android ?tv|googlecast|chromecast|firetv|fire ?stick|apple ?tv|shield", MEDIA, 50, "TV/Streaming-Gerät"),
    (r"\bsonos\b|\bbose\b|denon|marantz|yamaha|heos|\broku\b|\becho\b|homepod|soundbar|receiver|\bzp[0-9]|\bplay:?[0-9]", MEDIA, 45, "Audio-/Media-Gerät"),
    (r"\bplex\b|\bkodi\b|jellyfin|emby", MEDIA, 40, "Medienserver"),
    # Mobil
    (r"iphone|ipad|ipod", MOBILE, 65, "iOS-Gerät im Namen"),
    (r"android|galaxy|pixel|oneplus|xiaomi|redmi|huawei|\bhandy\b|smartphone|\btablet\b", MOBILE, 45, "Mobilgerät im Namen"),
    (r"\bwatch\b|airpods|fitbit|garmin", MOBILE, 30, "Wearable"),
    # Konsolen
    (r"playstation|\bps[45]\b|\bxbox\b|nintendo|switch-?[0-9]|steamdeck|\bwii\b", CONSOLE, 60, "Spielkonsole"),
    # IoT
    (r"shelly|sonoff|tasmota|esphome|esp-?[0-9a-f]{6}|tuya|smartlife|\bhue\b|\bbridge\b|tradfri|homematic|\bhomey\b|homeassistant|home-?assistant|zigbee|\bnetatmo\b|tado|nuki|wallbox|\bwbox\b", IOT, 50, "IoT-/Smart-Home-Kennung"),
    (r"thermostat|steckdose|\bplug\b|\bsensor\b|\blampe\b|\blight\b|rolladen|\bshutter\b|waschmasch|dishwasher|geschirrsp", IOT, 35, "Smart-Home-Funktion"),
    # Industrie / USV
    (r"simatic|s7-?[0-9]{3,4}|\bplc\b|\bsps\b|beckhoff|\bwago\b|profinet|modbus|allen-?bradley|\bcompactlogix\b", INDUSTRIAL, 55, "Industriesteuerung"),
    (r"\bups\b|\busv\b|smart-?ups|\bapc\b|eaton|riello|online ?yunto", UPS, 50, "USV-Kennung"),
    # Virtualisierung
    (r"\bvmware\b|virtualbox|\bqemu\b|\bkvm\b|hyper-?v|\bxen\b|parallels", VM, 40, "Virtualisierung"),
]

# mDNS-Dienst -> (Kategorie, Punkte)
MDNS_SERVICE_RULES: List[Tuple[str, str, int, str]] = [
    (r"_ipp\._tcp|_ipps\._tcp|_printer\._tcp|_pdl-datastream\._tcp|_scanner\._tcp|_uscan", PRINTER, 50, "Bonjour-Druckdienst"),
    (r"_airplay\._tcp|_raop\._tcp|_spotify-connect|_googlecast|_sonos|_sleep-proxy", MEDIA, 40, "Bonjour-Mediendienst"),
    (r"_apple-mobdev|_touch-able|_apple-pairable", MOBILE, 45, "iOS-Gerätedienst"),
    (r"_smb\._tcp|_rfb\._tcp|_net-assistant|_odisk", MAC_PC, 25, "Mac-Freigabedienst"),
    (r"_afpovertcp|_adisk|_smb\._tcp|_nfs\._tcp", NAS, 25, "Bonjour-Dateifreigabe"),
    (r"_workstation\._tcp|_ssh\._tcp|_sftp-ssh", NIX_PC, 20, "Bonjour-Workstation"),
    (r"_hap\._tcp|_homekit|_matter|_esphomelib|_shelly", IOT, 45, "HomeKit/IoT-Dienst"),
    (r"_sleep-proxy|_device-info", None, 0, ""),
]

CONFIDENCE_HIGH = "hoch"
CONFIDENCE_MEDIUM = "mittel"
CONFIDENCE_LOW = "niedrig"


class Classification:
    def __init__(self, category: str, confidence: str, reasons: List[str],
                 scores: Dict[str, int]):
        self.category = category
        self.confidence = confidence
        self.reasons = reasons
        self.scores = scores

    def __repr__(self) -> str:
        return "<Classification %s (%s)>" % (self.category, self.confidence)


def _add(scores: Dict[str, int], reasons: Dict[str, List[str]],
         category: Optional[str], points: int, reason: str) -> None:
    if not category or points <= 0:
        return
    scores[category] = scores.get(category, 0) + points
    if reason:
        reasons.setdefault(category, []).append(reason)


def classify(open_ports: Sequence[int],
             mac: Optional[str] = None,
             vendor: Optional[str] = None,
             vendor_hint: Optional[str] = None,
             names: Optional[Iterable[str]] = None,
             evidence: Optional[Dict[str, str]] = None,
             is_gateway: bool = False,
             is_self: bool = False) -> Classification:
    """Bestimmt die wahrscheinlichste Gerätekategorie."""
    scores: Dict[str, int] = {}
    reasons: Dict[str, List[str]] = {}
    ports: Set[int] = set(open_ports or ())
    evidence = evidence or {}

    # 1) Offene Ports
    for port in ports:
        for category, points, reason in PORT_RULES.get(port, ()):
            _add(scores, reasons, category, points, reason)

    # 2) MAC-Hersteller
    if vendor_hint:
        category = HINT_TO_CATEGORY.get(vendor_hint)
        _add(scores, reasons, category, 35, "MAC-Hersteller: %s" % (vendor or vendor_hint))
    if vendor:
        low = vendor.lower()
        if "apple" in low:
            # Apple: Mac, iPhone oder Apple TV - Ports entscheiden
            _add(scores, reasons, MAC_PC, 10, "Apple-Hardware")
            _add(scores, reasons, MOBILE, 10, "Apple-Hardware")
        if "raspberry" in low:
            _add(scores, reasons, NIX_PC, 25, "Raspberry Pi")

    # 3) Namen und Textkennungen
    text_parts: List[str] = [n for n in (names or ()) if n]
    for key, value in evidence.items():
        if key.startswith(("server:", "title:", "auth:", "banner:", "tls_cn:",
                           "snmp_", "ssdp_", "upnp_", "netbios_", "mdns_")):
            text_parts.append(str(value))
    haystack = " ".join(text_parts).lower()

    for pattern, category, points, reason in TEXT_RULES:
        if re.search(pattern, haystack):
            _add(scores, reasons, category, points, reason)

    # 4) mDNS-Dienste
    services = evidence.get("mdns_services", "")
    if re.search(r"_companion-link|_rdlink", services, re.I):
        # Haben Mac, iPhone und Apple TV gleichermassen - nur ein Apple-Indiz
        for category in (MAC_PC, MOBILE, MEDIA):
            _add(scores, reasons, category, 8, "Apple-Gerätedienst (Bonjour)")
    if services:
        for pattern, category, points, reason in MDNS_SERVICE_RULES:
            if category and re.search(pattern, services, re.I):
                _add(scores, reasons, category, points, reason)

    # 5) Protokollspezifische Zusatzindizien
    if evidence.get("netbios_name"):
        _add(scores, reasons, WIN_PC, 25, "NetBIOS-Name vorhanden")
    if evidence.get("snmp_descr") or evidence.get("snmp_name"):
        descr = (evidence.get("snmp_descr", "") + " " + evidence.get("snmp_name", "")).lower()
        if not any(re.search(p, descr) for p, c, _s, _r in TEXT_RULES if c in (PRINTER, ROUTER, SWITCH)):
            _add(scores, reasons, SWITCH, 15, "SNMP-fähiges Netzwerkgerät")
    server_headers = " ".join(v for k, v in evidence.items() if k.startswith("server:")).lower()
    if "iis" in server_headers or "microsoft-httpapi" in server_headers:
        _add(scores, reasons, WIN_PC, 30, "Microsoft-Webserver")
        _add(scores, reasons, SERVER, 20, "Microsoft-Webserver")
    if "debut" in server_headers or "hp-chai" in server_headers or "virata" in server_headers:
        _add(scores, reasons, PRINTER, 40, "Drucker-Webserver")

    # 6) Rolle im Netz
    if is_gateway:
        _add(scores, reasons, ROUTER, 70, "Standardgateway dieses Netzes")
    if is_self:
        _add(scores, reasons, MAC_PC if _this_is_mac() else WIN_PC, 30, "dieser Rechner")

    # 7) Gegenanzeigen
    if PRINTER in scores and ports & {3389, 5985, 62078}:
        scores[PRINTER] = max(0, scores[PRINTER] - 30)
    if WIN_PC in scores and 9100 in ports and not (ports & {135, 3389, 5985}):
        scores[WIN_PC] = max(0, scores[WIN_PC] - 20)
    if MOBILE in scores and ports & {445, 135, 3389, 9100, 631}:
        scores[MOBILE] = max(0, scores[MOBILE] - 40)
    if ROUTER in scores and not is_gateway and (ports & {9100, 515, 554, 5060}):
        scores[ROUTER] = max(0, scores[ROUTER] - 25)
    # Ein reiner "Computer (Linux/Unix)" wird zum Server, wenn Serverdienste laufen
    if scores.get(SERVER, 0) >= 30 and scores.get(NIX_PC, 0):
        _add(scores, reasons, SERVER, scores[NIX_PC] // 2, "zusätzlich Unix-Dienste")

    if not scores:
        if ports:
            return Classification(UNKNOWN, CONFIDENCE_LOW,
                                  ["nur unspezifische Ports offen"], scores)
        return Classification(UNKNOWN, CONFIDENCE_LOW, ["keine Indizien"], scores)

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best, best_score = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    margin = best_score - runner_up

    if best_score >= 55 and margin >= 20:
        confidence = CONFIDENCE_HIGH
    elif best_score >= 30:
        confidence = CONFIDENCE_MEDIUM
    else:
        confidence = CONFIDENCE_LOW
    if best_score <= 12:
        best = UNKNOWN

    return Classification(best, confidence, reasons.get(best, [])[:5], dict(ranked))


def _this_is_mac() -> bool:
    import platform
    return platform.system() == "Darwin"


# Namen, die zwar zurueckgeliefert werden, aber nichts aussagen
_USELESS_NAMES = re.compile(
    r"^(none|null|unknown|unbekannt|localhost|default|device|hostname|"
    r"new[- ]?device|n/?a|-|\*|\?+)(\.local)?\.?$", re.I)


def clean_name(value: Optional[str], ip: Optional[str] = None) -> Optional[str]:
    """Bereinigt einen Gerätenamen (Leerzeichen, IP-Präfix, Platzhalter)."""
    if not value:
        return None
    value = re.sub(r"\s+", " ", str(value)).strip().rstrip(".")
    if ip and value.startswith(ip):
        # UPnP liefert oft "192.168.1.172 - Sonos Play:1"
        value = re.sub(r"^%s\s*[-:]\s*" % re.escape(ip), "", value).strip()
    if not value or _USELESS_NAMES.match(value):
        return None
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", value):      # nur eine IP
        return None
    return value


def pick_display_name(names: Dict[str, str], ip: Optional[str] = None) -> Optional[str]:
    """Wählt aus allen gefundenen Namensquellen den aussagekräftigsten."""
    priority = ("upnp_name", "mdns_name", "netbios_name", "snmp_name",
                "dns_name", "ssdp_name", "tls_cn", "title")
    for key in priority:
        value = clean_name(names.get(key), ip)
        if value:
            return value
    return None
