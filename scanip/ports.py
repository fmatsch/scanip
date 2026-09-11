"""TCP-Portscan (connect-Scan, ohne Root-Rechte) inkl. leichtem Banner-Grabbing."""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

# Portname -> nur zur Anzeige; die Klassifizierung nutzt die Nummern.
SERVICE_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    80: "http", 81: "http-alt", 88: "kerberos", 106: "pop3pw", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 427: "slp", 443: "https",
    445: "smb", 465: "smtps", 500: "isakmp", 502: "modbus", 515: "printer-lpd",
    548: "afp", 554: "rtsp", 587: "submission", 623: "ipmi", 631: "ipp",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1010: "surf",
    1080: "socks", 1234: "vlc", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 1900: "upnp", 2000: "sccp-cisco", 2049: "nfs", 2082: "cpanel",
    2100: "amiganetfs", 2222: "ssh-alt", 2323: "telnet-alt", 2375: "docker",
    2869: "upnp-event", 3000: "http-dev", 3128: "squid", 3260: "iscsi",
    3283: "apple-remote-desktop", 3306: "mysql", 3389: "rdp", 3689: "daap-itunes",
    4370: "zkteco", 4433: "https-alt", 4567: "tram", 5000: "upnp/synology",
    5001: "synology-https", 5009: "airport-admin", 5060: "sip", 5061: "sip-tls",
    5222: "xmpp", 5353: "mdns", 5357: "wsdapi", 5432: "postgres", 5555: "adb",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6000: "x11", 6379: "redis",
    7000: "afs/airplay", 7100: "font-service", 7443: "https-alt", 7547: "tr-069",
    8000: "http-alt", 8006: "proxmox", 8008: "http-alt", 8009: "chromecast",
    8080: "http-proxy", 8081: "http-alt", 8088: "http-alt", 8123: "home-assistant",
    8172: "iis-mgmt", 8181: "http-alt", 8200: "gopro/dlna", 8291: "mikrotik-winbox",
    8443: "https-alt", 8554: "rtsp-alt", 8728: "mikrotik-api", 8883: "mqtt-tls",
    9000: "http-alt", 9080: "http-alt", 9090: "http-alt", 9100: "printer-raw",
    9101: "printer-raw2", 9102: "printer-raw3", 9200: "elasticsearch",
    9295: "printer-scan", 9443: "https-alt", 10000: "webmin", 11211: "memcached",
    27017: "mongodb", 32400: "plex", 37777: "dahua-dvr", 49152: "upnp-dyn",
    50000: "sap", 51413: "transmission", 62078: "apple-lockdown",
}

# ~90 Ports, die auf typischer LAN-Hardware wirklich etwas aussagen.
TOP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 427,
    443, 445, 465, 500, 515, 548, 554, 587, 623, 631, 636, 873, 993, 995,
    1080, 1433, 1521, 1723, 1883, 1900, 2000, 2049, 2222, 2323, 2375, 2869,
    3000, 3128, 3260, 3283, 3306, 3389, 3689, 4433, 5000, 5001, 5009, 5060,
    5061, 5222, 5357, 5432, 5555, 5900, 5985, 5986, 6000, 6379, 7000, 7100,
    7547, 8000, 8006, 8008, 8009, 8080, 8081, 8088, 8123, 8172, 8181, 8200,
    8291, 8443, 8554, 8728, 8883, 9000, 9090, 9100, 9101, 9102, 9200, 9295,
    9443, 10000, 32400, 37777, 49152, 62078,
]

# Kleine, schnelle Auswahl für die Host-Erkennung (Discovery-Phase).
DISCOVERY_PORTS: List[int] = [80, 443, 22, 445, 135, 139, 631, 9100, 8080, 53, 5000, 62078]

HTTP_PORTS = {80, 81, 631, 3000, 5000, 8000, 8006, 8008, 8080, 8081, 8088,
              8123, 8181, 9000, 9090, 10000, 32400}
HTTPS_PORTS = {443, 4433, 5001, 7443, 8443, 9443}


def parse_port_spec(spec: str) -> List[int]:
    """'22,80,1000-1010' oder 'top' oder 'all' -> Portliste."""
    spec = spec.strip().lower()
    if spec in ("top", "default", ""):
        return list(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: List[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(chunk))
    return sorted({p for p in ports if 0 < p < 65536})


def check_port(ip: str, port: int, timeout: float = 0.6) -> bool:
    """TCP-Connect-Test auf einen einzelnen Port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def scan_ports(ip: str, ports: List[int], timeout: float = 0.6,
               workers: int = 64) -> List[int]:
    """Scannt eine Portliste parallel und liefert die offenen Ports sortiert."""
    if not ports:
        return []
    workers = max(1, min(workers, len(ports)))
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, check_port(ip, p, timeout)), ports)
        for port, is_open in results:
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


def service_name(port: int) -> str:
    return SERVICE_NAMES.get(port, "")


def format_ports(ports: List[int], with_names: bool = False, limit: int = 0) -> str:
    if not ports:
        return "-"
    shown = ports[:limit] if limit else ports
    if with_names:
        items = ["%d/%s" % (p, service_name(p)) if service_name(p) else str(p) for p in shown]
    else:
        items = [str(p) for p in shown]
    text = ", ".join(items)
    if limit and len(ports) > limit:
        text += ", +%d" % (len(ports) - limit)
    return text


# --------------------------------------------------------------------------- #
# Banner / HTTP-Kennungen (helfen bei Gerätename + Kategorie)
# --------------------------------------------------------------------------- #

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_SERVER_RE = re.compile(rb"^server:\s*(.+)$", re.I | re.M)
_WWWAUTH_RE = re.compile(rb"^www-authenticate:\s*(.+)$", re.I | re.M)


def _decode(raw: bytes, limit: int = 120) -> str:
    text = raw.decode("utf-8", "replace").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def http_probe(ip: str, port: int, timeout: float = 1.5) -> Dict[str, str]:
    """Holt Server-Header und <title> einer Web-Oberfläche."""
    use_tls = port in HTTPS_PORTS
    info: Dict[str, str] = {}
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    sock = raw_sock
    try:
        raw_sock.connect((ip, port))
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
            except (ssl.SSLError, OSError):
                return info
            cert = sock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", ()) if x)
                common = subject.get("commonName")
                if common:
                    info["tls_cn"] = str(common)[:80]
        request = (
            "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: scanip/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n" % ip
        )
        sock.sendall(request.encode("ascii"))
        chunks = []
        total = 0
        while total < 16384:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        m = _SERVER_RE.search(data)
        if m:
            info["server"] = _decode(m.group(1), 80)
        m = _WWWAUTH_RE.search(data)
        if m:
            info["auth"] = _decode(m.group(1), 80)
        m = _TITLE_RE.search(data)
        if m:
            title = re.sub(rb"<[^>]+>", b" ", m.group(1))
            value = _decode(title, 80)
            if value:
                info["title"] = value
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
        if sock is not raw_sock:
            try:
                raw_sock.close()
            except OSError:
                pass
    return info


def banner_probe(ip: str, port: int, timeout: float = 1.2) -> Optional[str]:
    """Liest ein Klartext-Banner (ssh, ftp, smtp, telnet ...)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        data = sock.recv(256)
        if not data:
            return None
        return _decode(data, 100) or None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_services(ip: str, open_ports: List[int], timeout: float = 1.5,
                   max_probes: int = 4) -> Dict[str, str]:
    """Sammelt Kennungen der interessantesten offenen Dienste."""
    evidence: Dict[str, str] = {}
    web_candidates = [p for p in open_ports if p in HTTP_PORTS or p in HTTPS_PORTS]
    for port in web_candidates[:max_probes]:
        info = http_probe(ip, port, timeout)
        for key, value in info.items():
            evidence.setdefault("%s:%d" % (key, port), value)
        if "server:%d" % port in evidence or "title:%d" % port in evidence:
            break
    for port in (22, 21, 25, 23):
        if port in open_ports:
            banner = banner_probe(ip, port, timeout)
            if banner:
                evidence["banner:%d" % port] = banner
            break
    return evidence
