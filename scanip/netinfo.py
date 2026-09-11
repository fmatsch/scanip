"""Plattformabhängige Basisinformationen: Interfaces, ARP-Tabelle, Gateway, Ping."""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import subprocess
from typing import Dict, List, Optional

import time

SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"

_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW: kein Konsolenfenster in der GUI


def run(cmd: List[str], timeout: float = 8.0) -> str:
    """Fuehrt ein Kommando aus und liefert stdout (leer bei Fehler)."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return res.stdout.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Zwischenspeicher
#
# Die Abfrage der Schnittstellen startet unter Windows PowerShell - das dauert
# auf langsamen Systemen mehrere Sekunden. Da sich Schnittstellen und Gateway
# während eines Programmlaufs praktisch nie ändern, wird das Ergebnis kurz
# zwischengespeichert. Die ARP-Tabelle bleibt bewusst ungepuffert, sie ändert
# sich während eines Scans laufend.
# --------------------------------------------------------------------------- #

CACHE_TTL = 30.0
_cache: Dict[str, tuple] = {}


def _cached(key: str, producer, ttl: float = CACHE_TTL):
    now = time.monotonic()
    entry = _cache.get(key)
    if entry is not None and now - entry[0] < ttl:
        return entry[1]
    value = producer()
    _cache[key] = (now, value)
    return value


def clear_cache() -> None:
    """Erzwingt die Neuermittlung von Schnittstellen und Gateway."""
    _cache.clear()


def normalize_mac(raw: str) -> Optional[str]:
    """'0:1e:c9:a:b:c' oder '00-1E-C9-...' -> '00:1E:C9:0A:0B:0C'."""
    if not raw:
        return None
    parts = re.split(r"[:-]", raw.strip())
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    mac = ":".join("%02X" % o for o in octets)
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    return mac


# --------------------------------------------------------------------------- #
# Interfaces
# --------------------------------------------------------------------------- #

class Interface:
    def __init__(self, name: str, ip: str, prefixlen: int, mac: Optional[str] = None):
        self.name = name
        self.ip = ip
        self.prefixlen = prefixlen
        self.mac = mac

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network("%s/%d" % (self.ip, self.prefixlen), strict=False)

    def __repr__(self) -> str:
        return "<Interface %s %s/%d>" % (self.name, self.ip, self.prefixlen)


def primary_ip() -> Optional[str]:
    """Lokale IP, die für ausgehenden Verkehr benutzt wird (ohne echten Traffic)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _interfaces_windows() -> List[Interface]:
    out = run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object IPAddress,PrefixLength,InterfaceAlias | ConvertTo-Json -Compress",
    ], timeout=20)
    result: List[Interface] = []
    if out.strip():
        try:
            data = json.loads(out)
        except ValueError:
            data = []
        if isinstance(data, dict):
            data = [data]
        for entry in data:
            ip = str(entry.get("IPAddress", ""))
            try:
                plen = int(entry.get("PrefixLength", 24))
            except (TypeError, ValueError):
                continue
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                result.append(Interface(str(entry.get("InterfaceAlias", "?")), ip, plen))
    if result:
        return result
    # Fallback: ipconfig parsen (sprachunabhängig über IPv4-Muster)
    text = run(["ipconfig"], timeout=20)
    ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)[^\n]*\n[^\n]*?(\d+\.\d+\.\d+\.\d+)", text)
    for ip, mask in ips:
        if ip.startswith(("127.", "169.254.")) or not mask.startswith("255."):
            continue
        try:
            plen = ipaddress.ip_network("0.0.0.0/%s" % mask).prefixlen
        except ValueError:
            continue
        result.append(Interface("?", ip, plen))
    return result


def _interfaces_unix() -> List[Interface]:
    result: List[Interface] = []
    text = run(["ifconfig"], timeout=10) or run(["/sbin/ifconfig"], timeout=10)
    if text:
        current = "?"
        current_mac = None
        for line in text.splitlines():
            if line and not line[0].isspace():
                current = line.split(":", 1)[0].strip()
                current_mac = None
            stripped = line.strip()
            if stripped.startswith(("ether ", "lladdr ")):
                current_mac = normalize_mac(stripped.split()[1])
            m = re.match(r"inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", stripped)
            if not m:
                m2 = re.match(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", stripped)
                if m2:
                    ip, plen = m2.group(1), int(m2.group(2))
                    if not ip.startswith(("127.", "169.254.")):
                        result.append(Interface(current, ip, plen, current_mac))
                continue
            ip, mask = m.group(1), m.group(2)
            if ip.startswith(("127.", "169.254.")):
                continue
            try:
                if mask.startswith("0x"):
                    plen = bin(int(mask, 16)).count("1")
                else:
                    plen = ipaddress.ip_network("0.0.0.0/%s" % mask).prefixlen
            except ValueError:
                plen = 24
            result.append(Interface(current, ip, plen, current_mac))
    if not result:
        text = run(["ip", "-o", "-4", "addr", "show"], timeout=10)
        for m in re.finditer(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", text):
            if not m.group(2).startswith(("127.", "169.254.")):
                result.append(Interface(m.group(1), m.group(2), int(m.group(3))))
    return result


def _detect_interfaces() -> List[Interface]:
    try:
        found = _interfaces_windows() if IS_WINDOWS else _interfaces_unix()
    except Exception:
        found = []
    if not found:
        ip = primary_ip()
        if ip:
            found = [Interface("?", ip, 24)]
    return found


def interfaces() -> List[Interface]:
    """Alle aktiven IPv4-Schnittstellen mit Netzmaske (kurz zwischengespeichert)."""
    return _cached("interfaces", _detect_interfaces)


def default_networks() -> List[ipaddress.IPv4Network]:
    """Sinnvolle Scan-Netze: bevorzugt das Netz des primaeren Interfaces."""
    ifaces = interfaces()
    prim = primary_ip()
    nets: List[ipaddress.IPv4Network] = []
    for iface in ifaces:
        if iface.prefixlen < 16:          # zu groß zum Scannen
            continue
        net = iface.network
        if prim and ipaddress.ip_address(prim) in net:
            nets.insert(0, net)
        else:
            nets.append(net)
    seen = set()
    unique = []
    for net in nets:
        if str(net) not in seen:
            seen.add(str(net))
            unique.append(net)
    return unique


# --------------------------------------------------------------------------- #
# Gateway / ARP
# --------------------------------------------------------------------------- #

def default_gateways() -> List[str]:
    """IP-Adressen der Standardgateways (kurz zwischengespeichert)."""
    return _cached("gateways", _detect_gateways)


def _detect_gateways() -> List[str]:
    gws: List[str] = []
    if IS_WINDOWS:
        out = run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
            "Select-Object -ExpandProperty NextHop",
        ], timeout=20)
        gws = re.findall(r"\d+\.\d+\.\d+\.\d+", out)
        if not gws:
            gws = re.findall(r"\d+\.\d+\.\d+\.\d+", run(["route", "print", "0.0.0.0"], timeout=20))
    elif IS_MAC:
        out = run(["route", "-n", "get", "default"], timeout=10)
        gws = re.findall(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
    else:
        out = run(["ip", "route", "show", "default"], timeout=10)
        gws = re.findall(r"via\s+(\d+\.\d+\.\d+\.\d+)", out)
        if not gws:
            out = run(["route", "-n"], timeout=10)
            for line in out.splitlines():
                f = line.split()
                if len(f) > 2 and f[0] == "0.0.0.0":
                    gws.append(f[1])
    return [g for g in dict.fromkeys(gws) if not g.startswith("0.")]


def arp_table() -> Dict[str, str]:
    """Aktuelle ARP-Tabelle des Systems als {IP: MAC}."""
    table: Dict[str, str] = {}
    out = run(["arp", "-a"] if IS_WINDOWS else ["arp", "-an"], timeout=15)
    if not out:
        out = run(["ip", "neigh", "show"], timeout=10)
    for line in out.splitlines():
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
        macs = _MAC_RE.findall(line)
        if not ips or not macs:
            continue
        mac = normalize_mac(macs[0])
        if mac:
            table[ips[0]] = mac
    return table


def ping(ip: str, timeout_ms: int = 800) -> bool:
    """Ein einzelner ICMP-Echo-Versuch ohne Root-Rechte (nutzt das System-Ping)."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-n", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-n", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_ms / 1000.0 + 2.0,
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if res.returncode != 0:
        return False
    # Windows meldet "Zielhost nicht erreichbar" ebenfalls mit Exitcode 0
    return b"TTL=" in res.stdout or b"ttl=" in res.stdout or not IS_WINDOWS


def prime_arp(ip: str) -> None:
    """Erzwingt einen ARP-Request, indem ein UDP-Paket an den Host geschickt wird."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.2)
        sock.sendto(b"\x00", (ip, 9))       # Discard-Port
    except OSError:
        pass
    finally:
        sock.close()
