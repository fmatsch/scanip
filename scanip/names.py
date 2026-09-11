"""Namensermittlung: Reverse-DNS, mDNS/Bonjour, NetBIOS, SNMP und SSDP/UPnP.

Alles in reinem Python über UDP-Sockets - keine Fremdbibliotheken, keine Root-Rechte.
"""

from __future__ import annotations

import os
import re
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Reverse DNS
# --------------------------------------------------------------------------- #

def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Klassisches PTR-Lookup über den konfigurierten Resolver."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name or None
    except (OSError, socket.herror, socket.gaierror):
        return None
    finally:
        socket.setdefaulttimeout(old)


# --------------------------------------------------------------------------- #
# Minimaler DNS-Encoder/Decoder (für mDNS)
# --------------------------------------------------------------------------- #

def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        data = label.encode("utf-8")[:63]
        out.append(len(data))
        out += data
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    end = offset
    while depth < 10:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:                     # Kompressionszeiger
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = pointer
            depth += 1
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _parse_dns_answers(data: bytes) -> List[Tuple[str, int, bytes, int]]:
    """Liefert (name, rrtype, rdata, rdata_offset) aller Antwort-Records."""
    if len(data) < 12:
        return []
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    offset = 12
    for _ in range(qd):
        _, offset = _decode_name(data, offset)
        offset += 4
    records = []
    for _ in range(an + ns + ar):
        if offset >= len(data):
            break
        name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rrtype, _rrclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        records.append((name, rrtype, rdata, offset))
        offset += rdlength
    return records


# --------------------------------------------------------------------------- #
# mDNS / Bonjour
# --------------------------------------------------------------------------- #

def _multicast_socket(timeout: float, bind_ip: Optional[str] = None) -> socket.socket:
    """UDP-Socket, das explizit über das lokale Interface sendet.

    Ohne gesetztes Ausgangs-Interface scheitert Multicast auf macOS mit
    "No route to host", sobald mehrere Interfaces existieren.
    """
    if bind_ip is None:
        bind_ip = local_source_ip()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    if bind_ip:
        try:
            sock.bind((bind_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(bind_ip))
        except OSError:
            pass
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    except OSError:
        pass
    sock.settimeout(timeout)
    return sock


def local_source_ip() -> Optional[str]:
    """Lokale IP des Interfaces mit der Standardroute."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


def mdns_reverse(ip: str, timeout: float = 1.2) -> Optional[str]:
    """Fragt den Host per Multicast-DNS nach seinem .local-Namen."""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    query += _encode_qname(qname) + struct.pack(">HH", 12, 0x8001)  # PTR, Unicast-Antwort

    sock = _multicast_socket(timeout)
    try:
        def send() -> None:
            for target in ((MDNS_ADDR, MDNS_PORT), (ip, MDNS_PORT)):
                try:                             # Multicast + Unicast an den Host
                    sock.sendto(query, target)
                except OSError:
                    continue

        send()
        deadline = time.time() + timeout
        resent = False
        while time.time() < deadline:
            remaining = deadline - time.time()
            if not resent and remaining < timeout * 0.6:
                send()                           # eine Wiederholung: UDP geht verloren
                resent = True
            sock.settimeout(max(0.05, min(0.4, remaining)))
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != ip:
                continue
            for _name, rrtype, rdata, rdoff in _parse_dns_answers(data):
                if rrtype == 12:                 # PTR
                    target, _ = _decode_name(data, rdoff)
                    if target:
                        return target.rstrip(".")
    finally:
        sock.close()
    return None


def _parse_txt(rdata: bytes) -> Dict[str, str]:
    """TXT-Rdata besteht aus längenpräfigierten Zeichenketten (key=value)."""
    result: Dict[str, str] = {}
    offset = 0
    while offset < len(rdata):
        length = rdata[offset]
        offset += 1
        chunk = rdata[offset:offset + length].decode("utf-8", "replace")
        offset += length
        if "=" in chunk:
            key, _, value = chunk.partition("=")
            result[key.strip().lower()] = value.strip()
    return result


#: Dienste, die Apple-Geräte beantworten. Die Antwort enthält als Beifang den
#: '_device-info'-TXT-Record mit der Modellkennung.
DEVICE_INFO_SERVICES = ["_airplay._tcp.local", "_raop._tcp.local",
                        "_companion-link._tcp.local", "_device-info._tcp.local"]


def mdns_device_info(ip: str, timeout: float = 1.5) -> Dict[str, str]:
    """Ermittelt Modellkennung, Betriebssystem-Hinweis und Anzeigenamen per mDNS.

    Der '_device-info'-TXT-Record enthält 'model' (z.B. 'Mac17,5' bei einem Mac,
    'J42dAP' bei einem Apple TV) und bei Macs zusätzlich 'osxvers'. Letzteres
    veröffentlicht ausschließlich macOS und trennt damit einen Mac mit aktivem
    AirPlay-Empfang zuverlässig von einem Apple TV - beide bieten sonst dieselben
    Dienste an.

    Der PTR-Zielname liefert nebenbei den vom Benutzer vergebenen Gerätenamen
    ("MacBook von Florian"), der aussagekräftiger ist als der Hostname.
    """
    result: Dict[str, str] = {}
    services: List[str] = []
    sock = _multicast_socket(timeout)
    try:
        for service in DEVICE_INFO_SERVICES:
            query = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
            query += _encode_qname(service) + struct.pack(">HH", 12, 0x8001)
            for target in ((MDNS_ADDR, MDNS_PORT), (ip, MDNS_PORT)):
                try:
                    sock.sendto(query, target)
                except OSError:
                    continue
            time.sleep(0.02)      # Anfragen leicht entzerren

        deadline = time.time() + timeout
        while time.time() < deadline:
            sock.settimeout(max(0.05, min(0.4, deadline - time.time())))
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != ip:
                continue
            for name, rrtype, rdata, rdoff in _parse_dns_answers(data):
                if rrtype == 16 and "._device-info._tcp." in name and rdata:
                    for key, value in _parse_txt(rdata).items():
                        if key in ("model", "osxvers") and value:
                            result.setdefault("mdns_" + key, value[:60])
                elif rrtype == 12:
                    target, _ = _decode_name(data, rdoff)
                    if "._tcp.local" in target or "._udp.local" in target:
                        instance, _, service_type = target.rstrip(".").partition("._")
                        if service_type:
                            services.append("_" + service_type)
                        if instance and "mdns_instance" not in result:
                            result["mdns_instance"] = instance[:60]
            if "mdns_model" in result and "mdns_instance" in result:
                break                      # alles Wesentliche beisammen
    finally:
        sock.close()

    if services:
        result["mdns_services"] = ",".join(sorted(set(services))[:12])
    return result


def mdns_sweep(timeout: float = 2.5) -> Dict[str, Dict[str, str]]:
    """Ein Multicast-Rundruf; sammelt A-Records aller antwortenden Bonjour-Geräte."""
    query = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    query += _encode_qname("_services._dns-sd._udp.local") + struct.pack(">HH", 12, 0x8001)
    found: Dict[str, Dict[str, str]] = {}
    sock = _multicast_socket(timeout)
    try:
        sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
        deadline = time.time() + timeout
        while time.time() < deadline:
            sock.settimeout(max(0.05, deadline - time.time()))
            try:
                data, addr = sock.recvfrom(8192)
            except (socket.timeout, OSError):
                break
            entry = found.setdefault(addr[0], {})
            services: List[str] = []
            for name, rrtype, rdata, rdoff in _parse_dns_answers(data):
                if rrtype == 1 and len(rdata) == 4:           # A-Record
                    host_ip = socket.inet_ntoa(rdata)
                    found.setdefault(host_ip, {})["mdns_name"] = name.rstrip(".")
                elif rrtype == 12:
                    target, _ = _decode_name(data, rdoff)
                    if target.endswith("._tcp.local") or target.endswith("._udp.local"):
                        services.append(target.rstrip("."))
            if services:
                old = entry.get("mdns_services", "")
                merged = sorted(set(filter(None, old.split(",") + services)))
                entry["mdns_services"] = ",".join(merged[:12])
    except OSError:
        pass
    finally:
        sock.close()
    return found


# --------------------------------------------------------------------------- #
# NetBIOS (Windows-Namen + MAC-Adresse, auch über Subnetzgrenzen)
# --------------------------------------------------------------------------- #

def _encode_netbios_name(name: str = "*") -> bytes:
    padded = name.ljust(16, "\x00")[:16].encode("ascii", "replace")
    encoded = bytearray()
    for byte in padded:
        encoded.append(ord("A") + (byte >> 4))
        encoded.append(ord("A") + (byte & 0x0F))
    return bytes([len(encoded)]) + bytes(encoded) + b"\x00"


def netbios_query(ip: str, timeout: float = 1.0) -> Dict[str, str]:
    """NBSTAT-Abfrage: liefert Rechnername, Arbeitsgruppe und MAC-Adresse."""
    packet = struct.pack(">HHHHHH", 0x4321, 0x0000, 1, 0, 0, 0)
    packet += _encode_netbios_name("*") + struct.pack(">HH", 0x0021, 0x0001)
    result: Dict[str, str] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return result
    finally:
        sock.close()

    offset = 12
    if len(data) < offset + 1:
        return result
    offset += data[offset] + 2 if data[offset] else 1     # Fragename überspringen
    offset += 8                                           # Typ, Klasse, TTL
    if len(data) < offset + 3:
        return result
    offset += 2                                           # RDLENGTH
    count = data[offset]
    offset += 1
    workstation, group = None, None
    for _ in range(count):
        if len(data) < offset + 18:
            break
        raw = data[offset:offset + 15].decode("ascii", "replace").strip()
        suffix = data[offset + 15]
        flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
        is_group = bool(flags & 0x8000)
        if is_group and group is None:
            group = raw
        elif not is_group and suffix in (0x00, 0x20) and workstation is None:
            workstation = raw
        offset += 18
    if workstation:
        result["netbios_name"] = workstation
    if group:
        result["netbios_group"] = group
    if len(data) >= offset + 6:
        mac = ":".join("%02X" % b for b in data[offset:offset + 6])
        if mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            result["netbios_mac"] = mac
    return result


# --------------------------------------------------------------------------- #
# SNMP v2c (Drucker, Switches, Router, USV ...)
# --------------------------------------------------------------------------- #

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return _tlv(0x02, raw)


def _ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = bytearray([part & 0x7F])
        part >>= 7
        while part:
            chunk.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        body += chunk
    return _tlv(0x06, bytes(body))


def _read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def _snmp_values(data: bytes) -> List[str]:
    """Zieht die Werte aus der Varbind-Liste einer SNMP-Antwort."""
    values: List[str] = []

    def walk(blob: bytes, depth: int = 0) -> None:
        offset = 0
        while offset + 2 <= len(blob) and depth < 8:
            try:
                tag, value, offset = _read_tlv(blob, offset)
            except (IndexError, ValueError):
                return
            if tag in (0x30, 0xA2, 0xA0):                  # SEQUENCE / PDU
                walk(value, depth + 1)
            elif tag == 0x04 and depth >= 2:               # OCTET STRING
                text = value.decode("utf-8", "replace").strip()
                text = re.sub(r"\s+", " ", text)
                if text:
                    values.append(text[:200])
    walk(data)
    return values


def snmp_get(ip: str, oids: List[str], community: str = "public",
             timeout: float = 0.9) -> List[str]:
    """SNMPv2c-GET für mehrere OIDs; liefert die Klartextwerte."""
    varbinds = b"".join(_tlv(0x30, _ber_oid(oid) + _tlv(0x05, b"")) for oid in oids)
    pdu = (_ber_int(int.from_bytes(os.urandom(2), "big"))
           + _ber_int(0) + _ber_int(0) + _tlv(0x30, varbinds))
    message = _tlv(0x30, _ber_int(1)                                   # v2c
                   + _tlv(0x04, community.encode("ascii", "replace"))
                   + _tlv(0xA0, pdu))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(message, (ip, 161))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return []
    finally:
        sock.close()
    return _snmp_values(data)


def snmp_identify(ip: str, community: str = "public",
                  timeout: float = 0.9) -> Dict[str, str]:
    values = snmp_get(ip, [OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_LOCATION],
                      community, timeout)
    info: Dict[str, str] = {}
    # Reihenfolge der Antwort entspricht der Reihenfolge der OIDs
    for key, value in zip(("snmp_name", "snmp_descr", "snmp_location"), values):
        if value:
            info[key] = value
    return info


# --------------------------------------------------------------------------- #
# SSDP / UPnP (Smart-TVs, Router, Drucker, Media-Player ...)
# --------------------------------------------------------------------------- #

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900


def ssdp_sweep(timeout: float = 3.0) -> Dict[str, Dict[str, str]]:
    """Ein M-SEARCH-Rundruf; sammelt SERVER- und LOCATION-Angaben je IP."""
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: %s:%d\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: scanip/1.0\r\n\r\n" % (SSDP_ADDR, SSDP_PORT)
    )
    found: Dict[str, Dict[str, str]] = {}
    sock = _multicast_socket(timeout)
    try:
        sock.sendto(request.encode("ascii"), (SSDP_ADDR, SSDP_PORT))
        deadline = time.time() + timeout
        while time.time() < deadline:
            sock.settimeout(max(0.05, deadline - time.time()))
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            text = data.decode("utf-8", "replace")
            entry = found.setdefault(addr[0], {})
            for line in text.splitlines():
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key == "server" and value:
                    entry.setdefault("ssdp_server", value[:120])
                elif key == "location" and value:
                    entry.setdefault("ssdp_location", value[:200])
                elif key == "st" and value:
                    services = entry.get("ssdp_st", "")
                    if value not in services:
                        entry["ssdp_st"] = (services + "," + value).strip(",")[:200]
    except OSError:
        pass
    finally:
        sock.close()
    return found


_FRIENDLY_RE = re.compile(r"<friendlyName>(.*?)</friendlyName>", re.I | re.S)
_MODEL_RE = re.compile(r"<modelName>(.*?)</modelName>", re.I | re.S)
_MANU_RE = re.compile(r"<manufacturer>(.*?)</manufacturer>", re.I | re.S)


def upnp_description(location: str, timeout: float = 1.5) -> Dict[str, str]:
    """Holt friendlyName/modelName aus der UPnP-Gerätebeschreibung."""
    import urllib.request

    info: Dict[str, str] = {}
    if not location.lower().startswith("http://"):
        return info
    try:
        with urllib.request.urlopen(location, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
    except Exception:
        return info
    for key, pattern in (("upnp_name", _FRIENDLY_RE), ("upnp_model", _MODEL_RE),
                         ("upnp_vendor", _MANU_RE)):
        m = pattern.search(body)
        if m:
            value = re.sub(r"\s+", " ", m.group(1)).strip()
            if value:
                info[key] = value[:100]
    return info
