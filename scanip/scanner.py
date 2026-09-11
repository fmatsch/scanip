"""Scan-Ablauf: Hosts finden, Ports pruefen, Namen auflösen, Geräte einordnen."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set

from . import classify as classifier
from . import names as name_lookup
from . import notes as notes_store
from . import netinfo, oui, ports as portscan

ProgressCallback = Optional[Callable[[str, int, int, str], None]]


class Device:
    """Ein gefundener Host mit allen ermittelten Eigenschaften."""

    def __init__(self, ip: str):
        self.ip = ip
        self.mac: Optional[str] = None
        self.vendor: Optional[str] = None
        self.hostname: Optional[str] = None
        self.names: Dict[str, str] = {}
        self.open_ports: List[int] = []
        self.category: str = classifier.UNKNOWN
        self.confidence: str = classifier.CONFIDENCE_LOW
        self.reasons: List[str] = []
        self.evidence: Dict[str, str] = {}
        self.sources: Set[str] = set()
        self.is_gateway = False
        self.is_self = False
        self.rtt_ms: Optional[float] = None
        self.note: str = ""

    @property
    def sort_key(self):
        return tuple(int(part) for part in self.ip.split("."))

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "category": self.category,
            "confidence": self.confidence,
            "open_ports": list(self.open_ports),
            "services": {str(p): portscan.service_name(p) for p in self.open_ports},
            "reasons": list(self.reasons),
            "names": dict(self.names),
            "evidence": dict(self.evidence),
            "sources": sorted(self.sources),
            "is_gateway": self.is_gateway,
            "is_self": self.is_self,
            "rtt_ms": self.rtt_ms,
            "note": self.note,
            "note_key": notes_store.device_key(self.mac, self.ip),
        }

    def __repr__(self) -> str:
        return "<Device %s %s %s>" % (self.ip, self.mac, self.category)


class ScanOptions:
    def __init__(self,
                 ports: Optional[List[int]] = None,
                 discovery_timeout: float = 0.35,
                 port_timeout: float = 0.6,
                 host_workers: int = 128,
                 port_workers: int = 0,
                 detail_workers: int = 16,
                 use_ping: bool = True,
                 use_mdns: bool = True,
                 use_netbios: bool = True,
                 use_snmp: bool = True,
                 use_ssdp: bool = True,
                 use_banner: bool = True,
                 snmp_community: str = "public",
                 resolve_dns: bool = True):
        self.ports = ports if ports is not None else list(portscan.TOP_PORTS)
        self.discovery_timeout = discovery_timeout
        self.port_timeout = port_timeout
        self.host_workers = host_workers
        self.detail_workers = detail_workers
        # Insgesamt nie mehr als ~400 gleichzeitige Sockets: sonst gehen
        # UDP-Antworten (mDNS/SNMP/NetBIOS) unter der Last verloren.
        self.port_workers = port_workers or max(8, min(48, 384 // max(1, detail_workers)))
        self.use_ping = use_ping
        self.use_mdns = use_mdns
        self.use_netbios = use_netbios
        self.use_snmp = use_snmp
        self.use_ssdp = use_ssdp
        self.use_banner = use_banner
        self.snmp_community = snmp_community
        self.resolve_dns = resolve_dns


#: Mehr Adressen als das nimmt dieses Werkzeug nicht an - ein versehentliches
#: /8 (16,7 Mio. Adressen) wuerde sonst schon beim Aufzaehlen den Speicher fluten.
MAX_TARGETS = 65536


def _range_size(spec: str) -> int:
    """Anzahl Adressen einer Angabe - ohne sie aufzuzählen."""
    spec = spec.strip()
    if "-" in spec and "/" not in spec:
        start_text, _, end_text = spec.partition("-")
        start = ipaddress.IPv4Address(start_text.strip())
        if "." not in end_text:
            end_text = start_text.rsplit(".", 1)[0] + "." + end_text.strip()
        return max(0, int(ipaddress.IPv4Address(end_text.strip())) - int(start) + 1)
    if "/" in spec:
        network = ipaddress.ip_network(spec, strict=False)
        return (network.num_addresses if network.prefixlen >= 31
                else max(0, network.num_addresses - 2))
    ipaddress.IPv4Address(spec)
    return 1


def expand_targets(specs: Sequence[str],
                   limit: int = MAX_TARGETS) -> List[str]:
    """'192.168.1.0/24', '10.0.0.5', '10.0.0.1-10.0.0.50' -> Liste von IPs.

    Prüft die Größe vorab, damit ein zu großer Bereich sofort abgelehnt wird,
    statt erst Millionen Adressen zu erzeugen.
    """
    total = sum(_range_size(spec) for spec in specs if spec.strip())
    if limit and total > limit:
        raise ValueError(
            "Bereich zu groß: %d Adressen (Grenze %d). Bitte enger fassen, "
            "z.B. 192.168.1.0/24." % (total, limit))

    result: List[str] = []
    seen: Set[str] = set()
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        addresses: Iterable[str]
        if "-" in spec and "/" not in spec:
            start_text, _, end_text = spec.partition("-")
            start = ipaddress.IPv4Address(start_text.strip())
            if "." not in end_text:                      # Kurzform 192.168.1.10-50
                end_text = start_text.rsplit(".", 1)[0] + "." + end_text.strip()
            end = ipaddress.IPv4Address(end_text.strip())
            addresses = (str(ipaddress.IPv4Address(i))
                         for i in range(int(start), int(end) + 1))
        elif "/" in spec:
            network = ipaddress.ip_network(spec, strict=False)
            addresses = ([str(network.network_address)] if network.prefixlen >= 31
                         else (str(host) for host in network.hosts()))
        else:
            addresses = [str(ipaddress.IPv4Address(spec))]
        for address in addresses:
            if address not in seen:
                seen.add(address)
                result.append(address)
    return result


class Scanner:
    def __init__(self, options: Optional[ScanOptions] = None):
        self.options = options or ScanOptions()
        self.cancel_event = threading.Event()
        self._gateways: Set[str] = set()
        self._local_ips: Set[str] = set()

    def cancel(self) -> None:
        self.cancel_event.set()

    # ------------------------------------------------------------------ #

    def scan(self, targets: Sequence[str],
             progress: ProgressCallback = None) -> List[Device]:
        """Fuehrt den vollstaendigen Scan aus und liefert die gefundenen Geräte."""
        self.cancel_event.clear()
        opts = self.options
        oui.load_external()
        notes_store.reload()
        self._gateways = set(netinfo.default_gateways())
        self._local_ips = {iface.ip for iface in netinfo.interfaces()}

        def report(phase: str, done: int, total: int, message: str = "") -> None:
            if progress:
                progress(phase, done, total, message)

        # Phase 0: Multicast-Rundrufe laufen parallel zur Host-Erkennung
        multicast: Dict[str, Dict[str, str]] = {}
        multicast_lock = threading.Lock()

        def collect(func, timeout: float) -> None:
            try:
                found = func(timeout)
            except Exception:                                   # noqa: BLE001
                return
            with multicast_lock:
                for ip, info in found.items():
                    multicast.setdefault(ip, {}).update(info)

        helpers: List[threading.Thread] = []
        if opts.use_ssdp:
            helpers.append(threading.Thread(target=collect,
                                            args=(name_lookup.ssdp_sweep, 3.0),
                                            daemon=True))
        if opts.use_mdns:
            helpers.append(threading.Thread(target=collect,
                                            args=(name_lookup.mdns_sweep, 3.0),
                                            daemon=True))
        for thread in helpers:
            thread.start()

        # Phase 1: Welche Hosts antworten überhaupt?
        report("discovery", 0, len(targets), "Suche aktive Hosts ...")
        alive: Dict[str, Device] = {}
        done = 0
        workers = max(1, min(opts.host_workers, max(1, len(targets))))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._probe_host, ip): ip for ip in targets}
            for future in as_completed(futures):
                done += 1
                if self.cancel_event.is_set():
                    break
                ip = futures[future]
                try:
                    device = future.result()
                except Exception:                               # noqa: BLE001
                    device = None
                if device:
                    alive[ip] = device
                if done % 8 == 0 or done == len(targets):
                    report("discovery", done, len(targets),
                           "%d aktive Hosts" % len(alive))
        report("discovery", len(targets), len(targets),
               "%d aktive Hosts" % len(alive))

        for thread in helpers:
            thread.join(timeout=4.0)

        # Phase 2: ARP-Tabelle auswerten (MAC-Adressen)
        arp = netinfo.arp_table()
        target_set = set(targets)
        for ip, mac in arp.items():
            if ip not in target_set:
                continue
            device = alive.get(ip)
            if device is None:
                device = Device(ip)
                device.sources.add("arp")
                alive[ip] = device
            device.mac = device.mac or mac
            device.sources.add("arp")

        # Aus Multicast-Antworten zusätzlich gefundene Hosts übernehmen
        for ip, info in multicast.items():
            if ip not in target_set:
                continue
            device = alive.get(ip)
            if device is None:
                device = Device(ip)
                alive[ip] = device
            device.evidence.update(info)
            device.sources.add("mdns" if "mdns_name" in info or "mdns_services" in info
                               else "ssdp")

        if self.cancel_event.is_set():
            return sorted(alive.values(), key=lambda d: d.sort_key)

        # Phase 3: Details je Host
        devices = sorted(alive.values(), key=lambda d: d.sort_key)
        total = len(devices)
        report("detail", 0, total, "Analysiere %d Geräte ..." % total)
        done = 0
        detail_workers = max(1, min(opts.detail_workers, max(1, total)))
        with ThreadPoolExecutor(max_workers=detail_workers) as pool:
            futures = {pool.submit(self._detail_host, device): device
                       for device in devices}
            for future in as_completed(futures):
                done += 1
                if self.cancel_event.is_set():
                    break
                try:
                    future.result()
                except Exception:                               # noqa: BLE001
                    pass
                report("detail", done, total, futures[future].ip)

        # Fehlende MACs nachtragen (ARP-Cache ist nach dem Scan vollstaendiger)
        arp = netinfo.arp_table()
        for device in devices:
            if not device.mac and device.ip in arp:
                device.mac = arp[device.ip]
            if device.mac and not device.vendor:
                device.vendor = oui.vendor(device.mac)

        for device in devices:
            self._finalize(device)

        report("done", total, total, "%d Geräte" % len(devices))
        return sorted(devices, key=lambda d: d.sort_key)

    # ------------------------------------------------------------------ #

    def _probe_host(self, ip: str) -> Optional[Device]:
        """Schnelltest: reagiert dieser Host auf ARP, ICMP oder TCP?"""
        if self.cancel_event.is_set():
            return None
        opts = self.options
        device = Device(ip)
        start = time.time()

        netinfo.prime_arp(ip)                       # loest ARP-Auflösung aus

        hit = False
        open_early: List[int] = []
        for port in portscan.DISCOVERY_PORTS:
            if self.cancel_event.is_set():
                return None
            if portscan.check_port(ip, port, opts.discovery_timeout):
                open_early.append(port)
                hit = True
                device.sources.add("tcp")
                break                               # ein Treffer genügt
        if not hit and opts.use_ping:
            if netinfo.ping(ip, int(max(0.3, opts.discovery_timeout) * 1000)):
                hit = True
                device.sources.add("icmp")
        if hit:
            device.open_ports = open_early
            device.rtt_ms = round((time.time() - start) * 1000, 1)
            return device
        return None

    def _detail_host(self, device: Device) -> None:
        """Vollstaendiger Portscan plus Namens- und Dienstermittlung."""
        if self.cancel_event.is_set():
            return
        opts = self.options
        ip = device.ip

        found_early = set(device.open_ports)      # aus der Suchphase
        scanned = portscan.scan_ports(
            ip, opts.ports, opts.port_timeout, opts.port_workers)
        device.open_ports = sorted(found_early | set(scanned))
        if device.open_ports:
            device.sources.add("tcp")

        if opts.resolve_dns:
            hostname = name_lookup.reverse_dns(ip, 1.0)
            if hostname:
                device.names["dns_name"] = hostname
        if opts.use_mdns and "mdns_name" not in device.evidence:
            mdns_name = name_lookup.mdns_reverse(ip, 1.4)
            if mdns_name:
                device.names["mdns_name"] = mdns_name
                device.sources.add("mdns")
        elif device.evidence.get("mdns_name"):
            device.names["mdns_name"] = device.evidence["mdns_name"]

        if opts.use_mdns:
            # Apple-Modellkennung: trennt Mac, Apple TV, HomePod und iPhone,
            # die sich über Ports und Dienste sonst kaum unterscheiden lassen.
            info = name_lookup.mdns_device_info(ip, 1.5)
            if info:
                services = device.evidence.get("mdns_services", "")
                if services and info.get("mdns_services"):
                    info["mdns_services"] = ",".join(sorted(
                        set(services.split(",")) | set(info["mdns_services"].split(","))))
                device.evidence.update(info)
                device.sources.add("mdns")
                if info.get("mdns_instance"):
                    device.names["mdns_instance"] = info["mdns_instance"]

        if opts.use_netbios:
            netbios = name_lookup.netbios_query(ip, 0.9)
            if netbios:
                device.evidence.update(netbios)
                device.sources.add("netbios")
                if netbios.get("netbios_name"):
                    device.names["netbios_name"] = netbios["netbios_name"]
                if netbios.get("netbios_mac") and not device.mac:
                    device.mac = netbios["netbios_mac"]

        if opts.use_snmp:
            snmp = name_lookup.snmp_identify(ip, opts.snmp_community, 0.9)
            if snmp:
                device.evidence.update(snmp)
                device.sources.add("snmp")
                if snmp.get("snmp_name"):
                    device.names["snmp_name"] = snmp["snmp_name"]

        if opts.use_banner and device.open_ports:
            probes = portscan.probe_services(ip, device.open_ports, 1.5)
            device.evidence.update(probes)
            for key, value in probes.items():
                if key.startswith("title:"):
                    device.names.setdefault("title", value)
                elif key.startswith("tls_cn:"):
                    device.names.setdefault("tls_cn", value)

        location = device.evidence.get("ssdp_location")
        if location:
            upnp = name_lookup.upnp_description(location, 1.5)
            if upnp:
                device.evidence.update(upnp)
                if upnp.get("upnp_name"):
                    device.names["upnp_name"] = upnp["upnp_name"]

    def _finalize(self, device: Device) -> None:
        """Hersteller, Anzeigename und Kategorie festlegen."""
        device.is_gateway = device.ip in self._gateways
        device.is_self = device.ip in self._local_ips
        vendor, hint = oui.lookup(device.mac)
        device.vendor = vendor
        device.hostname = classifier.pick_display_name(device.names, device.ip)
        if device.is_self and not device.hostname:
            device.hostname = socket.gethostname()

        result = classifier.classify(
            open_ports=device.open_ports,
            mac=device.mac,
            vendor=vendor,
            vendor_hint=hint,
            names=[classifier.clean_name(v, device.ip) for v in device.names.values()],
            evidence=device.evidence,
            is_gateway=device.is_gateway,
            is_self=device.is_self,
        )
        device.category = result.category
        device.confidence = result.confidence
        device.reasons = result.reasons
        device.note = notes_store.get(device.mac, device.ip)
