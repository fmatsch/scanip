"""Testsuite für scanip - läuft offline, ohne Netzwerkzugriff und ohne GUI.

Aufruf:  python -m unittest discover -s tests -v
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanip import classify, names, netinfo, oui, report
from scanip import ports as portscan
from scanip.scanner import Device, expand_targets


def make_device(ip="192.168.1.10", mac=None, vendor=None, hostname=None,
                category="Unbekannt", open_ports=()):
    device = Device(ip)
    device.mac = mac
    device.vendor = vendor
    device.hostname = hostname
    device.category = category
    device.open_ports = list(open_ports)
    return device


class TestMac(unittest.TestCase):
    def test_normalisierung(self):
        self.assertEqual(netinfo.normalize_mac("0:1e:c9:a:b:c"), "00:1E:C9:0A:0B:0C")
        self.assertEqual(netinfo.normalize_mac("00-1E-C9-0A-0B-0C"), "00:1E:C9:0A:0B:0C")

    def test_ungültige_werte(self):
        for value in ("", "xx", "00:11:22:33:44", "00:00:00:00:00:00",
                      "FF:FF:FF:FF:FF:FF", "zz:11:22:33:44:55"):
            self.assertIsNone(netinfo.normalize_mac(value), value)

    def test_lokal_verwaltete_mac(self):
        self.assertTrue(oui.is_locally_administered("8A:D6:ED:AA:BB:05"))
        self.assertFalse(oui.is_locally_administered("78:20:51:AA:BB:01"))


class TestArpParsing(unittest.TestCase):
    MAC_OUTPUT = (
        "? (192.168.1.1) at 78:20:51:aa:bb:01 on en0 ifscope [ethernet]\n"
        "? (192.168.1.95) at 8a:d6:ed:aa:bb:05 on en0 ifscope permanent [ethernet]\n"
        "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
    )
    WIN_OUTPUT = (
        "Schnittstelle: 192.168.1.152 --- 0xb\n"
        "  Internetadresse       Physische Adresse     Typ\n"
        "  192.168.1.1           78-20-51-aa-bb-01     dynamisch\n"
        "  192.168.1.20          00-11-32-aa-bb-cc     dynamisch\n"
        "  224.0.0.251           01-00-5e-00-00-fb     statisch\n"
    )

    def _with_output(self, text):
        original = netinfo.run
        netinfo.run = lambda cmd, timeout=8.0: text
        try:
            return netinfo.arp_table()
        finally:
            netinfo.run = original

    def test_macos_format(self):
        table = self._with_output(self.MAC_OUTPUT)
        self.assertEqual(table["192.168.1.1"], "78:20:51:AA:BB:01")
        self.assertEqual(table["192.168.1.95"], "8A:D6:ED:AA:BB:05")
        self.assertNotIn("192.168.1.255", table)      # Broadcast wird verworfen

    def test_windows_format(self):
        table = self._with_output(self.WIN_OUTPUT)
        self.assertEqual(table["192.168.1.1"], "78:20:51:AA:BB:01")
        self.assertEqual(table["192.168.1.20"], "00:11:32:AA:BB:CC")


class TestZwischenspeicher(unittest.TestCase):
    """Schnittstellen werden gepuffert - unter Windows sonst ein PowerShell-Start
    pro Aufruf."""

    def setUp(self):
        netinfo.clear_cache()
        self.aufrufe = 0

    def _zaehlend(self):
        self.aufrufe += 1
        return ["ergebnis"]

    def test_zweiter_aufruf_kommt_aus_dem_speicher(self):
        for _ in range(3):
            self.assertEqual(netinfo._cached("test", self._zaehlend), ["ergebnis"])
        self.assertEqual(self.aufrufe, 1)

    def test_clear_cache_erzwingt_neuermittlung(self):
        netinfo._cached("test", self._zaehlend)
        netinfo.clear_cache()
        netinfo._cached("test", self._zaehlend)
        self.assertEqual(self.aufrufe, 2)

    def test_abgelaufener_eintrag_wird_erneuert(self):
        netinfo._cached("test", self._zaehlend, ttl=0.0)
        netinfo._cached("test", self._zaehlend, ttl=0.0)
        self.assertEqual(self.aufrufe, 2)

    def test_schnittstellen_liefern_gleiches_ergebnis(self):
        erste = [str(i) for i in netinfo.interfaces()]
        zweite = [str(i) for i in netinfo.interfaces()]
        self.assertEqual(erste, zweite)


class TestTargets(unittest.TestCase):
    def test_netz(self):
        self.assertEqual(len(expand_targets(["192.168.1.0/24"])), 254)
        self.assertEqual(expand_targets(["192.168.1.0/30"]),
                         ["192.168.1.1", "192.168.1.2"])

    def test_bereiche(self):
        self.assertEqual(expand_targets(["10.0.0.5"]), ["10.0.0.5"])
        self.assertEqual(expand_targets(["10.0.0.1-3"]),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(expand_targets(["10.0.0.1-10.0.0.2"]),
                         ["10.0.0.1", "10.0.0.2"])

    def test_keine_duplikate(self):
        self.assertEqual(expand_targets(["10.0.0.1", "10.0.0.1", "10.0.0.1/32"]),
                         ["10.0.0.1"])

    def test_ungültig(self):
        with self.assertRaises(ValueError):
            expand_targets(["keine-ip"])

    def test_zu_großer_bereich_wird_sofort_abgelehnt(self):
        """Darf nicht erst Millionen Adressen erzeugen."""
        import time
        start = time.time()
        with self.assertRaises(ValueError) as ctx:
            expand_targets(["10.0.0.0/8"])
        self.assertIn("zu groß", str(ctx.exception))
        self.assertLess(time.time() - start, 1.0)

    def test_grenze_ist_einstellbar(self):
        self.assertEqual(len(expand_targets(["10.0.0.0/16"])), 65534)
        with self.assertRaises(ValueError):
            expand_targets(["192.168.1.0/24"], limit=100)

    def test_summe_mehrerer_ziele_zählt(self):
        # 2 x /17 sind 65.532 Adressen und damit noch erlaubt ...
        self.assertEqual(len(expand_targets(["10.0.0.0/17", "10.1.0.0/17"])), 65532)
        # ... /16 plus /17 sprengen die Grenze dagegen.
        with self.assertRaises(ValueError):
            expand_targets(["10.0.0.0/16", "10.1.0.0/17"])


class TestPorts(unittest.TestCase):
    def test_portliste(self):
        self.assertEqual(portscan.parse_port_spec("22,80,100-102"),
                         [22, 80, 100, 101, 102])
        self.assertEqual(portscan.parse_port_spec("top"), portscan.TOP_PORTS)
        self.assertEqual(len(portscan.parse_port_spec("all")), 65535)

    def test_sortiert_und_eindeutig(self):
        self.assertEqual(portscan.parse_port_spec("80,22,80"), [22, 80])

    def test_formatierung(self):
        self.assertEqual(portscan.format_ports([]), "-")
        self.assertEqual(portscan.format_ports([80, 443]), "80, 443")
        self.assertEqual(portscan.format_ports([80], True), "80/http")
        self.assertEqual(portscan.format_ports([1, 2, 3], False, 2), "1, 2, +1")


class TestOui(unittest.TestCase):
    def test_bekannte_hersteller(self):
        self.assertEqual(oui.lookup("78:20:51:AA:BB:01")[0], "TP-Link")
        self.assertEqual(oui.lookup("B8:27:EB:01:02:03"), ("Raspberry Pi", "computer"))
        self.assertEqual(oui.lookup("00:11:32:AA:BB:CC"), ("Synology", "nas"))
        self.assertEqual(oui.lookup("00:0C:29:11:22:33"), ("VMware", "vm"))

    def test_zufällige_mac(self):
        vendor, hint = oui.lookup("9E:11:22:33:44:55")
        self.assertIn("zufällige", vendor)
        self.assertIsNone(hint)

    def test_unbekannt(self):
        self.assertEqual(oui.lookup("00:00:01:02:03:04"), (None, None))
        self.assertEqual(oui.lookup(None), (None, None))

    def test_datenbank_konsistent(self):
        for prefix, (vendor, hint) in oui.BUILTIN_OUI.items():
            self.assertRegex(prefix, r"^[0-9A-F]{2}(:[0-9A-F]{2}){2}$")
            self.assertTrue(vendor)
            if hint is not None:
                self.assertIn(hint, classify.HINT_TO_CATEGORY, prefix)


class TestKlassifizierung(unittest.TestCase):
    """Jedes Profil entspricht einem realen Gerätetyp."""

    PROFILE = [
        ("Netzwerkdrucker", classify.PRINTER,
         dict(open_ports=[80, 443, 515, 631, 9100, 161], vendor="Brother",
              vendor_hint="printer", names=["BRN3C2AF4"])),
        ("Router", classify.ROUTER,
         dict(open_ports=[53, 80, 443], vendor="TP-Link", vendor_hint="network",
              is_gateway=True)),
        ("iPhone", classify.MOBILE,
         dict(open_ports=[62078], vendor="Apple", vendor_hint="computer",
              names=["iPhone-von-Anna"])),
        ("Apple TV", classify.MEDIA,
         dict(open_ports=[5000, 7000, 7100, 62078], vendor="Apple",
              vendor_hint="computer", names=["Apple-TV.local"])),
        ("MacBook", classify.MAC_PC,
         dict(open_ports=[22, 88, 445, 548], vendor="Apple",
              vendor_hint="computer", names=["MacBook-Buero.local"])),
        ("Windows-PC", classify.WIN_PC,
         dict(open_ports=[135, 139, 445, 3389, 5357], names=["DESKTOP-A1B2C3D"],
              evidence={"netbios_name": "DESKTOP-A1B2C3D"})),
        ("NAS", classify.NAS,
         dict(open_ports=[22, 80, 111, 445, 2049, 5000, 5001], vendor="Synology",
              vendor_hint="nas", names=["DiskStation"])),
        ("IP-Kamera", classify.CAMERA,
         dict(open_ports=[80, 554, 8000], vendor="Hikvision", vendor_hint="camera")),
        ("Switch", classify.SWITCH,
         dict(open_ports=[22, 23, 80, 161], vendor="Cisco", vendor_hint="network",
              evidence={"snmp_descr": "Cisco IOS Software, C2960 Software"})),
        ("IP-Telefon", classify.PHONE,
         dict(open_ports=[80, 443, 5060], vendor="Yealink", vendor_hint="phone")),
        ("Smart-Home", classify.IOT,
         dict(open_ports=[80], vendor="Espressif (ESP32/ESP8266)",
              vendor_hint="iot", names=["shelly1-A4CF12"])),
        ("Spielkonsole", classify.CONSOLE,
         dict(open_ports=[], vendor="Nintendo", vendor_hint="console",
              names=["Nintendo-Switch"])),
        ("SPS", classify.INDUSTRIAL,
         dict(open_ports=[102, 502], names=["SIMATIC-S7-1200"])),
        ("Virtuelle Maschine", classify.VM,
         dict(open_ports=[], vendor="VMware", vendor_hint="vm")),
        ("Proxmox-Server", classify.SERVER,
         dict(open_ports=[22, 8006, 3128], names=["pve-host1"])),
    ]

    def test_profile(self):
        for label, expected, kwargs in self.PROFILE:
            with self.subTest(label):
                result = classify.classify(**kwargs)
                self.assertEqual(result.category, expected,
                                 "%s -> %s (%s)" % (label, result.category,
                                                    result.scores))
                self.assertTrue(result.reasons, "%s ohne Begründung" % label)

    def test_ohne_indizien(self):
        result = classify.classify(open_ports=[])
        self.assertEqual(result.category, classify.UNKNOWN)
        self.assertEqual(result.confidence, classify.CONFIDENCE_LOW)

    def test_gateway_schlaegt_durch(self):
        result = classify.classify(open_ports=[80], is_gateway=True)
        self.assertEqual(result.category, classify.ROUTER)

    def test_drucker_ist_kein_windows_rechner(self):
        result = classify.classify(open_ports=[80, 139, 445, 515, 9100],
                                   vendor="HP (Drucker)", vendor_hint="printer")
        self.assertEqual(result.category, classify.PRINTER)

    def test_konfidenz_stufen(self):
        stark = classify.classify(open_ports=[515, 631, 9100], vendor="Brother",
                                  vendor_hint="printer")
        schwach = classify.classify(open_ports=[8080])
        self.assertEqual(stark.confidence, classify.CONFIDENCE_HIGH)
        self.assertIn(schwach.confidence,
                      (classify.CONFIDENCE_LOW, classify.CONFIDENCE_MEDIUM))


class TestAppleUnterscheidung(unittest.TestCase):
    """macOS aktiviert den AirPlay-Empfang standardmäßig. Ein Mac bietet dadurch
    dieselben Dienste und Ports an wie ein Apple TV - unterscheidbar nur über die
    Modellkennung aus dem '_device-info'-TXT-Record."""

    AIRPLAY = "_airplay._tcp.local,_raop._tcp.local,_companion-link._tcp.local"

    def test_mac_mit_airplay_ist_kein_fernseher(self):
        result = classify.classify(
            open_ports=[5000, 7000], vendor="Apple", vendor_hint="computer",
            names=["Arbeitsrechner.local"],
            evidence={"mdns_model": "Mac17,5", "mdns_osxvers": "25",
                      "mdns_services": self.AIRPLAY})
        self.assertEqual(result.category, classify.MAC_PC)

    def test_mac_ohne_aussagekräftigen_namen(self):
        result = classify.classify(
            open_ports=[22, 445, 5000, 5900, 7000], vendor="Apple",
            vendor_hint="computer",
            evidence={"mdns_model": "Mac15,3", "mdns_osxvers": "24",
                      "mdns_services": self.AIRPLAY + ",_rfb._tcp.local"})
        self.assertEqual(result.category, classify.MAC_PC)

    def test_mac_ganz_ohne_mdns(self):
        result = classify.classify(open_ports=[22, 445, 548, 5900],
                                   vendor="Apple", vendor_hint="computer")
        self.assertEqual(result.category, classify.MAC_PC)

    def test_apple_tv_bleibt_media(self):
        result = classify.classify(
            open_ports=[7000, 7100, 49152, 62078], vendor="Apple",
            vendor_hint="computer",
            evidence={"mdns_model": "J42dAP",
                      "mdns_services": self.AIRPLAY + ",_touch-able._tcp.local"})
        self.assertEqual(result.category, classify.MEDIA)

    def test_homepod_ist_media(self):
        result = classify.classify(
            open_ports=[7000, 62078], vendor="Apple", vendor_hint="computer",
            evidence={"mdns_model": "AudioAccessory5,1",
                      "mdns_services": self.AIRPLAY})
        self.assertEqual(result.category, classify.MEDIA)

    def test_iphone_bleibt_mobil(self):
        result = classify.classify(
            open_ports=[62078], vendor="Apple", vendor_hint="computer",
            evidence={"mdns_model": "iPhone14,2",
                      "mdns_services": "_companion-link._tcp.local"})
        self.assertEqual(result.category, classify.MOBILE)

    def test_modellauswertung_einzeln(self):
        faelle = [
            (None, "25", classify.MAC_PC),          # osxvers allein genügt
            ("Mac17,5", None, classify.MAC_PC),
            ("iMac21,1", None, classify.MAC_PC),
            ("AppleTV6,2", None, classify.MEDIA),
            ("AudioAccessory5,1", None, classify.MEDIA),
            ("iPhone14,2", None, classify.MOBILE),
            ("iPad13,1", None, classify.MOBILE),
        ]
        for model, osxvers, erwartet in faelle:
            with self.subTest(model=model, osxvers=osxvers):
                hints = classify.apple_model_hints(model, osxvers)
                self.assertTrue(hints)
                self.assertEqual(hints[0][0], erwartet)

    def test_platinenkennung_ohne_osxvers_ist_kein_mac(self):
        # J42dAP ist ein Apple TV; ohne osxvers darf daraus nie ein Mac werden
        hints = classify.apple_model_hints("J42dAP", None, self.AIRPLAY)
        self.assertEqual(hints[0][0], classify.MEDIA)

    def test_linux_und_windows_bleiben_unberührt(self):
        linux = classify.classify(open_ports=[22, 111], vendor="Raspberry Pi",
                                  vendor_hint="computer", names=["raspberrypi"])
        self.assertEqual(linux.category, classify.NIX_PC)
        windows = classify.classify(open_ports=[135, 139, 445, 3389],
                                    vendor="Intel", vendor_hint="computer")
        self.assertEqual(windows.category, classify.WIN_PC)


class TestNamensbereinigung(unittest.TestCase):
    def test_platzhalter_werden_verworfen(self):
        for value in ("none", "none.local", "unknown", "localhost", "-", "?",
                      "N/A", "new-device"):
            self.assertIsNone(classify.clean_name(value), value)

    def test_ip_praefix_wird_entfernt(self):
        self.assertEqual(
            classify.clean_name("192.168.1.172 - Sonos Play:1", "192.168.1.172"),
            "Sonos Play:1")

    def test_reine_ip_ist_kein_name(self):
        self.assertIsNone(classify.clean_name("192.168.1.5", "192.168.1.5"))

    def test_gueltige_namen_bleiben(self):
        self.assertEqual(classify.clean_name("  Drucker  EG "), "Drucker EG")
        self.assertEqual(classify.clean_name("MacBook.local"), "MacBook.local")

    def test_prioritaet_der_quellen(self):
        self.assertEqual(
            classify.pick_display_name({"dns_name": "a.fritz.box",
                                        "upnp_name": "Wohnzimmer-TV"}),
            "Wohnzimmer-TV")
        self.assertEqual(
            classify.pick_display_name({"mdns_name": "none.local",
                                        "dns_name": "drucker.local"}),
            "drucker.local")


class TestProtokolle(unittest.TestCase):
    def test_dns_name_kodierung(self):
        encoded = names._encode_qname("1.1.168.192.in-addr.arpa")
        self.assertTrue(encoded.endswith(b"\x00"))
        decoded, offset = names._decode_name(encoded, 0)
        self.assertEqual(decoded, "1.1.168.192.in-addr.arpa")
        self.assertEqual(offset, len(encoded))

    def test_dns_kompressionszeiger(self):
        data = names._encode_qname("drucker.local") + b"\xc0\x00"
        decoded, _ = names._decode_name(data, len(data) - 2)
        self.assertEqual(decoded, "drucker.local")

    def test_dns_antwort_parsen(self):
        # Antwort mit einem PTR-Record
        packet = struct.pack(">HHHHHH", 1, 0x8400, 1, 1, 0, 0)
        packet += names._encode_qname("1.1.168.192.in-addr.arpa")
        packet += struct.pack(">HH", 12, 1)
        packet += names._encode_qname("1.1.168.192.in-addr.arpa")
        rdata = names._encode_qname("router.local")
        packet += struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
        records = names._parse_dns_answers(packet)
        self.assertEqual(len(records), 1)
        name, rrtype, _rdata, rdoff = records[0]
        self.assertEqual(rrtype, 12)
        self.assertEqual(names._decode_name(packet, rdoff)[0], "router.local")

    def test_txt_record_parsen(self):
        rdata = b"\x0fmodel=Mac17,5" .replace(b"\x0f", bytes([13]))
        rdata = bytes([13]) + b"model=Mac17,5" + bytes([11]) + b"osxvers=25"
        self.assertEqual(names._parse_txt(rdata),
                         {"model": "Mac17,5", "osxvers": "25"})

    def test_txt_record_ohne_gleichheitszeichen(self):
        self.assertEqual(names._parse_txt(bytes([4]) + b"nurso"[:4]), {})

    def test_netbios_namenskodierung(self):
        encoded = names._encode_netbios_name("*")
        self.assertEqual(len(encoded), 34)            # 1 + 32 + 1
        self.assertEqual(encoded[0], 32)
        self.assertEqual(encoded[1:3], b"CK")          # '*' = 0x2A -> 'C','K'
        self.assertEqual(encoded[-1], 0)

    def test_snmp_ber_kodierung(self):
        oid = names._ber_oid("1.3.6.1.2.1.1.5.0")
        self.assertEqual(oid[0], 0x06)                 # OID-Tag
        self.assertEqual(oid[2], 0x2B)                 # 1.3 -> 40*1+3
        self.assertEqual(names._ber_len(3), b"\x03")
        self.assertEqual(names._ber_len(200), b"\x81\xc8")

    def test_snmp_antwort_auswerten(self):
        varbind = names._tlv(0x30, names._ber_oid("1.3.6.1.2.1.1.5.0")
                             + names._tlv(0x04, b"Drucker-EG"))
        pdu = (names._ber_int(1) + names._ber_int(0) + names._ber_int(0)
               + names._tlv(0x30, varbind))
        message = names._tlv(0x30, names._ber_int(1)
                             + names._tlv(0x04, b"public")
                             + names._tlv(0xA2, pdu))
        self.assertIn("Drucker-EG", names._snmp_values(message))


class TestAusgabe(unittest.TestCase):
    def setUp(self):
        self.devices = [
            make_device("192.168.1.1", "78:20:51:AA:BB:01", "TP-Link",
                        "Archer AX53", "Router / Gateway", [53, 80, 443]),
            make_device("192.168.1.50", "3C:2A:F4:11:22:33", "Brother",
                        "BRN3C2AF4", "Drucker / MFP", [80, 515, 9100]),
            make_device("192.168.1.100"),
        ]
        self.devices[0].is_gateway = True
        self.devices[1].reasons = ["Port 9100 (RAW-Druck)"]

    def test_texttabelle(self):
        table = report.text_table(self.devices)
        self.assertIn("192.168.1.1", table)
        self.assertIn("Archer AX53", table)
        self.assertIn("9100", table)
        self.assertEqual(len(table.strip().splitlines()), 5)   # Kopf + Linie + 3

    def test_texttabelle_mit_begruendung(self):
        table = report.text_table(self.devices, show_why=True)
        self.assertIn("Begründung", table)
        self.assertIn("RAW-Druck", table)

    def test_tabelle_bleibt_in_der_breite(self):
        for width in (80, 100, 200):
            table = report.text_table(self.devices, True, width, True)
            for line in table.splitlines():
                self.assertLessEqual(len(line), width, "Breite %d" % width)

    def test_csv(self):
        text = report.to_csv(self.devices)
        lines = text.strip().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertIn("IP-Adresse;MAC-Adresse", lines[0])
        self.assertIn("Archer AX53", lines[1])
        self.assertIn("ja", lines[1])                          # Gateway-Spalte

    def test_json(self):
        import json
        data = json.loads(report.to_json(self.devices, {"Netz": "test"}))
        self.assertEqual(data["count"], 3)
        self.assertEqual(data["devices"][0]["ip"], "192.168.1.1")
        self.assertEqual(data["devices"][1]["services"]["9100"], "printer-raw")
        self.assertTrue(data["devices"][0]["is_gateway"])

    def test_html(self):
        html_text = report.to_html(self.devices, {"Netz": "192.168.1.0/24"})
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn("Archer AX53", html_text)
        self.assertIn("Drucker / MFP", html_text)
        self.assertIn("prefers-color-scheme", html_text)       # Dunkelmodus
        self.assertEqual(html_text.count("<tr>"), 4)      # Kopfzeile + 3 Geräte

    def test_html_maskiert_sonderzeichen(self):
        device = make_device("10.0.0.1", hostname="<script>alert(1)</script>")
        html_text = report.to_html([device])
        self.assertNotIn("<script>alert", html_text)
        self.assertIn("&lt;script&gt;", html_text)

    def test_zusammenfassung(self):
        text = report.summary(self.devices, 12.5)
        self.assertIn("3 Geräte", text)
        self.assertIn("12.5 s", text)
        self.assertIn("Router / Gateway: 1", text)


class TestFilterUndSortierung(unittest.TestCase):
    def setUp(self):
        self.devices = [
            make_device("192.168.1.10", "AA:BB:CC:00:00:01", "Brother",
                        "BRN123", "Drucker / MFP", [515, 9100]),
            make_device("192.168.1.2", "AA:BB:CC:00:00:02", "TP-Link",
                        "Router", "Router / Gateway", [53, 80]),
            make_device("192.168.1.100"),
        ]

    def test_filter(self):
        self.assertEqual([d.ip for d in report.filter_devices(self.devices, "drucker")],
                         ["192.168.1.10"])
        self.assertEqual([d.ip for d in report.filter_devices(self.devices, "9100")],
                         ["192.168.1.10"])
        self.assertEqual(len(report.filter_devices(self.devices, "")), 3)
        self.assertEqual(len(report.filter_devices(self.devices, "gibtsnicht")), 0)

    def test_filter_mehrere_begriffe(self):
        self.assertEqual(
            [d.ip for d in report.filter_devices(self.devices, "brother 9100")],
            ["192.168.1.10"])
        self.assertEqual(
            len(report.filter_devices(self.devices, "brother tp-link")), 0)

    def test_filter_findet_dienstnamen(self):
        self.assertEqual(
            [d.ip for d in report.filter_devices(self.devices, "printer-raw")],
            ["192.168.1.10"])

    def test_sortierung_ip_numerisch(self):
        self.assertEqual([d.ip for d in report.sort_devices(self.devices, "ip")],
                         ["192.168.1.2", "192.168.1.10", "192.168.1.100"])

    def test_sortierung_umkehrbar(self):
        forward = [d.ip for d in report.sort_devices(self.devices, "vendor")]
        backward = [d.ip for d in report.sort_devices(self.devices, "vendor", True)]
        self.assertEqual(forward, list(reversed(backward)))

    def test_sortierung_nach_portanzahl(self):
        self.assertEqual(
            [len(d.open_ports) for d in report.sort_devices(self.devices, "ports", True)],
            [2, 2, 0])


class TestGerät(unittest.TestCase):
    def test_serialisierung(self):
        device = make_device("192.168.1.5", "00:11:32:AA:BB:CC", "Synology",
                             "DiskStation", "NAS / Storage", [445, 5000])
        data = device.to_dict()
        self.assertEqual(data["ip"], "192.168.1.5")
        self.assertEqual(data["services"]["445"], "smb")
        self.assertIn("evidence", data)

    def test_sortierschluessel(self):
        self.assertEqual(Device("10.0.0.9").sort_key, (10, 0, 0, 9))
        self.assertLess(Device("192.168.1.9").sort_key, Device("192.168.1.10").sort_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
