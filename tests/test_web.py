"""Tests der Browser-Oberfläche - startet einen echten Server auf 127.0.0.1.

Es wird kein Netzwerkscan ausgelöst; geprüft werden Zustandsverwaltung,
Token-Absicherung, Routen und Exporte.
"""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanip import web
from scanip.scanner import Device


def make_device(ip, mac=None, vendor=None, hostname=None, category="Unbekannt",
                open_ports=()):
    device = Device(ip)
    device.mac, device.vendor, device.hostname = mac, vendor, hostname
    device.category, device.open_ports = category, list(open_ports)
    return device


class TestScanState(unittest.TestCase):
    def setUp(self):
        self.state = web.ScanState()

    def test_ausgangszustand(self):
        data = self.state.snapshot()
        self.assertFalse(data["running"])
        self.assertEqual(data["phase"], "idle")
        self.assertEqual(data["devices"], [])
        self.assertIsNone(data["error"])

    def test_ungueltiges_ziel_startet_keinen_scan(self):
        for ziel in ("keine-ip", "", "   "):
            error = self.state.start(ziel, "top", False)
            self.assertIsNotNone(error, ziel)
            self.assertFalse(self.state.running)

    def test_zu_grosser_bereich_wird_abgelehnt(self):
        error = self.state.start("10.0.0.0/8", "top", False)
        self.assertIn("zu groß", error)
        self.assertFalse(self.state.running)

    def test_geraetezeile_enthaelt_anzeigefelder(self):
        device = make_device("192.168.1.50", "3C:2A:F4:11:22:33", "Brother",
                             "BRN3C2AF4", "Drucker / MFP", [80, 443, 9100])
        row = web.ScanState._device_row(device)
        self.assertEqual(row["ports_text"], "80/http, 443/https, 9100/printer-raw")
        self.assertEqual(row["web_url"], "http://192.168.1.50")
        self.assertEqual(row["name_suffix"], "")

    def test_geraetezeile_markiert_gateway_und_eigenen_rechner(self):
        gateway = make_device("192.168.1.1")
        gateway.is_gateway = True
        self.assertEqual(web.ScanState._device_row(gateway)["name_suffix"], "Gateway")
        own = make_device("192.168.1.95")
        own.is_self = True
        self.assertEqual(web.ScanState._device_row(own)["name_suffix"], "dieser Rechner")

    def test_weblink_nutzt_https_und_port(self):
        device = make_device("10.0.0.5", open_ports=[8443])
        self.assertEqual(web.ScanState._device_row(device)["web_url"],
                         "https://10.0.0.5:8443")
        self.assertIsNone(web.ScanState._device_row(make_device("10.0.0.6"))["web_url"])


class TestSeite(unittest.TestCase):
    def test_vorlage_rendert(self):
        page = web.PAGE_TEMPLATE % {
            "version": "1.0.0", "token": "geheim",
            "target": "192.168.1.0/24", "presets": "<option>x</option>"}
        self.assertIn("<!DOCTYPE html>", page)
        self.assertIn('var TOKEN = "geheim"', page)
        self.assertIn("192.168.1.0/24", page)
        self.assertIn("prefers-color-scheme", page)
        self.assertNotIn("%(", page)                  # alle Platzhalter ersetzt

    def test_alle_portvoreinstellungen_sind_gueltig(self):
        from scanip import ports as portscan
        for key, (label, spec) in web.PORT_PRESETS.items():
            self.assertTrue(label)
            if spec is not None:
                self.assertTrue(portscan.parse_port_spec(spec), key)


class TestServer(unittest.TestCase):
    """Echter Server auf einem freien Loopback-Port."""

    @classmethod
    def setUpClass(cls):
        from scanip import netinfo
        netinfo.interfaces()          # Zwischenspeicher füllen (unter Windows langsam)
        cls.state = web.ScanState()
        cls.token = "test-token-1234567890"
        handler = type("TestHandler", (web.Handler,),
                       {"state": cls.state, "token": cls.token})
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def url(self, path, token=None):
        base = "http://127.0.0.1:%d%s" % (self.port, path)
        if token is not None:
            base += ("&" if "?" in base else "?") + "token=" + token
        return base

    def get(self, path, token=None, method="GET", data=None):
        request = urllib.request.Request(self.url(path, token), method=method,
                                         data=data)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def test_ohne_token_abgewiesen(self):
        self.assertEqual(self.get("/api/status")[0], 403)
        self.assertEqual(self.get("/")[0], 403)

    def test_falsches_token_abgewiesen(self):
        self.assertEqual(self.get("/api/status", "falsch")[0], 403)
        self.assertEqual(self.get("/", "falsch")[0], 403)

    def test_richtiges_token_erlaubt(self):
        status, body = self.get("/api/status", self.token)
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["running"])

    def test_startseite(self):
        status, body = self.get("/", self.token)
        self.assertEqual(status, 200)
        self.assertIn("Netzwerk-Scanner", body)
        self.assertIn("Scan starten", body)

    def test_unbekannter_pfad(self):
        self.assertEqual(self.get("/gibtsnicht", self.token)[0], 404)

    def test_scan_mit_ungueltigem_ziel(self):
        status, body = self.get("/api/scan", self.token, "POST",
                                json.dumps({"target": "keine-ip"}).encode())
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(body))

    def test_export_liefert_alle_formate(self):
        self.state.devices = [make_device("192.168.1.1", "AA:BB:CC:DD:EE:FF",
                                          "TP-Link", "Router",
                                          "Router / Gateway", [80])]
        for fmt, marker in (("html", "<!DOCTYPE html>"), ("csv", "IP-Adresse;"),
                            ("json", '"devices"')):
            status, body = self.get("/api/export?format=" + fmt, self.token)
            self.assertEqual(status, 200, fmt)
            self.assertIn(marker, body, fmt)
            self.assertIn("192.168.1.1", body, fmt)

    def test_abbrechen_ohne_laufenden_scan(self):
        status, body = self.get("/api/cancel", self.token, "POST", b"{}")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
