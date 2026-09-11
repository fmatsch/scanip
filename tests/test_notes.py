"""Tests der dauerhaften Gerätenotizen - schreiben nur in ein temporäres Verzeichnis."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanip import notes, report
from scanip.scanner import Device


class NotizTestFall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        notes.use_path(os.path.join(self.tmp, "notes.json"))

    def tearDown(self):
        notes.use_path(None)
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestSpeichern(NotizTestFall):
    def test_speichern_und_lesen(self):
        self.assertTrue(notes.set_note("AA:BB:CC:DD:EE:FF", "192.168.1.5", "Drucker EG"))
        self.assertEqual(notes.get("AA:BB:CC:DD:EE:FF"), "Drucker EG")

    def test_ueberdauert_neustart(self):
        notes.set_note("AA:BB:CC:DD:EE:FF", "192.168.1.5", "bleibt erhalten")
        notes.reload()                       # simuliert einen Programmneustart
        self.assertEqual(notes.get("AA:BB:CC:DD:EE:FF"), "bleibt erhalten")

    def test_notiz_folgt_dem_geraet_bei_neuer_ip(self):
        """Der eigentliche Zweck: DHCP vergibt eine andere IP, die Notiz bleibt."""
        notes.set_note("AA:BB:CC:DD:EE:FF", "192.168.1.5", "Drucker Buchhaltung")
        self.assertEqual(notes.get("AA:BB:CC:DD:EE:FF", "192.168.1.199"),
                         "Drucker Buchhaltung")

    def test_ohne_mac_wird_die_ip_zum_schlüssel(self):
        notes.set_note(None, "10.0.0.7", "Gerät hinter dem Router")
        self.assertEqual(notes.get(None, "10.0.0.7"), "Gerät hinter dem Router")
        self.assertEqual(notes.get(None, "10.0.0.8"), "")

    def test_mac_schreibweise_egal(self):
        notes.set_note("aa:bb:cc:dd:ee:ff", "192.168.1.5", "kleingeschrieben")
        self.assertEqual(notes.get("AA:BB:CC:DD:EE:FF"), "kleingeschrieben")

    def test_leerer_text_löscht(self):
        notes.set_note("AA:BB:CC:DD:EE:FF", None, "weg damit")
        self.assertEqual(notes.count(), 1)
        notes.set_note("AA:BB:CC:DD:EE:FF", None, "   ")
        self.assertEqual(notes.count(), 0)
        self.assertEqual(notes.get("AA:BB:CC:DD:EE:FF"), "")

    def test_ohne_gerät_kein_schlüssel(self):
        self.assertFalse(notes.set_note(None, None, "ins Leere"))
        self.assertIsNone(notes.device_key(None, None))

    def test_umlaute_und_zeilenumbrüche(self):
        text = "Büro 2. OG\nAnschluss hinter dem Schrank – Schlüssel bei Müller"
        notes.set_note("AA:BB:CC:DD:EE:FF", None, text)
        notes.reload()
        self.assertEqual(notes.get("AA:BB:CC:DD:EE:FF"), text)

    def test_länge_wird_begrenzt(self):
        notes.set_note("AA:BB:CC:DD:EE:FF", None, "x" * 5000)
        self.assertEqual(len(notes.get("AA:BB:CC:DD:EE:FF")), notes.MAX_LENGTH)

    def test_dateiformat(self):
        notes.set_note("AA:BB:CC:DD:EE:FF", "192.168.1.5", "Text", "Drucker")
        with open(notes.notes_path(), encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["version"], notes.FORMAT_VERSION)
        eintrag = data["notes"]["AA:BB:CC:DD:EE:FF"]
        self.assertEqual(eintrag["text"], "Text")
        self.assertEqual(eintrag["last_ip"], "192.168.1.5")
        self.assertEqual(eintrag["last_name"], "Drucker")
        self.assertIn("updated", eintrag)

    def test_beschädigte_datei_wird_verkraftet(self):
        with open(notes.notes_path(), "w", encoding="utf-8") as handle:
            handle.write("{kein gültiges JSON")
        notes.reload()
        self.assertEqual(notes.count(), 0)
        self.assertTrue(notes.set_note("AA:BB:CC:DD:EE:FF", None, "neu"))

    def test_einfaches_textformat_wird_gelesen(self):
        with open(notes.notes_path(), "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "notes": {"AA:BB:CC:DD:EE:FF": "kurzform"}}, handle)
        notes.reload()
        self.assertEqual(notes.get("AA:BB:CC:DD:EE:FF"), "kurzform")

    def test_löschen(self):
        notes.set_note("AA:BB:CC:DD:EE:FF", None, "weg")
        self.assertTrue(notes.delete("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(notes.delete("AA:BB:CC:DD:EE:FF"))

    def test_auflistung(self):
        notes.set_note("AA:BB:CC:DD:EE:FF", "192.168.1.5", "Drucker", "HP")
        zeilen = notes.format_list()
        self.assertEqual(len(zeilen), 1)
        self.assertIn("Drucker", zeilen[0])
        self.assertIn("HP", zeilen[0])


class TestAusgabeMitNotizen(NotizTestFall):
    def _geraet(self, note=""):
        device = Device("192.168.1.50")
        device.mac = "AA:BB:CC:DD:EE:FF"
        device.vendor = "Brother"
        device.hostname = "BRN123"
        device.category = "Drucker / MFP"
        device.open_ports = [9100]
        device.note = note
        return device

    def test_spalte_erscheint_nur_bei_bedarf(self):
        ohne = report.text_table([self._geraet()])
        self.assertNotIn("Notiz", ohne)
        mit = report.text_table([self._geraet("Buchhaltung")])
        self.assertIn("Notiz", mit)
        self.assertIn("Buchhaltung", mit)

    def test_spalte_erzwingbar(self):
        self.assertIn("Notiz", report.text_table([self._geraet()], show_notes=True))
        self.assertNotIn("Notiz",
                         report.text_table([self._geraet("x")], show_notes=False))

    def test_csv_enthält_notiz(self):
        text = report.to_csv([self._geraet("Buchhaltung, 2. OG")])
        self.assertIn("Notiz", text.splitlines()[0])
        self.assertIn("Buchhaltung, 2. OG", text)

    def test_json_enthält_notiz_und_schlüssel(self):
        data = json.loads(report.to_json([self._geraet("Testnotiz")]))
        geraet = data["devices"][0]
        self.assertEqual(geraet["note"], "Testnotiz")
        self.assertEqual(geraet["note_key"], "AA:BB:CC:DD:EE:FF")

    def test_html_enthält_notiz_maskiert(self):
        html_text = report.to_html([self._geraet("<b>fett</b>")])
        self.assertIn("&lt;b&gt;fett", html_text)
        self.assertNotIn("<b>fett</b>", html_text)

    def test_filter_findet_notiztext(self):
        geraete = [self._geraet("Buchhaltung"), self._geraet()]
        geraete[1].ip = "192.168.1.51"
        treffer = report.filter_devices(geraete, "buchhaltung")
        self.assertEqual([g.ip for g in treffer], ["192.168.1.50"])


class TestOberflaechenAnbindung(NotizTestFall):
    """Prüft die Teile der Bedienoberflächen, die ohne Fenster testbar sind."""

    def test_tk_spalte_vorhanden(self):
        from scanip import gui
        schluessel = [key for key, _titel, _breite in gui.COLUMNS]
        self.assertIn("note", schluessel)

    def test_tk_wertetupel_passt_zur_spaltenzahl(self):
        """Die Hinweiszeile muss genauso viele Werte liefern wie es Spalten gibt."""
        from scanip import gui
        import inspect
        quelltext = inspect.getsource(gui.ScanApp._refresh_table)
        # Hinweiszeile: values=("", "", "", hint, "", "", "")
        treffer = [zeile for zeile in quelltext.splitlines() if "__hinweis__" in zeile]
        self.assertTrue(treffer)
        werte = quelltext.split('values=("", "", "", hint')[1].split(")")[0]
        anzahl = 4 + werte.count(',')
        self.assertEqual(anzahl, len(gui.COLUMNS))

    def test_web_seite_enthaelt_notizspalte(self):
        from scanip import web
        seite = web.PAGE_TEMPLATE % {"version": "1", "token": "t",
                                     "target": "192.168.1.0/24", "presets": ""}
        self.assertIn("notecell", seite)
        self.assertIn("bearbeiteNotiz", seite)
        self.assertIn(">Notiz<", seite)

    def test_web_tabellenbreite_stimmt(self):
        """colspan der Platzhalterzeilen muss zur Spaltenzahl passen."""
        from scanip import web
        seite = web.PAGE_TEMPLATE % {"version": "1", "token": "t",
                                     "target": "x", "presets": ""}
        kopfspalten = seite.count('<th data-key=')
        import re
        for colspan in re.findall(r"colspan='?\"?(\d+)", seite):
            self.assertEqual(int(colspan), kopfspalten)

    def test_geraet_bekommt_notiz_beim_scan(self):
        """_finalize muss die gespeicherte Notiz an das Gerät hängen."""
        from scanip.scanner import Scanner
        notes.set_note("AA:BB:CC:DD:EE:FF", "192.168.1.5", "vorhandene Notiz")
        notes.reload()
        device = Device("192.168.1.5")
        device.mac = "AA:BB:CC:DD:EE:FF"
        scanner = Scanner()
        scanner._gateways = set()
        scanner._local_ips = set()
        scanner._finalize(device)
        self.assertEqual(device.note, "vorhandene Notiz")


if __name__ == "__main__":
    unittest.main(verbosity=2)
