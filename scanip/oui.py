"""MAC-Hersteller-Datenbank (OUI).

Eingebaut ist eine kuratierte Liste der im LAN häufigsten Hersteller.
Für die vollstaendige IEEE-Registrierung:  python -m scanip --update-oui
(laedt https://standards-oui.ieee.org/oui/oui.csv in den Cache-Ordner).
Alternativ wird die 'manuf'-Datei von Wireshark automatisch genutzt, falls vorhanden.
"""

from __future__ import annotations

import csv
import os
import re
import sys
from typing import Dict, Optional, Tuple

# prefix -> (Hersteller, Kategorie-Hinweis oder None)
# Kategorie-Hinweise: printer, computer, phone, camera, network, nas, media,
#                     iot, mobile, console, vm, industrial
BUILTIN_OUI: Dict[str, Tuple[str, Optional[str]]] = {}


def _add(vendor: str, hint: Optional[str], *prefixes: str) -> None:
    """Traegt Präfixe ein. Normalisiert die Schreibweise und meldet Tippfehler."""
    for prefix in prefixes:
        normalized = prefix.upper().replace("-", ":")
        if ":" not in normalized and len(normalized) == 6:     # "0005CD"
            normalized = ":".join(normalized[i:i + 2] for i in (0, 2, 4))
        if not re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){2}", normalized):
            raise ValueError("Ungültiges OUI-Präfix %r für %s" % (prefix, vendor))
        BUILTIN_OUI[normalized] = (vendor, hint)


# --- Apple ------------------------------------------------------------------
_add("Apple", "computer",
     "00:03:93", "00:0A:27", "00:0A:95", "00:16:CB", "00:17:F2", "00:1B:63",
     "00:1E:C2", "00:1F:F3", "00:23:12", "00:25:00", "00:26:BB", "00:C6:10",
     "04:0C:CE", "04:1E:64", "04:26:65", "04:54:53", "04:F1:3E", "08:00:07",
     "0C:30:21", "0C:3E:9F", "0C:4D:E9", "0C:74:C2", "10:40:F3", "10:93:E9",
     "10:9A:DD", "14:10:9F", "14:5A:05", "18:AF:61", "18:E7:F4", "1C:AB:A7",
     "20:C9:D0", "24:AB:81", "28:6A:BA", "28:CF:E9", "28:E0:2C", "2C:B4:3A",
     "30:10:E4", "30:90:AB", "34:15:9E", "34:C0:59", "38:C9:86", "3C:07:54",
     "3C:15:C2", "40:6C:8F", "40:A6:D9", "44:D8:84", "48:60:BC", "4C:8D:79",
     "50:EA:D6", "54:26:96", "58:55:CA", "5C:95:AE", "60:03:08", "60:33:4B",
     "60:FB:42", "64:20:0C", "64:B9:E8", "68:96:7B", "68:A8:6D", "6C:40:08",
     "70:CD:60", "70:DE:E2", "74:E2:F5", "78:31:C1", "78:CA:39", "7C:6D:62",
     "7C:C3:A1", "80:92:9F", "84:38:35", "88:63:DF", "8C:2D:AA", "8C:58:77",
     "90:27:E4", "90:B2:1F", "98:01:A7", "98:5A:EB", "9C:04:EB", "9C:20:7B",
     "A0:99:9B", "A4:5E:60", "A4:B1:97", "A8:20:66", "A8:66:7F", "AC:87:A3",
     "B0:34:95", "B0:65:BD", "B4:F0:AB", "B8:17:C2", "B8:E8:56", "BC:52:B7",
     "BC:92:6B", "C0:84:7A", "C4:2C:03", "C8:1E:E7", "C8:69:CD", "C8:BC:C8",
     "CC:08:E0", "CC:29:F5", "D0:23:DB", "D0:81:7A", "D4:9A:20", "D8:00:4D",
     "D8:30:62", "DC:2B:2A", "DC:A9:04", "E0:B9:BA", "E4:8B:7F", "E4:CE:8F",
     "E8:80:2E", "EC:35:86", "F0:18:98", "F0:B4:79", "F4:1B:A1", "F4:37:B7",
     "F8:1E:DF", "FC:25:3F")

# --- PC-/Server-Hersteller ---------------------------------------------------
_add("Dell", "computer", "00:06:5B", "00:08:74", "00:11:43", "00:14:22",
     "00:1A:A0", "00:1E:4F", "00:21:9B", "00:22:19", "00:24:E8", "00:26:B9",
     "14:FE:B5", "18:66:DA", "18:A9:9B", "24:6E:96", "34:17:EB", "44:A8:42",
     "4C:D9:8F", "50:9A:4C", "54:BF:64", "78:2B:CB", "84:2B:2B", "B0:83:FE",
     "B8:2A:72", "B8:AC:6F", "D0:67:E5", "D4:AE:52", "E4:43:4B", "F0:1F:AF",
     "F8:BC:12", "F8:DB:88")
_add("Hewlett Packard", "computer", "00:0B:CD", "00:0E:7F", "00:14:38",
     "00:17:A4", "00:1B:78", "00:1F:29", "00:21:5A", "00:23:7D", "00:25:B3",
     "00:26:55", "10:1F:74", "14:02:EC", "18:A9:05", "2C:23:3A", "2C:41:38",
     "30:8D:99", "38:63:BB", "3C:D9:2B", "48:0F:CF", "5C:8A:38", "6C:3B:E5",
     "78:AC:C0", "80:C1:6E", "94:18:82", "98:E7:F4", "9C:8E:99", "A0:1D:48",
     "A0:8C:FD", "B4:99:BA", "C8:CB:B8", "D0:7E:28", "D4:85:64", "D8:9D:67",
     "DC:4A:3E", "EC:8E:B5", "F4:CE:46", "FC:15:B4")
_add("Hewlett Packard Enterprise", "network", "00:17:08", "00:1C:C4",
     "3C:A8:2A", "40:A8:F0", "70:10:6F", "94:F1:28", "9C:DC:71", "B0:5A:DA")
_add("Lenovo", "computer", "00:12:FE", "00:59:07", "08:D4:0C", "10:51:72",
     "28:D2:44", "44:8A:5B", "48:0F:8E", "50:7B:9D", "54:E1:AD", "60:D9:C7",
     "68:F7:28", "6C:5F:1C", "70:72:0D", "8C:16:45", "98:FA:9B", "A4:8C:DB",
     "E8:6A:64", "F8:B1:56")
_add("ASUSTek", "computer", "00:0C:6E", "00:0E:A6", "00:11:2F", "00:13:D4",
     "00:15:F2", "00:17:31", "00:1A:92", "00:1B:FC", "00:1D:60", "00:1E:8C",
     "00:22:15", "00:23:54", "00:24:8C", "00:26:18", "04:92:26", "04:D4:C4",
     "08:60:6E", "0C:9D:92", "10:7B:44", "10:C3:7B", "14:DA:E9", "1C:87:2C",
     "20:CF:30", "2C:4D:54", "30:5A:3A", "38:D5:47", "40:16:7E", "50:46:5D",
     "54:04:A6", "60:45:CB", "70:4D:7B", "74:D0:2B", "88:D7:F6", "9C:5C:8E",
     "AC:22:0B", "AC:9E:17", "B0:6E:BF", "BC:AE:C5", "C8:60:00", "D8:50:E6",
     "E0:3F:49", "F4:6D:04", "FC:34:97")
_add("Micro-Star (MSI)", "computer", "00:16:17", "00:21:85", "00:24:21",
     "00:D8:61", "30:9C:23", "44:8A:5B", "70:85:C2", "8C:89:A5", "A4:BB:6D",
     "D8:CB:8A", "E0:D5:5E")
_add("Gigabyte", "computer", "00:1D:7D", "00:24:1D", "1C:6F:65", "20:CF:30",
     "40:8D:5C", "50:E5:49", "74:D4:35", "94:DE:80", "B4:2E:99", "D8:5E:D3",
     "E0:D5:5E", "FC:AA:14")
_add("Intel", "computer", "00:02:B3", "00:03:47", "00:04:23", "00:0C:F1",
     "00:0E:0C", "00:12:F0", "00:13:02", "00:13:20", "00:15:00", "00:16:76",
     "00:19:D1", "00:1B:21", "00:1C:C0", "00:1E:64", "00:1F:3B", "00:21:5C",
     "00:22:FA", "00:24:D7", "00:27:10", "08:11:96", "0C:8B:FD", "10:0B:A9",
     "18:3D:A2", "1C:3E:84", "1C:4D:70", "28:B2:BD", "34:13:E8", "34:E1:2D",
     "3C:A9:F4", "44:85:00", "48:51:B7", "4C:79:BA", "50:76:AF", "58:94:6B",
     "5C:51:4F", "5C:E0:C5", "60:57:18", "64:80:99", "68:05:CA", "6C:29:95",
     "70:1C:E7", "7C:B2:7D", "80:19:34", "84:3A:4B", "88:53:2E", "8C:55:4A",
     "94:65:9C", "98:AF:65", "9C:B6:D0", "A0:A8:CD", "A4:34:D9", "A4:C4:94",
     "AC:7B:A1", "B0:35:9F", "B4:96:91", "C8:34:8E", "CC:D9:AC", "D0:57:7B",
     "D8:F2:CA", "E4:A4:71", "E8:2A:EA", "EC:A5:3E", "F8:63:3F", "FC:F8:AE")
_add("Acer", "computer", "00:00:E2", "00:01:24", "00:02:E3", "00:1B:24",
     "00:24:8C", "08:00:87", "C0:38:96")
_add("Fujitsu", "computer", "00:00:0E", "00:0B:5D", "00:17:42", "00:19:99",
     "00:1E:A7", "90:1B:0E", "D4:81:D7")
_add("Toshiba", "computer", "00:00:39", "00:08:0D", "00:23:18", "18:A9:05",
     "3C:07:71", "B8:6B:23")
_add("Supermicro", "computer", "00:25:90", "0C:C4:7A", "3C:EC:EF", "7C:C2:55",
     "AC:1F:6B")

# --- Virtualisierung ---------------------------------------------------------
_add("VMware", "vm", "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "00:50:57")
_add("VirtualBox / Oracle", "vm", "08:00:27", "0A:00:27", "52:54:00")
_add("Microsoft (Hyper-V/Xbox)", "vm", "00:03:FF", "00:15:5D", "00:17:FA",
     "00:1D:D8", "00:22:48", "00:25:AE", "28:18:78", "60:45:BD", "7C:1E:52",
     "98:5F:D3", "C8:3F:26", "D4:81:D7", "DC:98:40")
_add("Parallels", "vm", "00:1C:42")
_add("Xen / Citrix", "vm", "00:16:3E")
_add("QEMU/KVM", "vm", "52:54:00")

# --- Netzwerk ----------------------------------------------------------------
_add("Cisco", "network", "00:00:0C", "00:01:42", "00:01:63", "00:06:28",
     "00:0A:41", "00:0B:BE", "00:0E:38", "00:0F:23", "00:11:5C", "00:12:80",
     "00:14:1B", "00:15:C7", "00:17:5A", "00:19:E7", "00:1B:0D", "00:1D:45",
     "00:1E:F7", "00:21:1B", "00:22:90", "00:24:97", "00:26:99", "04:6C:9D",
     "0C:11:67", "1C:DF:0F", "2C:3F:38", "34:BD:C8", "38:1C:1A", "3C:5E:C3",
     "40:CE:24", "50:57:A8", "58:97:1E", "6C:41:6A", "70:DB:98", "78:BC:1A",
     "88:5A:92", "A0:EC:F9", "B0:AA:77", "BC:16:65", "C4:14:3C", "D0:C7:89",
     "E0:2F:6D", "EC:BD:1D", "F4:0F:1B", "F8:72:EA")
_add("Cisco Meraki", "network", "00:18:0A", "0C:8D:DB", "88:15:44", "98:18:88",
     "AC:17:C8", "E0:CB:BC")
_add("Ubiquiti", "network", "00:15:6D", "00:27:22", "04:18:D6", "18:E8:29",
     "24:5A:4C", "24:A4:3C", "44:D9:E7", "68:72:51", "68:D7:9A", "74:83:C2",
     "78:45:58", "78:8A:20", "80:2A:A8", "9C:05:D6", "B4:FB:E4", "DC:9F:DB",
     "E0:63:DA", "F0:9F:C2", "FC:EC:DA")
_add("AVM (FRITZ!Box)", "network", "00:04:0E", "00:1C:4A", "00:24:FE",
     "08:96:D7", "1C:ED:6F", "24:65:11", "2C:91:AB", "34:31:C4", "38:10:D5",
     "3C:A6:2F", "5C:49:79", "6C:B0:CE", "9C:C7:A6", "BC:05:43", "C8:0E:14",
     "D8:EB:97", "E0:28:6D", "E8:DF:70", "F0:B0:14")
_add("TP-Link", "network", "00:0A:EB", "00:19:E0", "00:1D:0F", "00:21:27",
     "00:23:CD", "00:25:86", "00:27:19", "04:8D:38", "0C:80:63", "10:FE:ED",
     "14:CC:20", "14:CF:92", "18:A6:F7", "1C:3B:F3", "24:69:68", "30:B5:C2",
     "34:60:F9", "3C:46:D8", "40:16:9F", "50:64:2B", "50:C7:BF", "54:C8:0F",
     "5C:63:BF", "60:32:B1", "64:66:B3", "64:70:02", "6C:5A:B0", "74:DA:88",
     "78:20:51", "78:8C:B5", "84:16:F9", "8C:21:0A", "90:9A:4A", "94:0C:6D",
     "98:DA:C4", "9C:53:22", "A0:F3:C1", "A4:2B:B0", "AC:15:A2", "AC:84:C6",
     "B0:48:7A", "B0:95:8E", "B4:B0:24", "BC:46:99", "C0:06:C3", "C0:4A:00",
     "C4:6E:1F", "C4:71:54", "CC:32:E5", "D8:07:B6", "D8:47:32", "E8:48:B8",
     "EC:08:6B", "EC:17:2F", "F0:F3:36", "F4:28:53", "F4:EC:38", "F8:1A:67",
     "FC:7C:02")
_add("Netgear", "network", "00:09:5B", "00:0F:B5", "00:14:6C", "00:18:4D",
     "00:1B:2F", "00:1E:2A", "00:22:3F", "00:24:B2", "00:26:F2", "04:A1:51",
     "08:02:8E", "10:0C:6B", "20:4E:7F", "28:C6:8E", "2C:30:33", "30:46:9A",
     "34:98:B5", "44:94:FC", "4C:60:DE", "6C:B0:CE", "74:44:01", "84:1B:5E",
     "9C:3D:CF", "A0:04:60", "A0:40:A0", "B0:39:56", "B0:B9:8A", "C0:3F:0E",
     "C0:FF:D4", "CC:40:D0", "E0:46:9A", "E0:91:F5", "E4:F4:C6", "F8:73:94")
_add("D-Link", "network", "00:05:5D", "00:0D:88", "00:0F:3D", "00:13:46",
     "00:15:E9", "00:17:9A", "00:19:5B", "00:1B:11", "00:1C:F0", "00:1E:58",
     "00:21:91", "00:22:B0", "00:24:01", "00:26:5A", "14:D6:4D", "1C:7E:E5",
     "28:10:7B", "34:08:04", "3C:1E:04", "5C:D9:98", "78:32:1B", "84:C9:B2",
     "90:94:E4", "AC:F1:DF", "B8:A3:86", "C4:A8:1D", "C8:BE:19", "CC:B2:55",
     "F0:7D:68", "FC:75:16")
_add("Zyxel", "network", "00:13:49", "00:19:CB", "00:1E:33", "00:23:F8",
     "04:BF:6D", "10:7B:EF", "28:28:5D", "40:4A:03", "5C:6A:80", "58:8B:F3",
     "90:EF:68", "B8:D5:26", "BC:CF:4F", "C8:6C:87", "D8:EC:E5", "EC:43:F6")
_add("MikroTik", "network", "00:0C:42", "18:FD:74", "2C:C8:1B", "48:8F:5A",
     "4C:5E:0C", "64:D1:54", "6C:3B:6B", "74:4D:28", "78:9A:18", "B8:69:F4",
     "C4:AD:34", "CC:2D:E0", "D4:01:C3", "DC:2C:6E", "E4:8D:8C", "F4:1E:57")
_add("Aruba Networks", "network", "00:0B:86", "00:1A:1E", "04:BD:88",
     "18:64:72", "20:4C:03", "24:DE:C6", "6C:F3:7F", "70:3A:0E", "84:D4:7E",
     "94:B4:0F", "9C:1C:12", "AC:A3:1E", "D8:C7:C8", "F0:5C:19")
_add("Juniper", "network", "00:05:85", "00:12:1E", "00:17:CB", "00:19:E2",
     "00:1D:B5", "00:23:9C", "2C:21:31", "3C:61:04", "54:E0:32", "5C:45:27",
     "78:19:F7", "84:18:88", "88:A2:5E", "C0:42:D0", "EC:13:DB", "F4:CC:55")
_add("Extreme Networks", "network", "00:04:96", "00:E0:2B", "5C:0E:8B",
     "B4:C7:99", "D8:84:66", "F0:AD:4E")
_add("Huawei", "network", "00:18:82", "00:1E:10", "00:25:9E", "00:34:FE",
     "04:BD:70", "08:19:A6", "0C:37:DC", "10:47:80", "18:C5:8A", "20:0B:C7",
     "24:69:A5", "28:31:52", "30:87:30", "34:6B:D3", "38:BC:01", "3C:47:11",
     "40:4D:8E", "48:46:FB", "4C:1F:CC", "54:39:DF", "5C:7D:5E", "60:DE:44",
     "70:72:3C", "78:1D:BA", "80:B6:86", "84:A8:E4", "88:53:D4", "8C:34:FD",
     "98:E7:F5", "A0:8D:16", "AC:E2:15", "B0:5B:67", "BC:76:70", "C0:70:09",
     "C8:D1:5E", "D0:16:B4", "D4:6A:A8", "E0:24:7F", "E4:68:A3", "F4:9F:F3",
     "FC:48:EF")
_add("Ruckus", "network", "00:13:92", "00:1D:2E", "00:24:82", "2C:C5:D3",
     "34:8F:27", "50:A7:33", "58:93:96", "6C:AA:B3", "8C:0C:90", "C0:8A:DE",
     "C4:01:7C", "EC:58:EA", "F0:3E:90")
_add("Sophos / Fortinet", "network", "00:09:0F", "00:0E:8E", "08:5B:0E",
     "70:4C:A5", "90:6C:AC", "E8:1C:BA")
_add("Vodafone / Arcadyan", "network", "00:12:BF", "00:22:3F", "1C:C6:3C",
     "38:70:0C", "44:4E:6D", "50:D4:F7", "84:9C:A6", "88:03:55", "94:7B:E7",
     "D0:D3:E0", "E0:19:1D")
_add("Technicolor / Thomson", "network", "00:0E:50", "00:14:7F", "00:1A:2A",
     "00:1F:9F", "00:24:17", "10:9F:A9", "30:91:8F", "44:32:C8", "58:23:8C",
     "7C:03:4C", "88:03:55", "A0:1B:29", "CC:03:FA", "F8:8E:85")
_add("Broadcom", "network", "00:05:B5", "00:0A:F7", "00:10:18", "00:1B:E9",
     "00:50:F1", "18:BF:1C", "44:D2:CA", "B0:EC:71")
_add("Realtek", None, "00:E0:4C", "52:54:AB", "00:20:18")

# --- Drucker / Scanner -------------------------------------------------------
_add("HP (Drucker)", "printer", "00:01:E6", "00:01:E7", "00:02:A5", "00:04:EA",
     "00:08:02", "00:0B:CD", "00:0F:61", "00:10:83", "00:11:0A", "00:11:85",
     "00:12:79", "00:13:21", "00:14:C2", "00:15:60", "00:16:35", "00:17:08",
     "00:18:71", "00:19:BB", "00:1A:4B", "00:1B:78", "00:1C:C4", "00:1E:0B",
     "00:1F:29", "00:21:5A", "00:22:64", "00:23:7D", "00:25:B3", "00:26:55",
     "10:60:4B", "18:60:24", "1C:C1:DE", "28:80:23", "2C:44:FD", "30:8D:99",
     "3C:52:82", "3C:D9:2B", "40:B0:34", "48:0F:CF", "5C:B9:01", "6C:3B:E5",
     "70:5A:0F", "78:48:59", "80:CE:62", "84:34:97", "8C:DC:D4", "94:57:A5",
     "9C:B6:54", "A0:48:1C", "A4:5D:36", "AC:16:2D", "B0:5C:DA", "B4:B5:2F",
     "C4:34:6B", "C8:D3:FF", "D0:BF:9C", "D4:C9:EF", "DC:4A:3E", "E4:11:5B",
     "E8:39:35", "EC:9A:74", "F4:03:43", "FC:3F:DB")
_add("Brother", "printer", "00:1B:A9", "00:22:58", "00:80:77", "30:05:5C",
     "3C:2A:F4", "44:D2:44", "60:6D:3C", "80:0A:80", "8C:53:C3", "B4:22:00",
     "B4:22:01", "D8:88:CE", "E4:AA:EA")
_add("Canon", "printer", "00:00:85", "00:1E:8F", "00:BB:C1", "18:0C:AC",
     "2C:9E:FC", "30:C9:AB", "3C:2A:F4", "40:7C:7D", "48:44:F7", "68:9A:B7",
     "88:87:17", "9C:69:B4", "A0:1E:0B", "C8:00:84", "D4:81:CA", "F4:81:39")
_add("Epson", "printer", "00:00:48", "00:26:AB", "08:00:37", "1C:6F:65",
     "24:60:44", "38:1A:52", "44:D2:44", "5C:F3:70", "64:EB:8C", "74:35:15",
     "80:00:0B", "9C:AE:D3", "A4:EE:57", "B0:E8:92", "C4:5B:BE", "D0:15:A6",
     "E8:9A:8F", "F8:D0:27")
_add("Kyocera", "printer", "00:00:99", "00:17:C8", "00:C0:EE", "6C:7B:9C",
     "94:D9:B3", "B0:B2:8F", "D4:7B:B0")
_add("Lexmark", "printer", "00:04:00", "00:20:00", "00:21:B7", "00:23:7A",
     "00:26:73", "18:60:24", "44:8A:5B", "58:40:4E", "6C:9C:ED", "70:9E:29",
     "E8:D4:E0")
_add("Ricoh", "printer", "00:00:74", "00:26:73", "58:38:79", "78:BD:BC",
     "84:2B:2B", "AC:44:F2", "C8:29:20")
_add("Xerox", "printer", "00:00:AA", "00:15:99", "00:1B:A9", "08:00:37",
     "9C:93:4E", "D4:56:36")
_add("Konica Minolta", "printer", "00:20:6B", "00:1B:E9", "3C:8C:F8",
     "60:DE:44", "AC:64:62")
_add("Sharp", "printer", "00:00:B0", "00:0D:F0", "00:22:6B", "08:00:1F",
     "3C:FA:06", "90:8D:6E", "B0:05:94")
_add("OKI", "printer", "00:80:87", "00:17:C8", "00:25:36", "60:D3:0A")
_add("Zebra", "printer", "00:07:4D", "00:15:70", "00:17:0D", "00:19:9C",
     "00:1F:F8", "00:22:58", "48:A4:93", "AC:3F:A4", "B4:22:00")
_add("Dymo / Seiko", "printer", "00:00:40", "00:1A:B6")

# --- IP-Telefonie ------------------------------------------------------------
_add("Snom", "phone", "00:04:13", "00:11:0F")
_add("Yealink", "phone", "00:15:65", "24:9A:D8", "58:56:E8", "80:5E:C0",
     "80:5E:0C", "9C:9D:7E")
_add("Grandstream", "phone", "00:0B:82", "C0:74:AD", "EC:74:D7")
_add("Polycom", "phone", "00:04:F2", "00:09:2D", "00:E0:DB", "38:56:B9",
     "48:25:67", "64:16:7F", "8C:35:C1")
_add("Gigaset", "phone", "00:01:E3", "00:1A:E8", "24:62:78", "3C:A6:F6",
     "7C:2F:80", "AC:9E:17")
_add("Mitel / Aastra", "phone", "00:08:5D", "00:10:BC", "08:00:0F", "50:38:B8")
_add("Avaya", "phone", "00:04:0D", "00:09:6E", "00:1B:4F", "00:24:00",
     "3C:B1:5B", "6C:FA:58", "B4:B0:17", "E4:5D:52")
_add("Unify / Siemens Enterprise", "phone", "00:01:E3", "00:0E:A6", "08:00:06")
_add("Fanvil", "phone", "00:1F:E1", "0C:38:3E")
_add("Sangoma / Digium", "phone", "00:12:1E", "00:50:56")

# --- Kameras / Sicherheit ----------------------------------------------------
_add("Axis", "camera", "00:40:8C", "AC:CC:8E", "B8:A4:4F", "E8:27:25")
_add("Hikvision", "camera", "00:0F:7C", "00:40:48", "08:A1:89", "18:68:CB",
     "1C:1B:68", "28:57:BE", "24:0F:9B", "2C:A5:9C", "44:19:B6", "4C:BD:8F",
     "54:C4:15", "58:03:FB", "68:6D:BC", "8C:E7:48", "A4:14:37", "B4:A3:82",
     "BC:9B:5E", "C0:56:E3", "C4:2F:90", "D4:E8:B2", "E0:BA:AD", "F8:4D:FC")
_add("Dahua", "camera", "00:12:16", "08:ED:ED", "14:A7:8B", "24:52:6A",
     "3C:EF:8C", "38:AF:29", "4C:11:BF", "50:9B:12", "6C:1C:71", "90:02:A9",
     "9C:14:63", "A0:BD:1D", "B4:4C:3B", "BC:32:5F", "E0:50:8B", "FC:5F:49")
_add("Mobotix", "camera", "00:03:C5")
_add("Reolink", "camera", "EC:71:DB", "9C:8E:CD", "A0:04:60")
_add("Arlo", "camera", "00:62:6E", "3C:37:86", "74:2F:68")
_add("Ring", "camera", "0C:47:C9", "34:3E:A4", "54:E0:19", "B0:7D:47",
     "F0:B3:EC")
_add("Nest / Google Nest", "camera", "18:B4:30", "64:16:66", "A4:77:33",
     "D8:EB:46")
_add("Ubiquiti UniFi Protect", "camera", "78:8A:20", "B4:FB:E4", "FC:EC:DA")

# --- NAS / Storage -----------------------------------------------------------
_add("Synology", "nas", "00:11:32", "90:09:D0")
_add("QNAP", "nas", "00:08:9B", "24:5E:BE", "00:13:D4")
_add("Western Digital", "nas", "00:00:C0", "00:14:EE", "00:90:A9", "58:9C:FC",
     "9C:8E:99")
_add("Buffalo", "nas", "00:0D:0B", "00:16:01", "00:1D:73", "00:24:A5",
     "10:6F:3F", "4C:E6:76", "DC:FB:02")
_add("Netgear ReadyNAS", "nas", "00:0F:B5", "A0:63:91")
_add("TrueNAS / iXsystems", "nas", "00:25:90", "0C:C4:7A")

# --- Media / TV / Audio ------------------------------------------------------
_add("Sonos", "media", "00:0E:58", "34:7E:5C", "38:42:0B", "48:A6:B8",
     "5C:AA:FD", "78:28:CA", "94:9F:3E", "B8:E9:37", "F0:F6:C1")
_add("Samsung", "media", "00:07:AB", "00:12:FB", "00:15:B9", "00:16:32",
     "00:17:C9", "00:1A:8A", "00:1D:25", "00:1E:7D", "00:21:19", "00:23:39",
     "00:24:54", "00:26:37", "04:18:0F", "08:08:C2", "0C:14:20", "10:1D:C0",
     "14:49:E0", "18:3F:47", "1C:62:B8", "20:13:E0", "24:4B:03", "28:39:5E",
     "2C:44:01", "30:19:66", "34:23:BA", "38:0A:94", "3C:8B:FE", "40:0E:85",
     "44:78:3E", "48:44:F7", "4C:3C:16", "50:32:75", "54:88:0E", "5C:0A:5B",
     "60:6B:BD", "64:1C:B0", "68:27:37", "6C:2F:2C", "70:F9:27", "78:1F:DB",
     "7C:61:66", "80:57:19", "84:25:DB", "88:32:9B", "8C:71:F8", "90:18:7C",
     "94:35:0A", "98:83:89", "9C:02:98", "A0:07:98", "A4:EB:D3", "A8:F2:74",
     "AC:5F:3E", "B0:72:BF", "B4:79:A7", "B8:5A:73", "BC:14:85", "C0:65:99",
     "C4:57:6E", "C8:A8:23", "CC:07:AB", "D0:22:BE", "D4:87:D8", "D8:57:EF",
     "DC:71:96", "E4:12:1D", "E8:50:8B", "EC:1F:72", "F0:5A:09", "F4:7B:5E",
     "F8:04:2E", "FC:00:12")
_add("LG Electronics", "media", "00:1C:62", "00:1E:75", "00:1F:6B", "00:22:A9",
     "00:24:83", "00:26:E2", "00:E0:91", "10:68:3F", "2C:54:CF", "34:FC:EF",
     "38:8C:50", "3C:CD:93", "58:A2:B5", "5C:70:A3", "60:E3:AC", "6C:DD:BC",
     "70:05:14", "74:A7:22", "88:36:6C", "98:93:CC", "A0:39:F7", "A8:16:D0",
     "B4:0E:DC", "C4:36:6C", "CC:2D:8C", "E8:5B:5B", "F8:0C:F3")
_add("Sony", "media", "00:01:4A", "00:04:1F", "00:13:15", "00:19:63",
     "00:1A:80", "00:1D:BA", "00:24:BE", "04:5D:4B", "18:00:2D", "30:F9:ED",
     "3C:07:71", "54:42:49", "78:84:3C", "8C:B8:4A", "94:CE:2C", "AC:9B:0A",
     "D8:D4:3C", "FC:0F:E6")
_add("Panasonic", "media", "00:0B:97", "00:13:49", "00:80:45", "08:00:23",
     "20:C6:EB", "34:76:C5", "48:A9:D2", "80:C7:55", "A4:12:32", "C0:D9:62")
_add("Philips", "media", "00:1F:47", "00:26:5E", "24:76:7D", "70:AF:24",
     "9C:A5:25", "B0:F8:93", "D0:CF:5E", "F0:D1:A9")
_add("Philips Hue", "iot", "00:17:88", "EC:B5:FA")
_add("Roku", "media", "00:0D:4B", "08:05:81", "10:59:32", "20:EF:BD",
     "88:DE:A9", "AC:3A:7A", "B0:A7:37", "B8:3E:59", "CC:6D:A0", "D0:4D:2C",
     "D8:31:34", "DC:3A:5E")
_add("Amazon (Echo/Fire)", "media", "00:BB:3A", "0C:47:C9", "10:AE:60",
     "18:74:2E", "34:D2:70", "38:F7:3D", "40:B4:CD", "44:65:0D", "4C:EF:C0",
     "50:DC:E7", "68:37:E9", "68:54:FD", "6C:56:97", "74:75:48", "74:C2:46",
     "78:E1:03", "88:71:E5", "A0:02:DC", "AC:63:BE", "B4:7C:9C", "F0:27:2D",
     "F0:81:73", "FC:65:DE", "FC:A1:83")
_add("Google / Chromecast", "media", "00:1A:11", "08:9E:08", "1C:F2:9A",
     "20:DF:B9", "30:FD:38", "38:8B:59", "3C:28:6D", "44:07:0B", "48:D6:D5",
     "54:60:09", "58:CB:52", "6C:AD:F8", "70:3A:CB", "94:EB:2C", "A4:77:33",
     "D8:6C:63", "DA:A1:19", "F4:F5:D8", "F4:F5:E8", "F8:8F:CA")
_add("Apple TV / HomePod", "media", "7C:D1:C3", "D4:90:9C", "F0:D1:A9")
_add("Bose", "media", "04:A3:16", "08:DF:1F", "18:1D:EA", "2C:9F:FB",
     "38:18:4C", "60:AB:D5", "70:99:1C", "88:4A:EA", "9C:D3:5B", "C8:7F:54")
_add("Denon / Marantz", "media", "00:05:CD", "00:06:78", "00:1E:DF")
_add("Yamaha", "media", "00:A0:DE", "04:B4:22", "08:36:C9", "AC:44:F2")
_add("Loewe", "media", "00:09:A4", "9C:31:B6")
_add("TechniSat", "media", "00:1F:A7", "40:2C:76")
_add("Vestel / Telefunken", "media", "00:1A:D0", "44:E1:37", "B0:F1:A3")
_add("Hisense", "media", "00:1E:C0", "38:AB:41", "44:6D:57", "C4:9D:ED")
_add("TCL", "media", "00:1E:8C", "38:C1:2E", "6C:21:A2", "AC:14:D2")

# --- Spielkonsolen -----------------------------------------------------------
_add("Nintendo", "console", "00:09:BF", "00:16:56", "00:17:AB", "00:19:1D",
     "00:1A:E9", "00:1B:7A", "00:1B:EA", "00:1C:BE", "00:1D:BC", "00:1E:35",
     "00:1E:A9", "00:1F:32", "00:21:47", "00:22:4C", "00:22:AA", "00:23:31",
     "00:23:CC", "00:24:1E", "00:24:44", "00:24:F3", "00:25:A0", "00:26:59",
     "04:03:D6", "18:2A:7B", "2C:10:C1", "34:AF:2C", "40:D2:8A", "58:BD:A3",
     "64:B5:C6", "78:A2:A0", "8C:CD:E8", "98:B6:E9", "9C:E6:35", "A4:5C:27",
     "B8:8A:EC", "CC:9E:00", "E0:E7:51", "E8:4E:CE")
_add("Sony PlayStation", "console", "00:04:1F", "00:13:15", "00:15:C1",
     "00:19:C5", "00:1D:0D", "00:24:8D", "0C:FE:45", "28:0D:FC", "2C:CC:44",
     "5C:96:56", "70:9E:29", "78:C8:81", "A8:E3:EE", "BC:60:A7", "C8:63:F1",
     "D4:4B:5E", "F8:46:1C", "FC:0F:E6")
_add("Microsoft Xbox", "console", "00:0D:3A", "00:12:5A", "00:17:FA",
     "00:1D:D8", "00:22:48", "00:50:F2", "28:18:78", "30:59:B7", "58:82:A8",
     "60:45:BD", "7C:1E:52", "98:5F:D3", "C8:3F:26", "DC:98:40")
_add("Valve (Steam)", "console", "F8:5D:9F")

# --- Mobilgeräte ------------------------------------------------------------
_add("Xiaomi", "mobile", "00:9E:C8", "04:CF:8C", "0C:1D:AF", "10:2A:B3",
     "14:F6:5A", "18:59:36", "20:82:C0", "28:6C:07", "2C:F0:A2", "34:80:B3",
     "38:A4:ED", "3C:BD:3E", "44:23:7C", "50:64:2B", "50:8F:4C", "58:44:98",
     "64:09:80", "64:B4:73", "68:DF:DD", "6C:FA:A7", "74:23:44", "78:02:F8",
     "7C:1D:D9", "8C:BE:BE", "98:FA:E3", "9C:99:A0", "A0:86:C6", "AC:C1:EE",
     "B0:E2:35", "C4:0B:CB", "D4:97:0B", "E8:AB:FA", "F0:B4:29", "F8:A4:5F")
_add("OnePlus", "mobile", "94:65:2D", "AC:37:43", "C0:EE:FB", "C4:7C:8D",
     "64:A2:F9")
_add("Oppo / Realme", "mobile", "04:B1:67", "1C:15:1F", "2C:5B:B8", "30:74:96",
     "44:D7:91", "68:6E:F7", "84:D8:1B", "94:E9:79", "C0:EE:FB", "D0:C0:BF")
_add("Motorola", "mobile", "00:0A:28", "00:12:8A", "00:23:76", "14:9A:10",
     "24:DA:9B", "40:78:6A", "5C:51:88", "60:BE:B5", "84:10:0D", "98:7E:46",
     "CC:C3:EA", "E0:75:7D", "F8:E0:79")
_add("Nokia / HMD", "mobile", "00:02:EE", "00:0E:ED", "00:19:4F", "00:1F:5D",
     "18:87:96", "34:7E:39", "3C:BB:FD", "54:79:75", "9C:2A:70", "D4:97:0B")
_add("Google Pixel", "mobile", "00:1A:11", "3C:5A:B4", "58:CB:52", "64:16:66",
     "84:C5:A6", "94:EB:2C", "A4:50:46", "D8:6C:63", "F4:F5:D8")
_add("Garmin", "iot", "00:00:9D", "00:19:FE", "10:C6:FC", "88:34:9C")
_add("Fitbit", "iot", "78:C5:E5", "D0:C5:F3", "E0:F5:C6")

# --- IoT / Smart Home --------------------------------------------------------
_add("Espressif (ESP32/ESP8266)", "iot", "24:0A:C4", "24:6F:28", "24:B2:DE",
     "2C:3A:E8", "30:AE:A4", "34:94:54", "3C:61:05", "3C:71:BF", "40:F5:20",
     "44:17:93", "48:3F:DA", "4C:11:AE", "54:5A:A6", "58:BF:25", "5C:CF:7F",
     "60:01:94", "68:C6:3A", "70:03:9F", "7C:9E:BD", "7C:DF:A1", "80:7D:3A",
     "84:0D:8E", "84:CC:A8", "84:F3:EB", "88:13:BF", "8C:AA:B5", "90:38:0C",
     "94:B5:55", "94:B9:7E", "98:CD:AC", "98:F4:AB", "9C:9C:1F", "A0:20:A6",
     "A4:7B:9D", "A4:CF:12", "A8:03:2A", "AC:0B:FB", "AC:67:B2", "B4:E6:2D",
     "BC:DD:C2", "C4:4F:33", "C8:2B:96", "C8:C9:A3", "CC:50:E3", "D8:A0:1D",
     "D8:BF:C0", "DC:4F:22", "E0:98:06", "E8:31:CD", "E8:DB:84", "EC:64:C9",
     "EC:FA:BC", "F0:08:D1", "F4:CF:A2", "FC:F5:C4")
_add("Tuya / Smart Life", "iot", "10:5A:17", "18:69:D8", "1C:90:FF", "2C:F4:32",
     "40:F5:20", "50:02:91", "50:8A:06", "68:57:2D", "70:89:76", "84:E3:42",
     "A4:C1:38", "B4:E6:2A", "CC:8C:BF", "D4:A6:51", "DC:4F:22", "EC:1B:BD")
_add("Shelly / Allterco", "iot", "24:4C:AB", "3C:61:05", "44:17:93", "98:CD:AC",
     "B0:B2:1C", "C4:5B:BE", "E8:DB:84")
_add("Sonoff / Itead", "iot", "2C:F4:32", "60:01:94", "68:C6:3A", "CC:50:E3",
     "D8:F1:5B", "DC:4F:22")
_add("Raspberry Pi", "computer", "28:CD:C1", "2C:CF:67", "B8:27:EB",
     "D8:3A:DD", "DC:A6:32", "E4:5F:01")
_add("Arduino", "iot", "90:A2:DA", "A8:61:0A")
_add("Netatmo", "iot", "70:EE:50")
_add("Devolo", "network", "00:0B:3B", "00:22:F7", "B0:48:1A")
_add("AVM Powerline", "network", "3C:A6:2F", "E0:28:6D")
_add("Bosch", "iot", "00:04:0E", "70:B3:D5", "C8:A3:0D")
_add("Miele", "iot", "00:13:3B", "88:6B:0F")
_add("Siemens", "industrial", "00:0E:8C", "00:1B:1B", "00:1C:06", "00:1F:F8",
     "08:00:06", "20:87:56", "28:63:36", "8C:F3:19", "E0:DC:A0")
_add("Beckhoff", "industrial", "00:01:05", "00:60:52")
_add("WAGO", "industrial", "00:30:DE")
_add("Phoenix Contact", "industrial", "00:A0:45", "A8:74:1D")
_add("Rockwell / Allen-Bradley", "industrial", "00:00:BC", "00:1D:9C",
     "5C:88:16", "E4:90:69")
_add("Schneider Electric", "industrial", "00:00:54", "00:80:F4", "00:B0:0D",
     "84:26:2B")
_add("APC / Schneider USV", "industrial", "00:C0:B7", "28:29:86", "3C:61:04")
_add("Eaton", "industrial", "00:20:85", "00:22:19", "F4:B7:E2")
_add("Tesla", "iot", "4C:FC:AA", "54:F8:F0", "98:ED:5C", "CC:88:26")
_add("Keba / Wallbox", "iot", "00:20:4A", "00:60:35")

_MAX_PREFIX_LEN = 8  # "AA:BB:CC"

# Zusätzliche Datenbanken, die zur Laufzeit geladen werden (IEEE/Wireshark)
_EXTRA_OUI: Dict[str, Tuple[str, Optional[str]]] = {}


def cache_dir() -> str:
    """Plattformgerechter Ort für die heruntergeladene OUI-Datenbank."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "scanip")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/scanip")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "scanip")


OUI_CACHE_FILE = os.path.join(cache_dir(), "oui.csv")

WIRESHARK_MANUF_PATHS = [
    "/usr/share/wireshark/manuf",
    "/usr/local/share/wireshark/manuf",
    "/opt/homebrew/share/wireshark/manuf",
    "/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf",
    r"C:\Program Files\Wireshark\manuf",
]


def _load_ieee_csv(path: str) -> int:
    """Laedt die offizielle IEEE-CSV (Registry,Assignment,Organization Name,...)."""
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.reader(handle):
                if len(row) < 3 or len(row[1]) < 6:
                    continue
                assignment = row[1].strip().upper()
                if not re.fullmatch(r"[0-9A-F]{6}", assignment):
                    continue
                prefix = ":".join(assignment[i:i + 2] for i in (0, 2, 4))
                vendor = row[2].strip()
                if vendor:
                    _EXTRA_OUI.setdefault(prefix, (vendor, None))
                    count += 1
    except OSError:
        return 0
    return count


def _load_manuf(path: str) -> int:
    """Laedt die 'manuf'-Datei von Wireshark."""
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                fields = line.split("\t")
                fields = [f for f in fields if f.strip()]
                if len(fields) < 2:
                    fields = line.split(None, 2)
                if len(fields) < 2:
                    continue
                prefix = fields[0].strip().upper().replace("-", ":")
                if "/" in prefix:                     # längere Präfixe ignorieren
                    continue
                if len(prefix) != 8:
                    continue
                vendor = fields[-1].strip() if len(fields) > 2 else fields[1].strip()
                if vendor:
                    _EXTRA_OUI.setdefault(prefix, (vendor, None))
                    count += 1
    except OSError:
        return 0
    return count


def load_external(path: Optional[str] = None) -> int:
    """Laedt eine zusätzliche OUI-Quelle. Liefert die Zahl der Einträge."""
    candidates = [path] if path else [OUI_CACHE_FILE] + WIRESHARK_MANUF_PATHS
    total = 0
    for candidate in candidates:
        if not candidate or not os.path.isfile(candidate):
            continue
        loaded = (_load_ieee_csv(candidate) if candidate.lower().endswith(".csv")
                  else _load_manuf(candidate))
        total += loaded
        if loaded:
            break
    return total


def update_from_ieee(url: str = "https://standards-oui.ieee.org/oui/oui.csv",
                     timeout: float = 60.0) -> Tuple[bool, str]:
    """Laedt die vollstaendige IEEE-Datenbank in den Cache (nur auf Zuruf)."""
    import urllib.request

    os.makedirs(cache_dir(), exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = response.read()
    except Exception as exc:                                  # noqa: BLE001
        return False, "Download fehlgeschlagen: %s" % exc
    if len(data) < 100000:
        return False, "Unerwartet kleine Datei (%d Bytes) - Abbruch." % len(data)
    tmp = OUI_CACHE_FILE + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
    os.replace(tmp, OUI_CACHE_FILE)
    count = _load_ieee_csv(OUI_CACHE_FILE)
    return True, "%d Hersteller-Präfixe gespeichert in %s" % (count, OUI_CACHE_FILE)


def is_locally_administered(mac: str) -> bool:
    """True bei zufälliger/privater MAC (iOS/Android Privacy-Feature)."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def lookup(mac: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """MAC -> (Hersteller, Kategorie-Hinweis)."""
    if not mac:
        return None, None
    prefix = mac.upper()[:_MAX_PREFIX_LEN]
    if prefix in BUILTIN_OUI:
        return BUILTIN_OUI[prefix]
    if prefix in _EXTRA_OUI:
        return _EXTRA_OUI[prefix]
    if is_locally_administered(mac):
        return "zufällige MAC (Privatsphäre)", None
    return None, None


def vendor(mac: Optional[str]) -> Optional[str]:
    return lookup(mac)[0]
