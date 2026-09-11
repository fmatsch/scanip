"""Erzeugt das Programmsymbol - ohne Bildbibliothek, nur Standardbibliothek.

Zeichnet ein Radar-Motiv (konzentrische Ringe mit Geräte-Punkten) auf ein
abgerundetes Quadrat und schreibt PNG, ICNS (macOS) und ICO (Windows).

    python3 tools/make_icon.py [Zielordner]
"""

from __future__ import annotations

import math
import os
import struct
import subprocess
import sys
import zlib
from typing import List, Tuple

# Farben (R, G, B)
BG_TOP = (30, 58, 95)
BG_BOTTOM = (16, 28, 48)
RING = (110, 190, 255)
DOT = (120, 230, 180)
SWEEP = (70, 150, 230)

SUPERSAMPLE = 3            # gegen Treppenstufen: intern 3x zeichnen, dann mitteln


def _mix(a: Tuple[int, int, int], b: Tuple[int, int, int],
         t: float) -> Tuple[int, int, int]:
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def _rounded_square(x: float, y: float, size: float, radius: float) -> bool:
    """Liegt der Punkt innerhalb eines abgerundeten Quadrats?"""
    cx = min(max(x, radius), size - radius)
    cy = min(max(y, radius), size - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2


def render_rgba(size: int) -> bytearray:
    """Zeichnet das Symbol und liefert RGBA-Bilddaten."""
    scale = SUPERSAMPLE
    big = size * scale
    radius = big * 0.22
    centre = big / 2.0
    pixels = bytearray(big * big * 4)

    # Ringe: (Radius-Anteil, Strichstärke-Anteil)
    rings = [(0.19, 0.030), (0.31, 0.028), (0.43, 0.026)]
    # Geräte-Punkte: (Winkel in Grad, Radius-Anteil, Größe-Anteil)
    dots = [(35, 0.19, 0.045), (150, 0.31, 0.050), (265, 0.43, 0.045),
            (310, 0.19, 0.038)]

    for py in range(big):
        for px in range(big):
            offset = (py * big + px) * 4
            fx, fy = px + 0.5, py + 0.5
            if not _rounded_square(fx, fy, big, radius):
                continue                                    # außerhalb: transparent

            colour = _mix(BG_TOP, BG_BOTTOM, fy / big)
            dx, dy = fx - centre, fy - centre
            distance = math.hypot(dx, dy) / big
            angle = math.degrees(math.atan2(dy, dx)) % 360

            # Radarkeil als dezente Aufhellung
            delta = (angle - 300) % 360
            if delta > 300:
                colour = _mix(colour, SWEEP, 0.30 * (delta - 300) / 60.0)

            for ring_radius, width in rings:
                if abs(distance - ring_radius) < width:
                    strength = 1.0 - abs(distance - ring_radius) / width
                    colour = _mix(colour, RING, 0.85 * strength)

            if distance < 0.045:                            # Mittelpunkt
                colour = _mix(colour, RING, 1.0)

            for dot_angle, dot_radius, dot_size in dots:
                ax = centre + math.cos(math.radians(dot_angle)) * dot_radius * big
                ay = centre + math.sin(math.radians(dot_angle)) * dot_radius * big
                d = math.hypot(fx - ax, fy - ay) / big
                if d < dot_size:
                    colour = _mix(colour, DOT, min(1.0, (1.0 - d / dot_size) * 1.6))

            pixels[offset:offset + 4] = bytes(colour) + b"\xff"

    return _downsample(pixels, big, scale)


def _downsample(pixels: bytearray, big: int, scale: int) -> bytearray:
    """Mittelt scale x scale Blöcke - erzeugt weiche Kanten."""
    size = big // scale
    out = bytearray(size * size * 4)
    count = scale * scale
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0
            for sy in range(scale):
                row = (y * scale + sy) * big
                for sx in range(scale):
                    o = (row + x * scale + sx) * 4
                    alpha = pixels[o + 3]
                    r += pixels[o] * alpha
                    g += pixels[o + 1] * alpha
                    b += pixels[o + 2] * alpha
                    a += alpha
            target = (y * size + x) * 4
            if a:
                out[target:target + 4] = bytes((r // a, g // a, b // a, a // count))
            # sonst bleibt der Pixel transparent
    return out


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def encode_png(rgba: bytearray, size: int) -> bytes:
    """Minimaler PNG-Encoder (RGBA, Filtertyp 0)."""
    raw = bytearray()
    stride = size * 4
    for y in range(size):
        raw.append(0)
        raw += rgba[y * stride:(y + 1) * stride]
    return (b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + _png_chunk(b"IEND", b""))


def encode_ico(pngs: List[Tuple[int, bytes]]) -> bytes:
    """ICO mit eingebetteten PNGs (Windows Vista und neuer)."""
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries, blobs = b"", b""
    for size, data in pngs:
        dimension = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32,
                               len(data), offset)
        blobs += data
        offset += len(data)
    return header + entries + blobs


def build(target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    sizes = [16, 32, 64, 128, 256, 512]
    rendered = {}
    for size in sizes:
        sys.stderr.write("  zeichne %dx%d ...\n" % (size, size))
        rendered[size] = encode_png(render_rgba(size), size)

    png_path = os.path.join(target_dir, "icon.png")
    with open(png_path, "wb") as handle:
        handle.write(rendered[512])
    print("PNG  : %s" % png_path)

    ico_path = os.path.join(target_dir, "scanip.ico")
    with open(ico_path, "wb") as handle:
        handle.write(encode_ico([(s, rendered[s]) for s in (16, 32, 64, 128, 256)]))
    print("ICO  : %s" % ico_path)

    if sys.platform == "darwin":
        iconset = os.path.join(target_dir, "scanip.iconset")
        os.makedirs(iconset, exist_ok=True)
        naming = {16: ["icon_16x16.png"], 32: ["icon_16x16@2x.png", "icon_32x32.png"],
                  64: ["icon_32x32@2x.png"], 128: ["icon_128x128.png"],
                  256: ["icon_128x128@2x.png", "icon_256x256.png"],
                  512: ["icon_256x256@2x.png", "icon_512x512.png"]}
        for size, names in naming.items():
            for name in names:
                with open(os.path.join(iconset, name), "wb") as handle:
                    handle.write(rendered[size])
        icns_path = os.path.join(target_dir, "scanip.icns")
        try:
            subprocess.run(["iconutil", "-c", "icns", iconset, "-o", icns_path],
                           check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            print("ICNS : %s" % icns_path)
        except (OSError, subprocess.CalledProcessError):
            print("ICNS : übersprungen (iconutil nicht verfügbar)")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "assets")
