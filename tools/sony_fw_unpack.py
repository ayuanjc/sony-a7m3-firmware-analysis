#!/usr/bin/env python3
"""
Sony Packman SFX + UFU container structure parser.

Parses Update_ILCE7M3V404.exe (Sony Alpha 7 III system software updater):
    PE overlay -> Packman entry table -> embedded .cab (byte-inverted MSCF)
               -> FirmwareData_*.dat UFU container (magic + TLV chain)

This script only PARSES STRUCTURE. It performs no decryption, no signature
handling, and never talks to any device.

Requires: Python 3.9+, 7-Zip (optional, only to unpack the inner cab).
Usage:    python sony_fw_unpack.py <path to Update_ILCE7M3V404.exe>
"""

import os
import sys
import struct
import zlib
import tempfile
import subprocess

UFU_MAGIC = b"\x89UFU\r\n\x1a\n"
INV_MSCF = bytes(b ^ 0xFF for b in b"MSCF")   # b"\xb2\xac\xbc\xb9"

SEVENZIP_CANDIDATES = [
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files (x86)\7-Zip\7z.exe",
    "/usr/bin/7z",
    "/usr/local/bin/7z",
]


def find_sevenzip():
    for p in SEVENZIP_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def find_packman(data):
    """Packman root entry name -> start of the entry table."""
    needle = "!!!53AAED7C-68E7-413C-A5FD-D9F76477D66A".encode("utf-16-le")
    i = data.find(needle)
    if i < 0:
        raise SystemExit("Packman root entry not found; wrong sample?")
    return max(0, i - 0x52)


def extract_cab(data, hint=0x70000, window=0x40000):
    """Locate the byte-inverted MSCF cab in the overlay and un-invert it."""
    end = min(len(data) - 64, hint + window)
    off = data.find(INV_MSCF, hint, end)
    if off < 0:
        raise SystemExit("inverted MSCF cab not found in overlay")
    head = bytes(b ^ 0xFF for b in data[off:off + 64])
    cb = struct.unpack_from("<I", head, 8)[0]
    if cb <= 0 or off + cb > len(data):
        raise SystemExit("bad cbCabinet value: %d" % cb)
    return off, bytes(b ^ 0xFF for b in data[off:off + cb]), cb


def parse_ufu(data):
    if data[:8] != UFU_MAGIC:
        raise SystemExit("not a UFU container")
    off, chunks = 8, []
    while off + 8 <= len(data):
        ln = struct.unpack_from(">I", data, off)[0]
        tag = data[off + 4:off + 8].decode("latin1", "replace")
        chunks.append({"off": off, "len": ln, "tag": tag,
                       "payload": off + 8, "end": off + 8 + ln})
        off += 8 + ln
        if tag == "DEND":
            break
    return chunks, off


def report(exe_path):
    raw = open(exe_path, "rb").read()
    print("input          : %s (%d bytes)" % (os.path.basename(exe_path), len(raw)))

    print("packman table  : 0x%x" % find_packman(raw))
    cab_off, cab, cb = extract_cab(raw)
    print("inner cab      : 0x%x..0x%x  cbCabinet=%d (byte-inverted MSCF)"
          % (cab_off, cab_off + cb, cb))
    print("cab header     : version=%d.%d folders=%d files=%d"
          % (cab[25], cab[24],
             struct.unpack_from("<H", cab, 26)[0],
             struct.unpack_from("<H", cab, 28)[0]))
    print("trailing sig   : %d bytes after cab" % (len(raw) - (cab_off + cb)))

    out = tempfile.mkdtemp(prefix="packman_")
    cabfile = os.path.join(out, "payload.cab")
    open(cabfile, "wb").write(cab)

    sz = find_sevenzip()
    if not sz:
        print("\n7-Zip not found. Cab written to: %s" % cabfile)
        return
    subprocess.run([sz, "x", cabfile, "-o" + out, "-y"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    dats = [f for f in os.listdir(out)
            if f.startswith("FirmwareData") and f.endswith(".dat")]
    if not dats:
        print("no FirmwareData*.dat inside the cab")
        return

    fw = open(os.path.join(out, dats[0]), "rb").read()
    print("\n=== %s (%d bytes) ===" % (dats[0], len(fw)))
    chunks, end = parse_ufu(fw)
    for c in chunks:
        print("  %-5s @0x%-10x len=%-11d payload 0x%x..0x%x"
              % (c["tag"], c["off"], c["len"], c["payload"], c["end"]))
    print("  chain end 0x%x / file 0x%x (slack %d)" % (end, len(fw), len(fw) - end))

    dend = chunks[-1]
    if dend["tag"] == "DEND":
        stored = struct.unpack_from(">I", fw, dend["payload"])[0]
        calc = zlib.crc32(fw[:dend["off"]]) & 0xFFFFFFFF
        print("  DEND CRC32 : stored=0x%08X calculated=0x%08X -> %s"
              % (stored, calc, "MATCH" if stored == calc else "MISMATCH"))

    for c in chunks:
        if c["tag"] == "UDID":
            u = fw[c["payload"]:c["end"]]
            cnt = struct.unpack_from(">I", u, 0)[0]
            print("  UDID       : %d entries" % cnt)
            print("    idx  modelCode  usbVid  usbPid  flags")
            for k in range(cnt):
                mc, vid, pid, fl = struct.unpack_from(">HHHH", u, 4 + k * 8)
                print("    [%2d]   0x%04X   0x%04X  0x%04X  0x%04X" % (k, mc, vid, pid, fl))
        elif c["tag"] == "FDAT":
            pay = fw[c["payload"]:c["end"]]
            seen, dups = set(), 0
            for i in range(0, len(pay) - 15, 16):
                b = pay[i:i + 16]
                if b in seen:
                    dups += 1
                else:
                    seen.add(b)
            print("  FDAT       : %d bytes (%d x 16B), duplicate blocks=%d"
                  % (len(pay), len(pay) // 16, dups))
            print("               structure only; payload is encrypted and not decrypted here")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    report(sys.argv[1])
