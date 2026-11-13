"""Tiny OLE/CFB (v3) writer used only by tests to build synthetic Outlook .msg files."""
from __future__ import annotations

import math
import struct

SS, MSS, CUTOFF = 512, 64, 4096
END, FREE, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


def write_cfb(entries: dict) -> bytes:
    dirs = [{"name": "Root Entry", "type": 5, "children": []}]

    def add(name, val, parent):
        idx = len(dirs)
        if isinstance(val, dict):
            e = {"name": name, "type": 1, "children": []}
            dirs.append(e)
            parent["children"].append(idx)
            for k, v in val.items():
                add(k, v, e)
        else:
            dirs.append({"name": name, "type": 2, "data": val, "children": []})
            parent["children"].append(idx)

    for k, v in entries.items():
        add(k, v, dirs[0])
    for e in dirs:
        e.update(left=NOSTREAM, right=NOSTREAM, child=NOSTREAM, start=END, size=0)
    for e in dirs:
        ch = e["children"]
        if ch:
            e["child"] = ch[0]
            for a, b in zip(ch, ch[1:]):
                dirs[a]["right"] = b

    mini, minifat, big = bytearray(), [], []
    for e in dirs:
        if e["type"] != 2:
            continue
        d = e["data"]
        e["size"] = len(d)
        if len(d) < CUTOFF:
            n = math.ceil(len(d) / MSS)
            if n:
                start = len(mini) // MSS
                e["start"] = start
                mini += d + b"\0" * (n * MSS - len(d))
                minifat += [start + k + 1 for k in range(n - 1)] + [END]
        else:
            big.append(e)

    def nsec(nbytes):
        return math.ceil(nbytes / SS)

    blocks = [("dir", nsec(len(dirs) * 128)), ("minifat", nsec(len(minifat) * 4)), ("mini", nsec(len(mini)))]
    blocks += [(id(e), nsec(e["size"])) for e in big]
    other = sum(n for _, n in blocks)
    f = 1
    while f * (SS // 4) < f + other:
        f += 1
    fat = [FATSECT] * f
    starts = {}
    cur = f
    for key, n in blocks:
        if n == 0:
            starts[key] = END
            continue
        starts[key] = cur
        fat += [cur + k + 1 for k in range(n - 1)] + [END]
        cur += n
    fat += [FREE] * (f * (SS // 4) - len(fat))
    for e in big:
        e["start"] = starts[id(e)]
    dirs[0]["start"] = starts["mini"]
    dirs[0]["size"] = len(mini)

    def pad(b, n):
        return bytes(b) + b"\0" * (n * SS - len(b))

    dir_bytes = bytearray()
    for e in dirs:
        nm = (e["name"] + "\0").encode("utf-16-le")
        dir_bytes += nm.ljust(64, b"\0") + struct.pack("<HBBIII", len(nm), e["type"], 1, e["left"], e["right"], e["child"])
        dir_bytes += b"\0" * 16 + b"\0" * 4 + b"\0" * 16 + struct.pack("<IQ", e["start"], e["size"])
    dir_bytes += b"\0" * (nsec(len(dir_bytes)) * SS - len(dir_bytes))
    mf = struct.pack(f"<{len(minifat)}I", *minifat) if minifat else b""

    header = bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16)
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
    header += struct.pack("<IIIIIIIII", 0, f, starts["dir"], 0, CUTOFF, starts["minifat"], len(minifat) and nsec(len(mf)), END, 0)
    difat = list(range(f)) + [FREE] * (109 - f)
    header += struct.pack("<109I", *difat)
    assert len(header) == 512
    body = struct.pack(f"<{len(fat)}I", *fat)
    body += dir_bytes
    if mf:
        body += pad(mf, nsec(len(mf)))
    if mini:
        body += pad(mini, nsec(len(mini)))
    for e in big:
        body += pad(e["data"], nsec(e["size"]))
    return bytes(header) + body


def utf16(s: str) -> bytes:
    return s.encode("utf-16-le")
