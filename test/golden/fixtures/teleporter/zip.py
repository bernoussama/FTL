#!/usr/bin/env python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# Helper for the teleporter golden cases. Run as: python3 -I zip.py COMMAND ...
#
#   make OUT [--declare NAME=SIZE] NAME=SRC...  ZIP of the files SRC, stored as NAME
#                                               in the order given, fixed timestamps.
#                                               --declare overwrites the uncompressed
#                                               size of NAME in its headers.
#   list ARCHIVE                                one line per entry: name, method,
#                                               uncompressed size, comment; then testzip
#   extract ARCHIVE NAME OUT                    write the member NAME to OUT
#   noise SIZE SEED                             SIZE deterministic pseudo-random bytes
#                                               to stdout
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

import struct
import sys
import zipfile

FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def make(out, args):
    declared = {}
    pairs = []
    i = 0
    while i < len(args):
        if args[i] == "--declare":
            name, size = args[i + 1].split("=", 1)
            declared[name] = int(size)
            i += 2
            continue
        name, src = args[i].split("=", 1)
        pairs.append((name, src))
        i += 1

    with zipfile.ZipFile(out, "w") as zf:
        for name, src in pairs:
            with open(src, "rb") as f:
                data = f.read()
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data, compresslevel=9)

    if declared:
        patch_sizes(out, declared)


def patch_sizes(path, declared):
    # Overwrite the uncompressed size in the central directory and in the local
    # header of each named entry (archives written here have no comment and no
    # ZIP64 records, so the end record is the last 22 bytes)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    eocd = data.rfind(b"PK\x05\x06")
    pos = struct.unpack_from("<I", data, eocd + 16)[0]
    while data[pos:pos + 4] == b"PK\x01\x02":
        nlen, elen, clen = struct.unpack_from("<HHH", data, pos + 28)
        name = bytes(data[pos + 46:pos + 46 + nlen]).decode("utf-8")
        local = struct.unpack_from("<I", data, pos + 42)[0]
        if name in declared:
            struct.pack_into("<I", data, pos + 24, declared[name])
            struct.pack_into("<I", data, local + 22, declared[name])
        pos += 46 + nlen + elen + clen
    with open(path, "wb") as f:
        f.write(data)


def listing(path):
    methods = {zipfile.ZIP_STORED: "stored", zipfile.ZIP_DEFLATED: "deflate"}
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            print("\t".join([
                info.filename,
                methods.get(info.compress_type, str(info.compress_type)),
                str(info.file_size),
                info.comment.decode("utf-8", "replace"),
            ]))
        try:
            bad = zf.testzip()
            print("testzip\t" + ("ok" if bad is None else "bad entry " + bad))
        except Exception as e:  # corrupt member data
            print("testzip\t" + type(e).__name__ + ": " + str(e))


def extract(path, name, out):
    with zipfile.ZipFile(path) as zf:
        data = zf.read(name)
    with open(out, "wb") as f:
        f.write(data)


def noise(size, seed):
    x = seed
    out = bytearray()
    for _ in range(size):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    sys.stdout.buffer.write(bytes(out))


def main(argv):
    if len(argv) >= 3 and argv[1] == "make":
        make(argv[2], argv[3:])
    elif len(argv) == 3 and argv[1] == "list":
        listing(argv[2])
    elif len(argv) == 5 and argv[1] == "extract":
        extract(argv[2], argv[3], argv[4])
    elif len(argv) == 4 and argv[1] == "noise":
        noise(int(argv[2]), int(argv[3]))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
