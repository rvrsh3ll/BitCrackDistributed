#!/usr/bin/env python3
"""Draw a node's keyspace coverage as a disk-defrag style grid.

Reads GET /keyspace?buckets=N from the stats API (read-only, loopback by
default) and prints the grid to the terminal, or writes a PNG (no extra
packages needed). One cell per bucket, left to right, top to bottom; colour =
the contributor with the most keys in the bucket, brightness = fraction of
the bucket searched.

A puzzle range is huge (puzzle 71: 2^70 keys), so even a busy network covers
a tiny fraction of each bucket. By default brightness is on a log scale and
any searched bucket is visible; --linear shows the true fraction.

  scripts/keyspace_map.py                                  # terminal, 1024 buckets
  scripts/keyspace_map.py --buckets 16384 --png map.png    # 128x128 PNG
  ssh seed1 curl -s 'http://127.0.0.1:3339/keyspace?buckets=4096' | scripts/keyspace_map.py --stdin
"""
import argparse
import json
import math
import struct
import sys
import urllib.request
import zlib

PALETTE = [
    (230, 25, 75), (60, 180, 75), (255, 225, 25), (0, 130, 200), (245, 130, 48),
    (145, 30, 180), (70, 240, 240), (240, 50, 230), (210, 245, 60), (250, 190, 212),
    (0, 128, 128), (220, 190, 255), (170, 110, 40), (255, 250, 200), (128, 0, 0),
    (170, 255, 195), (128, 128, 0), (255, 215, 180), (0, 0, 128), (128, 128, 128),
]
EMPTY = (24, 24, 24)


def fetch(url, buckets):
    with urllib.request.urlopen(f"{url.rstrip('/')}/keyspace?buckets={buckets}", timeout=30) as r:
        return json.load(r)


def level(fraction, lo, linear):
    """0..1 brightness for a bucket's searched fraction."""
    if fraction <= 0:
        return 0.0
    if linear:
        return max(0.15, min(1.0, fraction))
    if lo >= 1.0:
        return 1.0
    # Log scale from the smallest non-zero fraction (dim) to 1 (full).
    return 0.25 + 0.75 * (math.log10(fraction) - math.log10(lo)) / -math.log10(lo)


def cells(data, linear):
    frac = data["buckets"]["fraction"]
    dom = data["buckets"]["dominant"]
    nonzero = [f for f in frac if f > 0]
    lo = min(nonzero) if nonzero else 1.0
    out = []
    for f, d in zip(frac, dom):
        if f <= 0 or d < 0:
            out.append(EMPTY)
            continue
        r, g, b = PALETTE[d % len(PALETTE)]
        k = level(f, lo, linear)
        out.append((int(EMPTY[0] + (r - EMPTY[0]) * k), int(EMPTY[1] + (g - EMPTY[1]) * k),
                    int(EMPTY[2] + (b - EMPTY[2]) * k)))
    return out


def write_png(path, px, width, scale):
    height = (len(px) + width - 1) // width
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            i = y * width + x
            c = px[i] if i < len(px) else (0, 0, 0)
            row += bytes(c) * scale
        rows.extend([b"\x00" + bytes(row)] * scale)
    raw = b"".join(rows)

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width * scale, height * scale, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def print_terminal(px, width):
    for y in range(0, len(px), width):
        line = "".join(f"\x1b[48;2;{r};{g};{b}m " for r, g, b in px[y:y + width])
        print(line + "\x1b[0m")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:3339", help="stats API base URL")
    ap.add_argument("--buckets", type=int, default=1024)
    ap.add_argument("--width", type=int, default=0, help="cells per row (default: square)")
    ap.add_argument("--png", help="write a PNG here instead of printing")
    ap.add_argument("--scale", type=int, default=4, help="PNG pixels per cell")
    ap.add_argument("--linear", action="store_true", help="brightness = true fraction (default log scale)")
    ap.add_argument("--stdin", action="store_true", help="read the /keyspace JSON from stdin")
    a = ap.parse_args()

    data = json.load(sys.stdin) if a.stdin else fetch(a.url, a.buckets)
    if not data.get("available") or "buckets" not in data:
        sys.exit("no keyspace data (is the puzzle initialised and the request /keyspace?buckets=N?)")
    px = cells(data, a.linear)
    width = a.width or max(1, int(math.ceil(math.sqrt(len(px)))))
    print(f"puzzle {data.get('puzzle')}  {data['range_start']}..{data['range_end']}  "
          f"searched {data['keys_searched_decimal']} of {data['keyspace_keys']} keys "
          f"({data['percent_searched']:.3g}%)  {data['range_count']} ranges, "
          f"{data['bucket_count']} buckets of {data['bucket_keys']} keys", file=sys.stderr)
    for i, who in enumerate(data.get("contributors", [])[:len(PALETTE)]):
        r, g, b = PALETTE[i]
        print(f"  \x1b[48;2;{r};{g};{b}m  \x1b[0m {who}", file=sys.stderr)
    if a.png:
        write_png(a.png, px, width, max(1, a.scale))
        print(f"wrote {a.png}", file=sys.stderr)
    else:
        print_terminal(px, width)


if __name__ == "__main__":
    main()
