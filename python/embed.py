#!/usr/bin/env python3
"""embed.py - stego CLI: cover PNG + payload -> stego PNG. See docs/FORMAT.md."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from stegolib import encode_image
from PIL import Image


def main():
    import argparse
    ap = argparse.ArgumentParser(description='stego embed')
    ap.add_argument('cover')
    ap.add_argument('payload')
    ap.add_argument('output')
    ap.add_argument('--seed', type=int, default=0, help='scatter seed (0=sequential)')
    ap.add_argument('--scatter', action='store_true')
    ap.add_argument('--password', default='')
    ap.add_argument('--auth', action='store_true')
    a = ap.parse_args()
    img = Image.open(a.cover).convert('RGB')
    w, h = img.size
    flat = []
    for r, g, b in img.getdata():
        flat += [r, g, b]
    payload = open(a.payload, 'rb').read()
    out = encode_image(flat, w, h, payload, seed=a.seed, password=a.password,
                       do_auth=a.auth, scatter=a.scatter)
    res = Image.new('RGB', (w, h))
    res.putdata([tuple(out[i:i + 3]) for i in range(0, len(out), 3)])
    res.save(a.output, 'PNG')
    print(f'[+] {len(payload)} bytes -> {a.output} ({w}x{h}, seed={a.seed})')


if __name__ == '__main__':
    main()
