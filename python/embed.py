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
    ap.add_argument('--envelope', choices=('v4', 'v3'), default='v4',
                    help='envelope version (default: modern v4)')
    ap.add_argument('--adaptive', dest='adaptive', action='store_true',
                    default=True)
    ap.add_argument('--no-adaptive', dest='adaptive', action='store_false')
    ap.add_argument('--robust', action='store_true')
    ap.add_argument('--costq', type=int, default=8)
    ap.add_argument('--stc', dest='stc', action='store_true', default=True)
    ap.add_argument('--no-stc', dest='stc', action='store_false')
    ap.add_argument('--kdf', choices=('argon2id', 'pbkdf2'),
                    default='argon2id')
    a = ap.parse_args()
    img = Image.open(a.cover).convert('RGB')
    w, h = img.size
    flat = []
    for r, g, b in img.getdata():
        flat += [r, g, b]
    payload = open(a.payload, 'rb').read()
    if a.envelope == 'v4' and not a.password:
        print('ERROR: v4 requires --password')
        return 1
    out = encode_image(flat, w, h, payload, password=a.password,
                       seed=a.seed, envelope=a.envelope, do_auth=a.auth,
                       scatter=a.scatter, adaptive=a.adaptive,
                       robust=a.robust, costq=a.costq, stc=a.stc, kdf=a.kdf)
    env = a.envelope
    res = Image.new('RGB', (w, h))
    res.putdata([tuple(out[i:i + 3]) for i in range(0, len(out), 3)])
    res.save(a.output, 'PNG')
    print(f'[+] {len(payload)} bytes -> {a.output} ({w}x{h}, {env}, seed={a.seed})')


if __name__ == '__main__':
    main()
