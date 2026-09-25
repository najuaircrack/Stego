#!/usr/bin/env python3
"""extract.py - stego CLI: stego PNG -> payload (current + legacy v1 read)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from stegolib import decode_image
from PIL import Image


def main():
    import argparse
    ap = argparse.ArgumentParser(description='stego extract')
    ap.add_argument('stego')
    ap.add_argument('output')
    ap.add_argument('--password', default='')
    a = ap.parse_args()
    img = Image.open(a.stego).convert('RGB')
    w, h = img.size
    flat = []
    for r, g, b in img.getdata():
        flat += [r, g, b]
    payload = decode_image(flat, w, h, password=a.password)
    if payload is None:
        print('ERROR: decode failed (format/CRC/auth)')
        sys.exit(1)
    open(a.output, 'wb').write(payload)
    print(f'[+] {len(payload)} bytes -> {a.output}')
    if payload[:2] == b'MZ':
        print('    Detected: PE executable')


if __name__ == '__main__':
    main()
