#!/usr/bin/env python3
"""extract.py template: decode a PNG file to a payload file.
Usage: extract.py <image.png> <out.bin> [--password P]
Decode only. What you DO with the bytes afterwards is your responsibility.
"""
import sys

from PIL import Image

sys.path.insert(0, __import__('os').path.join(
    __import__('os').path.dirname(__file__), '..', 'python'))
from stegolib import decode_image


def main():
    password = ''
    args = [a for a in sys.argv[1:] if not a.startswith('--password')]
    for i, a in enumerate(sys.argv[1:]):
        if a == '--password' and i + 1 < len(sys.argv[1:]):
            password = sys.argv[1:][i + 1]
    if len(args) != 2:
        print('usage: extract.py <image.png> <out.bin> [--password P]')
        return 2
    img = Image.open(args[0]).convert('RGB')
    w, h = img.size
    flat = []
    for r, g, b in img.getdata():
        flat += [r, g, b]
    payload = decode_image(flat, w, h, password=password)
    if payload is None:
        print('decode failed')
        return 1
    open(args[1], 'wb').write(payload)
    print(f'decoded {len(payload)} bytes')
    return 0


if __name__ == '__main__':
    sys.exit(main())
