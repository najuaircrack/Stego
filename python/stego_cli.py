#!/usr/bin/env python3
"""stego CLI: one command, file/bytes jobs only (hide/reveal/info)."""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from stegolib import decode_image, encode_image
from PIL import Image


def flat(img):
    out = []
    for r, g, b in img.getdata():
        out += [r, g, b]
    return out


def cmd_hide(a):
    img = Image.open(a.cover).convert('RGB')
    w, h = img.size
    payload = open(a.payload, 'rb').read()
    if not payload:
        print('ERROR: empty payload refused')
        return 1
    out = encode_image(flat(img), w, h, payload, seed=a.seed,
                       password=a.password or '', do_auth=a.auth,
                       scatter=a.scatter or a.seed != 0)
    res = Image.new('RGB', (w, h))
    res.putdata([tuple(out[i:i + 3]) for i in range(0, len(out), 3)])
    res.save(a.output, 'PNG')
    print(f'[+] {len(payload)} bytes -> {a.output}')
    return 0


def cmd_reveal(a):
    img = Image.open(a.image).convert('RGB')
    w, h = img.size
    payload = decode_image(flat(img), w, h, password=a.password or '')
    if payload is None:
        print('ERROR: decode failed (format/CRC/auth)')
        return 1
    open(a.output, 'wb').write(payload)
    print(f'[+] {len(payload)} bytes -> {a.output}')
    if payload[:2] == b'MZ':
        print('    note: payload starts with MZ (Windows executable)')
    return 0


def cmd_info(a):
    from stegolib import (MAGIC, FORMAT_VERSION, F_COMPRESS, F_SCATTER,
                          F_ENCRYPT, F_AUTH, read_bits, placement)
    import struct
    img = Image.open(a.image).convert('RGB')
    w, h = img.size
    npx = w * h
    seq = placement(npx, 0)
    hdr = read_bits(flat(img), w, h, seq, 0, 44)
    print(f'dimensions: {w}x{h} ({npx} px, ~{npx * 3 // 8} payload bytes max)')
    if hdr[:4] != MAGIC:
        print('format: unrecognized (not a stego image)')
        return 0
    ver, flags = struct.unpack('<H', hdr[4:6])[0], struct.unpack('<H', hdr[6:8])[0]
    if ver != FORMAT_VERSION:
        print(f'format: unsupported version v{ver} (this tool reads v{FORMAT_VERSION} only)')
        return 0
    seed, orig, comp = struct.unpack('<III', hdr[8:20])
    print(f'format: stego envelope v{ver}')
    print(f'flags: scatter={bool(flags & F_SCATTER)} encrypt={bool(flags & F_ENCRYPT)} '
          f'auth={bool(flags & F_AUTH)} compress={bool(flags & F_COMPRESS)}')
    print(f'seed: {seed}')
    print(f'payload size: {orig} bytes (stored {comp})')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='stego', description='hide bytes in PNGs')
    sub = ap.add_subparsers(dest='cmd', required=True)
    h = sub.add_parser('hide')
    h.add_argument('payload')
    h.add_argument('--cover', required=True)
    h.add_argument('-o', '--output', required=True)
    h.add_argument('--seed', type=int, default=0)
    h.add_argument('--scatter', action='store_true')
    h.add_argument('--password', default='')
    h.add_argument('--auth', action='store_true')
    h.set_defaults(fn=cmd_hide)
    r = sub.add_parser('reveal')
    r.add_argument('image')
    r.add_argument('-o', '--output', required=True)
    r.add_argument('--password', default='')
    r.set_defaults(fn=cmd_reveal)
    i = sub.add_parser('info')
    i.add_argument('image')
    i.set_defaults(fn=cmd_info)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == '__main__':
    sys.exit(main())
