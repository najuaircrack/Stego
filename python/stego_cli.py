#!/usr/bin/env python3
"""stego CLI: one command, file/bytes jobs only (hide/reveal/info)."""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from stegolib import (decode_image, encode_image)
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
    if a.envelope == 'v4' and not a.password:
        print('ERROR: v4 requires --password')
        return 1
    out = encode_image(flat(img), w, h, payload, password=a.password or '',
                       seed=a.seed, envelope=a.envelope, do_auth=a.auth,
                       scatter=a.scatter or None, adaptive=a.adaptive,
                       robust=a.robust, costq=a.costq, stc=a.stc, kdf=a.kdf)
    env = a.envelope
    res = Image.new('RGB', (w, h))
    res.putdata([tuple(out[i:i + 3]) for i in range(0, len(out), 3)])
    res.save(a.output, 'PNG')
    print(f'[+] {len(payload)} bytes -> {a.output} ({env})')
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
    from stegolib import (MAGIC, FORMAT_VERSION, FORMAT_V4, F_COMPRESS,
                          F_SCATTER, F_ENCRYPT, F_AUTH, F_ADAPTIVE, F_ROBUST,
                          read_bits, placement, v4_read_bits,
                          V4_HEADER_LEN)
    import struct
    img = Image.open(a.image).convert('RGB')
    w, h = img.size
    npx = w * h
    seq = placement(npx, 0)
    hdr = read_bits(flat(img), w, h, seq, 0, 44)
    print(f'dimensions: {w}x{h} ({npx} px, ~{npx * 3 // 8} payload bytes max)')
    ver, flags = None, None
    if hdr[:4] == MAGIC:
        # v3 header (44B over the 3-channel sequential map)
        ver, flags = struct.unpack('<H', hdr[4:6])[0], struct.unpack('<H', hdr[6:8])[0]
    if ver is None and npx > 256:
        # v4 header lives in R/B slots: re-read the 64B header properly
        hdr = bytes(v4_read_bits(flat(img), w, list(range(256)),
                                 V4_HEADER_LEN * 8))
        if hdr[:4] == MAGIC:
            ver, flags = struct.unpack('<H', hdr[4:6])[0], struct.unpack('<H', hdr[6:8])[0]
    if ver is None:
        print('format: unrecognized (not a stego image)')
        return 0
    if ver == FORMAT_V4:
        seed, orig, comp, costq = struct.unpack('<IIII', hdr[8:24])
        print(f'format: stego envelope v4')
        print(f'flags: adaptive={bool(flags & F_ADAPTIVE)} '
              f'robust={bool(flags & F_ROBUST)} '
              f'scatter={bool(flags & F_SCATTER)}')
        print(f'seed: {seed}  costq: {costq}')
        print(f'payload size: {orig} bytes (stored {comp})')
        return 0
    if ver != FORMAT_VERSION:
        print(f'format: unsupported version v{ver} (this tool reads v3+v4 only)')
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
    h.add_argument('--envelope', choices=('v4', 'v3'), default='v4',
                   help='envelope version (default: modern v4)')
    h.add_argument('--adaptive', dest='adaptive', action='store_true',
                   default=True)
    h.add_argument('--no-adaptive', dest='adaptive', action='store_false')
    h.add_argument('--robust', action='store_true')
    h.add_argument('--costq', type=int, default=8)
    h.add_argument('--stc', dest='stc', action='store_true', default=True)
    h.add_argument('--no-stc', dest='stc', action='store_false')
    h.add_argument('--kdf', choices=('argon2id', 'pbkdf2'),
                   default='argon2id')
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
