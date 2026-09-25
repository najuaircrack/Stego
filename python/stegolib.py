#!/usr/bin/env python3
"""stegolib.py - codec core (mirrors src/*.cpp bit-for-bit).

Single envelope format: [44B header][body][data_crc32][hmac?], header
pixels [0,118) sequential, body via PlacementRange(118, N-118, seed).
See docs/FORMAT.md.
"""
import hashlib
import hmac as hmac_mod
import os
import struct
import zlib

MAGIC = b'STG2'
FORMAT_VERSION = 0x0003
HEADER_LEN = 44
HEADER_PX = 118
SALT_LEN = 16
PBKDF2_ITER = 100000
F_COMPRESS = 0x0001
F_SCATTER = 0x0002
F_ENCRYPT = 0x0004
F_AUTH = 0x0008
MASK64 = 0xFFFFFFFFFFFFFFFF


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def splitmix64(state):
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return (z ^ (z >> 31)) & MASK64, state


class Xor128:
    def __init__(self, seed):
        t = seed & MASK64
        a, t = splitmix64(t)
        b, t = splitmix64(t)
        if a == 0 and b == 0:
            b = 0x9E3779B97F4A7C15
        self.s = [a, b]

    def next(self):
        x, y = self.s
        self.s[0] = y
        x ^= (x << 23) & MASK64
        self.s[1] = (x ^ y ^ (x >> 17) ^ (y >> 26)) & MASK64
        return (self.s[1] + y) & MASK64


def placement(n, seed):
    p = list(range(n))
    if seed != 0 and n > 1:
        r = Xor128(seed)
        for i in range(n - 1, 0, -1):
            j = r.next() % (i + 1)
            p[i], p[j] = p[j], p[i]
    return p


def placement_range(base, count, seed):
    p = [base + i for i in range(count)]
    if seed != 0 and count > 1:
        r = Xor128(seed)
        for i in range(count - 1, 0, -1):
            j = r.next() % (i + 1)
            p[i], p[j] = p[j], p[i]
    return p


def keystream_raw(key32, n):
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key32 + struct.pack('>I', ctr)).digest()
        ctr += 1
    return bytes(out[:n])


def kdf(pw, salt):
    # PBKDF2-HMAC-SHA256 -> 64B (enc[0..32) + auth[32..64)).
    # Password encoding: UTF-8 bytes (FORMAT.md).
    if isinstance(pw, str):
        pw = pw.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', pw, salt, PBKDF2_ITER, 64)


def encode_image(pixels, w, h, payload, seed=0, password='',
                 do_auth=False, scatter=None):
    """pixels: flat [R,G,B]* list. Returns new flat list with message."""
    if scatter is None:
        scatter = seed != 0
    if do_auth and not password:
        raise ValueError('auth requires password')
    if scatter and seed == 0:
        raise ValueError('scatter requires nonzero seed')
    if not payload:
        raise ValueError('empty payload refused (explicit, documented)')
    body = bytearray(payload)
    salt = b'\x00' * SALT_LEN  # header field always present (zeros if unused)
    if password:
        salt = os.urandom(SALT_LEN)
        dk = kdf(password, salt)
        ks = keystream_raw(dk[:32], len(body))
        body = bytearray(b ^ ks[i] for i, b in enumerate(body))
    flags = 0
    if scatter:
        flags |= F_SCATTER
    if password:
        flags |= F_ENCRYPT
    if do_auth:
        flags |= F_AUTH
    hdr = bytearray(MAGIC)
    hdr += struct.pack('<H', FORMAT_VERSION)
    hdr += struct.pack('<H', flags)
    hdr += struct.pack('<I', seed)
    hdr += struct.pack('<I', len(payload))
    hdr += struct.pack('<I', len(body))
    hdr += struct.pack('<I', 0)
    hdr += salt
    hdr += struct.pack('<I', crc32(bytes(hdr)))
    assert len(hdr) == HEADER_LEN
    stream = bytes(hdr) + bytes(body)
    tag = None
    if do_auth:
        # Tag covers header+ciphertext ONLY (not data_crc32) - must match
        # the decode-side span exactly.
        ak = kdf(password, salt)[32:]
        tag = hmac_mod.new(ak, stream, hashlib.sha256).digest()
    stream += struct.pack('<I', crc32(payload))
    if do_auth:
        stream += tag
    npx = w * h
    if npx <= HEADER_PX:
        raise ValueError('image too small for header')
    if (len(stream) * 8 - HEADER_LEN * 8) > (npx - HEADER_PX) * 3:
        raise ValueError('payload too large: %d bits need %d' %
                         (len(stream) * 8, npx * 3))
    out = list(pixels)
    for k in range(HEADER_LEN * 8):
        bit = (stream[k // 8] >> (k % 8)) & 1
        p = k // 3
        y, x = p // w, p % w
        out[(y * w + x) * 3 + (k % 3)] = (out[(y * w + x) * 3 + (k % 3)] & 0xFE) | bit
    place = placement_range(HEADER_PX, npx - HEADER_PX, seed)
    for m in range(HEADER_LEN * 8, len(stream) * 8):
        bit = (stream[m // 8] >> (m % 8)) & 1
        p = place[(m - HEADER_LEN * 8) // 3]
        y, x = p // w, p % w
        idx = (y * w + x) * 3 + ((m - HEADER_LEN * 8) % 3)
        out[idx] = (out[idx] & 0xFE) | bit
    return out


def capacity(w, h):
    """Payload-byte budget for dims (v3 layout, conservative, no tag)."""
    npx = w * h
    if npx <= HEADER_PX:
        return 0
    body_bits = (npx - HEADER_PX) * 3
    if body_bits < 4 * 8:
        return 0
    return (body_bits - 4 * 8) // 8


def read_bits(pixels, w, h, place, bit_off, nbytes):
    out = bytearray(nbytes)
    for i in range(nbytes * 8):
        p = place[(bit_off + i) // 3]
        y, x = p // w, p % w
        if pixels[(y * w + x) * 3 + ((bit_off + i) % 3)] & 1:
            out[i // 8] |= (1 << (i % 8))
    return bytes(out)


def _decode(pixels, w, h, hdr, password):
    npx = w * h
    ver, flags = struct.unpack('<H', hdr[4:6])[0], struct.unpack('<H', hdr[6:8])[0]
    seed, orig, comp = struct.unpack('<III', hdr[8:20])
    salt = hdr[24:40]
    hcrc = struct.unpack('<I', hdr[40:44])[0]
    if ver != FORMAT_VERSION or crc32(hdr[:40]) != hcrc:
        return None
    if flags & F_COMPRESS:
        return None
    enc = bool(flags & F_ENCRYPT)
    auth = bool(flags & F_AUTH)
    if (enc or auth) and not password:
        return None
    if auth and not enc:
        return None
    if comp == 0:
        return None
    ak = ek = None
    if enc:
        dk = kdf(password, salt)
        ek, ak = dk[:32], dk[32:]
    place = placement_range(HEADER_PX, npx - HEADER_PX, seed)
    body = read_bits(pixels, w, h, place, 0, comp)
    crc_at = comp * 8
    tag_at = (comp + 4) * 8
    stored = hdr + body
    if auth:
        tag = read_bits(pixels, w, h, place, tag_at, 32)
        good = hmac_mod.new(ak, stored, hashlib.sha256).digest()
        if tag != good:
            return None
    if enc:
        ks = keystream_raw(ek, len(body))
        body = bytes(b ^ ks[i] for i, b in enumerate(body))
    dcrc = struct.unpack('<I', read_bits(pixels, w, h, place, crc_at, 4))[0]
    if orig != comp:
        return None
    if crc32(body) != dcrc:
        return None
    return body


def decode_image(pixels, w, h, password=''):
    npx = w * h
    if w == 0 or h == 0 or len(pixels) < npx * 3:
        return None  # truncated/degenerate buffer: fail clean, never index OOB
    seq = placement(npx, 0)
    hdr = read_bits(pixels, w, h, seq, 0, HEADER_LEN)
    if hdr[:4] != MAGIC:
        return None
    if struct.unpack('<H', hdr[4:6])[0] != FORMAT_VERSION:
        return None
    return _decode(pixels, w, h, hdr, password)  # accept or reject, no fallbacks
