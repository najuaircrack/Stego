#!/usr/bin/env python3
"""stegolib.py - codec core (mirrors src/*.cpp bit-for-bit).

Two envelopes, one module. v3 (frozen): [44B header][body][data_crc32]
[hmac?], header pixels [0,118) sequential, body via
PlacementRange(118, N-118, seed). v4 (modern): [64B header][AEAD body],
ternary +/-1 embedding, cost-ordered adaptive placement, ChaCha20-Poly1305
with the full header as associated data. `decode_auto` dispatches on the
header version. See docs/FORMAT.md (normative for both).
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


# ============================================================================
# v4 envelope (FORMAT.md section 2): AEAD + adaptive ternary placement.
# ============================================================================

FORMAT_V4 = 0x0004
V4_HEADER_LEN = 64
V4_HEADER_PX = 256  # 256 px * 2 ch (R/B) = 512 header bits exactly
V4_PBKDF2_ITER = 210000
V4_KDF_OUT = 96     # 32 msg-key + 12 nonce + 52 reserved
V4_TAG_LEN = 16
F_ADAPTIVE = 0x0010
F_ROBUST = 0x0020
V4_COSTQ_DEFAULT = 8


def _rotl32(v, n):
    n &= 31
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n)) if n else v & 0xFFFFFFFF


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = _rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = _rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = _rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = _rotl32(x[b], 7)


def chacha_block(key32, nonce12, counter):
    """RFC 8439 ChaCha20 block -> 64 bytes."""
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack('<8I', key32))
    st += [counter & 0xFFFFFFFF]
    st += list(struct.unpack('<3I', nonce12))
    w = list(st)
    for _ in range(10):
        _qr(w, 0, 4, 8, 12)
        _qr(w, 1, 5, 9, 13)
        _qr(w, 2, 6, 10, 14)
        _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15)
        _qr(w, 1, 6, 11, 12)
        _qr(w, 2, 7, 8, 13)
        _qr(w, 3, 4, 9, 14)
    return struct.pack('<16I', *[((a + b) & 0xFFFFFFFF)
                                   for a, b in zip(w, st)])


def poly1305_mac(key32, msg):
    """RFC 8439 Poly1305 -> 16-byte tag."""
    r = int.from_bytes(key32[:16], 'little') & 0xffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key32[16:], 'little')
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16] + b'\x01'
        acc = ((acc + int.from_bytes(blk, 'little')) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')


def _pad16(data):
    return data + b'\x00' * ((-len(data)) % 16)


def aead_encrypt(key32, nonce12, aad, plaintext):
    otk = chacha_block(key32, nonce12, 0)[:32]
    ks = b''.join(chacha_block(key32, nonce12, c)
                  for c in range(1, (len(plaintext) // 64) + 2))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    mac = _pad16(aad) + _pad16(ct)
    mac += struct.pack('<Q', len(aad)) + struct.pack('<Q', len(ct))
    return ct + poly1305_mac(otk, mac)


def aead_decrypt(key32, nonce12, aad, blob):
    import hmac as _hm
    if len(blob) < V4_TAG_LEN:
        return None
    ct, tag = blob[:-V4_TAG_LEN], blob[-V4_TAG_LEN:]
    otk = chacha_block(key32, nonce12, 0)[:32]
    mac = _pad16(aad) + _pad16(ct)
    mac += struct.pack('<Q', len(aad)) + struct.pack('<Q', len(ct))
    if not _hm.compare_digest(poly1305_mac(otk, mac), tag):
        return None
    ks = b''.join(chacha_block(key32, nonce12, c)
                  for c in range(1, (len(ct) // 64) + 2))
    return bytes(a ^ b for a, b in zip(ct, ks))


def kdf4(pw, salt):
    # PBKDF2-HMAC-SHA256 -> 96B (msg-key[0..32) + nonce[32..44) + rsv).
    if isinstance(pw, str):
        pw = pw.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', pw, salt, V4_PBKDF2_ITER, V4_KDF_OUT)


def v4_costs(pixels, w, h):
    """Per-pixel 3x3 variance of the GREEN channel (FORMAT.md 2.4 rule 1),
    exact integers. Mirror edges. O(n) via summed-area tables.
    Green is never written by v4 embedding, so decode-side costs equal
    encode-side costs bit-exact (invariance — no retries, no margins)."""
    g = [pixels[3 * i + 1] for i in range(w * h)]
    # padded (h+2) x (w+2) with mirrored border
    pw_, ph_ = w + 2, h + 2
    pad = [0] * (pw_ * ph_)
    for yy in range(ph_):
        sy = min(max(yy - 1, 0), h - 1)
        for xx in range(pw_):
            sx = min(max(xx - 1, 0), w - 1)
            pad[yy * pw_ + xx] = g[sy * w + sx]
    # integral images of sum and sum-of-squares
    sw, sq = w + 3, h + 3  # one extra row/col of zeros
    isum = [0] * (sw * sq)
    isq = [0] * (sw * sq)
    for yy in range(ph_):
        rs, rq = 0, 0
        for xx in range(pw_):
            v = pad[yy * pw_ + xx]
            rs += v
            rq += v * v
            isum[(yy + 1) * sw + (xx + 1)] = isum[yy * sw + (xx + 1)] + rs
            isq[(yy + 1) * sw + (xx + 1)] = isq[yy * sw + (xx + 1)] + rq
    cost = [0] * (w * h)
    for yy in range(h):
        for xx in range(w):
            x0, y0 = xx, yy
            s = (isum[(y0 + 3) * sw + (x0 + 3)] - isum[y0 * sw + (x0 + 3)] -
                 isum[(y0 + 3) * sw + x0] + isum[y0 * sw + x0])
            q = (isq[(y0 + 3) * sw + (x0 + 3)] - isq[y0 * sw + (x0 + 3)] -
                 isq[(y0 + 3) * sw + x0] + isq[y0 * sw + x0])
            cost[yy * w + xx] = (9 * q - s * s) // 81
    return cost


def v4_bucket(cost, q):
    """Bucket index per FORMAT.md 2.4 rule 2. Integer-only. No skip rule:
    every pixel is a candidate; stability comes from green-invariance."""
    lb = cost.bit_length()
    return q - 1 if q <= 1 else min(q - 1, (lb * q) >> 4)


def v4_candidate_order(pixels, w, h, seed, costq, adaptive):
    """Pixel indices carrying body stream slots (header pixels excluded).
    Pure function of (green costs, seed, costq, adaptive) — the decoder
    reproduces it bit-exact from the stego image."""
    npx = w * h
    if not adaptive:
        return placement_range(V4_HEADER_PX, npx - V4_HEADER_PX, seed)
    costs = v4_costs(pixels, w, h)
    buckets = {}
    for i in range(V4_HEADER_PX, npx):
        buckets.setdefault(v4_bucket(costs[i], costq), []).append(i)
    order = []
    for b in sorted(buckets.keys(), reverse=True):
        members = sorted(buckets[b])
        r = Xor128((seed ^ ((b + 1) * 0x9E3779B97F4A7C15)) & MASK64)
        for i in range(len(members) - 1, 0, -1):
            j = r.next() % (i + 1)
            members[i], members[j] = members[j], members[i]
        order.extend(members)
    return order


def _v4_slot(order, s):
    """Slot s -> flat channel index. Slots use RED/BLUE only (green is
    never written): candidate pixel order[s//2], R if s even else B."""
    return order[s // 2] * 3 + (0 if s % 2 == 0 else 2)


def _v4_dirbit(seed64, s):
    """Direction bit for global slot s (FORMAT.md 2.5). Stateless
    SplitMix-finalize — no shared RNG state across header/body calls."""
    z = (seed64 ^ ((s * 0x9E3779B97F4A7C15) & MASK64)) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    z = (z ^ (z >> 31)) & MASK64
    return (z >> 32) & 1


def v4_embed_bits(px, w, order, bits, robust, seed64, slot_base):
    """Ternary +/-1 embed (FORMAT.md 2.5) over the R/B slot stream.
    `slot_base` is the global slot number of bits[0] (0 for the header,
    512 for the body) — directions are per-slot-hashed, so split calls
    stay bit-identical without shared state."""
    slots = 0
    bi = 0
    nbits = len(bits) * 8
    rep = 3 if robust else 1
    while bi < nbits:
        b = (bits[bi // 8] >> (bi % 8)) & 1
        for _ in range(rep):
            ch = _v4_slot(order, slots)
            v = px[ch]
            if (v & 1) != b:
                if v == 0:
                    v = 1
                elif v == 255:
                    v = 254
                else:
                    v += 1 if _v4_dirbit(seed64, slot_base + slots) else -1
                px[ch] = v
            slots += 1
        bi += 1
    return slots


def v4_read_bits(pixels, w, order, nbits, robust):
    out = bytearray((nbits + 7) // 8)
    for bi in range(nbits):
        if robust:
            votes = 0
            for k in range(3):
                votes += pixels[_v4_slot(order, 3 * bi + k)] & 1
            b = 1 if votes >= 2 else 0  # ties -> 0
        else:
            b = pixels[_v4_slot(order, bi)] & 1
        if b:
            out[bi // 8] |= (1 << (bi % 8))
    return bytes(out)


def _v4_pack_header(flags, seed, orig, comp, costq, salt):
    hdr = bytearray(MAGIC)
    hdr += struct.pack('<H', FORMAT_V4)
    hdr += struct.pack('<H', flags)
    hdr += struct.pack('<I', seed)
    hdr += struct.pack('<I', orig)
    hdr += struct.pack('<I', comp)
    hdr += struct.pack('<I', costq)
    hdr += salt
    hdr += struct.pack('<I', 0)
    hdr += struct.pack('<I', crc32(bytes(hdr)))
    hdr += bytes(16)
    assert len(hdr) == V4_HEADER_LEN
    return bytes(hdr)


def _v4_parse_header(hdr):
    if len(hdr) != V4_HEADER_LEN or hdr[:4] != MAGIC:
        return None
    ver, flags = struct.unpack('<H', hdr[4:6])[0], struct.unpack('<H', hdr[6:8])[0]
    seed, orig, comp, costq = struct.unpack('<IIII', hdr[8:24])
    salt = hdr[24:40]
    hcrc = struct.unpack('<I', hdr[44:48])[0]
    if ver != FORMAT_V4 or crc32(hdr[:44]) != hcrc:
        return None
    if flags & F_COMPRESS:
        return None
    if not (flags & F_ENCRYPT) or not (flags & F_AUTH):
        return None  # v4 is always encrypted + authenticated
    if not (1 <= costq <= 16) or orig < 1 or comp != orig + 4 + V4_TAG_LEN:
        return None
    return {'flags': flags, 'seed': seed, 'orig': orig, 'comp': comp,
            'costq': costq, 'salt': salt}


def _v4_slots_avail(npx, robust):
    ch = 2 * max(0, npx - V4_HEADER_PX)  # R/B channels only, green untouched
    return ch // 3 if robust else ch


def encode_image_v4(pixels, w, h, payload, password, seed=None, adaptive=True,
                    robust=False, costq=V4_COSTQ_DEFAULT, scatter=True):
    """v4 encode. Returns new flat pixel list. Password REQUIRED in v4."""
    if not payload:
        raise ValueError('empty payload refused (explicit, documented)')
    if not password:
        raise ValueError('v4 requires a password (ENCRYPT+AUTH always on)')
    if not (1 <= costq <= 16):
        raise ValueError('costq out of range 1..16')
    npx = w * h
    if npx <= V4_HEADER_PX:
        raise ValueError('image too small for v4 header')
    if isinstance(password, str):
        password = password.encode('utf-8')
    if seed is None:
        seed = int.from_bytes(os.urandom(4), 'little')
    if adaptive and (seed or 0) == 0:
        # 0 is forbidden on the wire for ADAPTIVE: pick nonzero random
        # (same rule as the C++ port — seed 0 is never written).
        seed = int.from_bytes(os.urandom(4), 'little') or 1
    flags = F_ENCRYPT | F_AUTH
    if scatter:
        flags |= F_SCATTER
    if adaptive:
        flags |= F_ADAPTIVE
    if robust:
        flags |= F_ROBUST
    comp = len(payload) + 4 + V4_TAG_LEN
    need_slots = comp * 8 * (3 if robust else 1)

    salt = os.urandom(SALT_LEN)
    dk = hashlib.pbkdf2_hmac('sha256', password, salt,
                             V4_PBKDF2_ITER, V4_KDF_OUT)
    hdr = _v4_pack_header(flags, seed, len(payload), comp, costq, salt)
    pt = struct.pack('<I', crc32(payload)) + bytes(payload)
    body = aead_encrypt(dk[:32], dk[32:44], hdr, pt)
    assert len(body) == comp
    order = v4_candidate_order(pixels, w, h, seed, costq, adaptive)
    if len(order) * 2 < need_slots:
        raise ValueError('payload too large: %d bits need %d slots' %
                         (need_slots, len(order) * 2))
    # One direction space for header slots then body slots (per-slot
    # hash — split calls stay bit-identical with no shared RNG state).
    seed64 = (seed ^ struct.unpack('<I', salt[:4])[0]) & MASK64
    out = list(pixels)
    v4_embed_bits(out, w, list(range(V4_HEADER_PX)), hdr, False, seed64, 0)
    v4_embed_bits(out, w, order, body, robust, seed64, V4_HEADER_LEN * 8)
    # No verify-and-retry: green-invariance makes the decode-side order
    # bit-identical by construction (FORMAT.md 2.4).
    return out


def decode_image_v4(pixels, w, h, password):
    npx = w * h
    if w == 0 or h == 0 or len(pixels) < npx * 3 or npx <= V4_HEADER_PX:
        return None  # truncated/degenerate buffer: fail clean, never OOB
    hdr = v4_read_bits(pixels, w, list(range(V4_HEADER_PX)),
                       V4_HEADER_LEN * 8, False)
    meta = _v4_parse_header(hdr)
    if meta is None or not password:
        return None
    if meta['comp'] * 8 > _v4_slots_avail(npx, bool(meta['flags'] & F_ROBUST)):
        return None
    if isinstance(password, str):
        password = password.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha256', password, meta['salt'],
                             V4_PBKDF2_ITER, V4_KDF_OUT)
    order = v4_candidate_order(pixels, w, h, meta['seed'], meta['costq'],
                               bool(meta['flags'] & F_ADAPTIVE))
    body = v4_read_bits(pixels, w, order, meta['comp'] * 8,
                        bool(meta['flags'] & F_ROBUST))
    pt = aead_decrypt(dk[:32], dk[32:44], hdr, body)
    if pt is None or len(pt) != meta['orig'] + 4:
        return None
    dcrc, payload = struct.unpack('<I', pt[:4])[0], pt[4:]
    if len(payload) != meta['orig'] or crc32(payload) != dcrc:
        return None
    return payload


def decode_auto(pixels, w, h, password=''):
    """Version-dispatched decode: v3 and v4 from one entry point. The two
    envelopes use different header slot maps (v3: RGB sequential, v4: R/B
    only), so probe v3 first (deployed majority, exact legacy path), then
    v4. Both probes are fail-closed (magic + version + CRC decide)."""
    npx = w * h
    if w == 0 or h == 0 or len(pixels) < npx * 3:
        return None
    seq = placement(npx, 0)
    hdr3 = read_bits(pixels, w, h, seq, 0, HEADER_LEN)
    if hdr3[:4] == MAGIC and \
            struct.unpack('<H', hdr3[4:6])[0] == FORMAT_VERSION:
        return decode_image(pixels, w, h, password)
    if npx > V4_HEADER_PX:
        hdr4 = v4_read_bits(pixels, w, list(range(V4_HEADER_PX)),
                            V4_HEADER_LEN * 8, False)
        if hdr4[:4] == MAGIC and \
                struct.unpack('<H', hdr4[4:6])[0] == FORMAT_V4:
            return decode_image_v4(pixels, w, h, password)
    return None
