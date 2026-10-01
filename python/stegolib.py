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
F_STC = 0x0040
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


def _v4_kdf(password, salt, kdf_id, kdf_m, kdf_t, kdf_lanes):
    # 96B KDF dispatch (msg-key[0..32) + nonce[32..44) + reserved).
    # Bounds enforced by callers (encode validates options, decode
    # validates header) to cap decoder memory/time on hostile headers.
    if kdf_id == 0:
        if isinstance(password, str):
            password = password.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', password, salt,
                                   V4_PBKDF2_ITER, V4_KDF_OUT)
    if kdf_id == 1:
        return argon2id(password, salt, kdf_t, kdf_m, lanes=kdf_lanes,
                         outlen=V4_KDF_OUT)
    raise ValueError('unknown kdf_id')


# ============================================================================
# Reed-Solomon RS(255,223) over GF(2^8), primitive poly 0x11D (FORMAT.md
# 2.6). Systematic data||parity blocks for the ROBUST framing.
# ============================================================================

_RS_N, _RS_K = 255, 223
_RS_EXP = [0] * 512
_RS_LOG = [0] * 256


def _rs_init():
    x = 1
    for i in range(255):
        _RS_EXP[i] = x
        _RS_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _RS_EXP[i] = _RS_EXP[i - 255]


_rs_init()


def _gf_add(a, b):
    return a ^ b


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _RS_EXP[_RS_LOG[a] + _RS_LOG[b]]


def _gf_div(a, b):
    if a == 0:
        return 0
    if b == 0:
        raise ValueError('gf division by zero')
    return _RS_EXP[(_RS_LOG[a] - _RS_LOG[b]) % 255]


def _gf_poly_mul(p, q):
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a:
            for j, b in enumerate(q):
                out[i + j] ^= _gf_mul(a, b)
    return out


def _rs_generator():
    # g(x) = PRODUCT_{i=0}^{31} (x + alpha^i), degree 32.
    g = [1]
    for i in range(32):
        g = _gf_poly_mul(g, [_RS_EXP[i], 1])
    return g


_RS_GEN = _rs_generator()
assert len(_RS_GEN) == 33 and _RS_GEN[0] != 0
# Long division eliminates from the high-degree end, so it consumes the
# generator high-to-low (GEN[32]=1 zeroes the leading term each step).
_RS_GEN_REV = _RS_GEN[::-1]
assert _RS_GEN_REV[0] == 1


def rs_encode_block(data223):
    """Systematic encode: 223B data -> 255B codeword (data || parity)."""
    if len(data223) != 223:
        raise ValueError('rs block must be 223 bytes')
    data = list(data223) + [0] * 32
    for i in range(223):
        coef = data[i]
        if coef:
            for j in range(33):
                data[i + j] ^= _gf_mul(_RS_GEN_REV[j], coef)
    assert max(data[:223]) == 0  # fully reduced
    return bytes(data223) + bytes(data[223:])


def _rs_syndromes(codeword):
    # S_i = C(alpha^i), C(x) = c_0 x^254 + ... + c_254 (c[0] highest
    # degree, matching the systematic encoder below).
    rev = codeword[::-1]
    syn = []
    for i in range(32):
        a = _RS_EXP[i]
        s, p = 0, 1
        for c in rev:
            s ^= _gf_mul(c, p)
            p = _gf_mul(p, a)
        syn.append(s)
    return syn


def rs_decode_block(codeword):
    """Decode 255B codeword -> 223B data, or None (uncorrectable).
    Berlekamp-Massey + Chien + Forney, errors-only, t=16."""
    if len(codeword) != 255:
        return None
    syn = _rs_syndromes(codeword)
    if max(syn) == 0:
        return bytes(codeword[:223])
    # Berlekamp-Massey: error-locator Lambda (degree <= 16).
    lam, prev = [1], [1]
    L, m, b = 0, 1, 1
    for n in range(32):
        d = syn[n]
        for i in range(1, L + 1):
            d ^= _gf_mul(lam[i] if i < len(lam) else 0, syn[n - i])
        if d == 0:
            m += 1
            continue
        nxt = list(lam) + [0] * m
        coef = _gf_div(d, b)
        while len(nxt) < len(prev) + m:
            nxt.append(0)
        for i in range(len(prev)):
            nxt[i + m] ^= _gf_mul(coef, prev[i])
        if 2 * L <= n:
            L, prev, b, m = n + 1 - L, lam, d, 1
        else:
            m += 1
        if L > 16:
            return None  # beyond t: uncorrectable, fail fast
        lam = nxt
    lam = lam[:L + 1]
    if L == 0 or L > 16:
        return None
    # Chien search: test x = alpha^{-t}; with X_k = alpha^{254-j_k} a hit
    # means t = 254-j_k, i.e. error at codeword j = 254-t.
    errs = []
    for t in range(255):
        x = _RS_EXP[(255 - t) % 255]  # alpha^{-t}
        y, p = 0, 1
        for c in lam:
            y ^= _gf_mul(c, p)
            p = _gf_mul(p, x)
        if y == 0:
            errs.append(t)
    if len(errs) != L:
        return None
    # Forney magnitudes.
    omega = [0] * 32
    for i in range(min(len(lam), 32)):
        s = 0
        for j in range(i + 1):
            if j < len(lam) and i - j < 32:
                s ^= _gf_mul(lam[j], syn[i - j])
        omega[i] = s
    out = bytearray(codeword)
    for t in errs:
        j = 254 - t
        x = _RS_EXP[t]  # X_k = alpha^{254-j} = alpha^{t}
        # Lambda'(x^{-1}): formal derivative, odd terms: lam[i]*xi^{i-1}.
        den = 0
        xi = _gf_div(1, x)
        xp = 1
        for i in range(1, len(lam), 2):
            den ^= _gf_mul(lam[i], xp)
            xp = _gf_mul(_gf_mul(xp, xi), xi)
        if den == 0:
            return None
        num, p = 0, 1
        for c in omega:
            num ^= _gf_mul(c, p)
            p = _gf_mul(p, xi)
        # Forney (narrow-sense, b=0): e = X * Omega(X^-1) / Lambda'(X^-1).
        out[j] ^= _gf_mul(num, _gf_div(x, den))
    if max(_rs_syndromes(bytes(out))) != 0:
        return None  # miscorrection guard: recheck syndromes
    return bytes(out[:223])


def _b2b(data, outlen):
    import hashlib as _hl
    h = _hl.blake2b(digest_size=outlen)
    h.update(data)
    return h.digest()


def _hprime(data, outlen):
    # RFC 9106 Fig.8: BOTH branches prepend LE32(outlen) — the T<=64
    # branch is H^T(LE32(T)||A), not bare H^T(A).
    if outlen <= 64:
        return _b2b(struct.pack('<I', outlen) + data, outlen)
    r = (outlen + 31) // 32 - 2
    v = _b2b(struct.pack('<I', outlen) + data, 64)
    out = bytearray(v[:32])
    for _ in range(1, r):
        v = _b2b(v, 64)
        out += v[:32]
    out += _b2b(v, outlen - 32 * r)
    return bytes(out)


def _rotr64_py(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64


def _gb_py(a, b, c, d):
    # RFC 9106 Fig.19 (Blamka GB with multiplies — NOT plain Blake2b G).
    m = MASK64
    t = lambda v: v & 0xFFFFFFFF
    a = (a + b + 2 * t(a) * t(b)) & m
    d = _rotr64_py(d ^ a, 32)
    c = (c + d + 2 * t(c) * t(d)) & m
    b = _rotr64_py(b ^ c, 24)
    a = (a + b + 2 * t(a) * t(b)) & m
    d = _rotr64_py(d ^ a, 16)
    c = (c + d + 2 * t(c) * t(d)) & m
    b = _rotr64_py(b ^ c, 63)
    return a, b, c, d


def _permute_p_py(v):
    v[0], v[4], v[8], v[12] = _gb_py(v[0], v[4], v[8], v[12])
    v[1], v[5], v[9], v[13] = _gb_py(v[1], v[5], v[9], v[13])
    v[2], v[6], v[10], v[14] = _gb_py(v[2], v[6], v[10], v[14])
    v[3], v[7], v[11], v[15] = _gb_py(v[3], v[7], v[11], v[15])
    v[0], v[5], v[10], v[15] = _gb_py(v[0], v[5], v[10], v[15])
    v[1], v[6], v[11], v[12] = _gb_py(v[1], v[6], v[11], v[12])
    v[2], v[7], v[8], v[13] = _gb_py(v[2], v[7], v[8], v[13])
    v[3], v[4], v[9], v[14] = _gb_py(v[3], v[4], v[9], v[14])


def _compress_g_py(x, y):
    r = [(a ^ b) & MASK64 for a, b in
         zip(struct.unpack('<128Q', x), struct.unpack('<128Q', y))]
    q = list(r)
    for row in range(8):
        w = q[row * 16:(row + 1) * 16]
        _permute_p_py(w)
        q[row * 16:(row + 1) * 16] = w
    z = [0] * 128
    for col in range(8):
        # column c = registers c, c+8, ..., c+56 (each = 2 words)
        w = []
        for i in range(8):
            k = col + 8 * i
            w += [q[2 * k], q[2 * k + 1]]
        _permute_p_py(w)
        for i in range(8):
            k = col + 8 * i
            z[2 * k], z[2 * k + 1] = w[2 * i], w[2 * i + 1]
    return struct.pack('<128Q', *[((a ^ b) & MASK64)
                                  for a, b in zip(z, r)])


def argon2id(password, salt, passes, mem_kib, lanes=1, outlen=96,
              secret=b'', ad=b'', _return_mem=False):
    """Argon2id (RFC 9106, v=0x13). Pure Python reference — correct at any
    params, slow at production memory (see docs: production validation is
    C++-side; KDF agility bounds decoder cost). _return_mem=True also
    returns the block list (test hook for RFC intermediate blocks)."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    if lanes < 1 or outlen < 16:
        raise ValueError('bad argon2id params')
    if mem_kib < 8 * lanes:
        raise ValueError('memory below 8*p KiB')
    h0in = struct.pack('<IIIIII', lanes, outlen, mem_kib, passes, 0x13, 2)
    h0in += struct.pack('<I', len(password)) + password
    h0in += struct.pack('<I', len(salt)) + salt
    h0in += struct.pack('<I', len(secret)) + secret
    h0in += struct.pack('<I', len(ad)) + ad
    h0 = _b2b(h0in, 64)
    mprime = 4 * lanes * (mem_kib // (4 * lanes))
    q = mprime // lanes
    seglen = q // 4
    mem = [None] * (lanes * q)

    def init_block(extra0, extra1, lane):
        return _hprime(h0 + struct.pack('<II', extra0, lane), 1024)

    for lane in range(lanes):
        mem[lane * q + 0] = init_block(0, 0, lane)
        mem[lane * q + 1] = init_block(1, 1, lane)
    zero = bytes(1024)
    snaps = []
    for r in range(passes):
        for sl in range(4):
            for lane in range(lanes):
                indep = (r == 0 and sl < 2)
                addr_vals = []  # positional: block j consumes vals[j]
                addr_ctr = 0
                if indep:
                    zin = struct.pack('<6Q', r, lane, sl, mprime, passes, 2)
                j0 = 2 if (r == 0 and sl == 0) else 0
                for j in range(j0, seglen):
                    c = sl * seglen + j
                    # Previous block: absolute (c-1) mod q, universally.
                    # (For pass>0 slice>0 j=0 this is the previous slice's
                    # last block, NOT the lane's last block.)
                    pc = (c - 1) % q
                    prev = mem[lane * q + pc]
                    if indep:
                        while len(addr_vals) <= j:
                            addr_ctr += 1
                            ib = zin + struct.pack('<Q', addr_ctr) + bytes(968)
                            inner = _compress_g_py(zero, ib)
                            blk = _compress_g_py(zero, inner)
                            addr_vals += struct.unpack('<128Q', blk)
                        v = addr_vals[j]
                        J1, J2 = v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF
                    else:
                        J1 = struct.unpack('<I', prev[0:4])[0]
                        J2 = struct.unpack('<I', prev[4:8])[0]
                    if r == 0 and sl == 0:
                        l = lane
                    else:
                        l = J2 % lanes
                    if l == lane:
                        area = (sl * seglen + j - 1) if r == 0 else \
                            (3 * seglen + j - 1)
                        start = (c - 1 - area) % q
                    else:
                        # Other lanes reference FINISHED segments only
                        # (never the current segment): run ends at E.
                        E = (sl * seglen - 1) % q  # most recent finished
                        if r == 0:
                            area = sl * seglen + (-1 if j == 0 else 0)
                        else:
                            area = 3 * seglen + (-1 if j == 0 else 0)
                        Ep = (E - 1) % q if j == 0 else E
                        start = (Ep - area + 1) % q
                    if area <= 0:
                        raise ValueError('degenerate reference area')
                    x = (J1 * J1) >> 32
                    y = (area * x) >> 32
                    zz = area - 1 - y
                    ref = mem[l * q + (start + zz) % q]
                    new = _compress_g_py(prev, ref)
                    if r == 0:
                        mem[lane * q + c] = new
                    else:
                        mem[lane * q + c] = bytes(a ^ b for a, b in
                                                 zip(new, mem[lane * q + c]))
        if _return_mem:
            snaps.append(list(mem))
    C = bytearray(1024)
    for lane in range(lanes):
        blk = mem[lane * q + q - 1]
        for i in range(1024):
            C[i] ^= blk[i]
    tag = _hprime(bytes(C), outlen)
    if _return_mem:
        return tag, snaps
    return tag


def _mirror_idx(i, n):
    while i < 0 or i >= n:
        i = -i if i < 0 else 2 * (n - 1) - i
    return i


def _dwt53_1d(a):
    # In-place integer 5/3 lifting (JPEG2000), symmetric extension.
    # Predict odds from ORIGINAL evens, then update evens from predicted
    # odds. Python // floors (matches portable FDiv in the C++ port).
    n = len(a)
    x = list(a)
    for i in range(1, n, 2):
        x[i] = x[i] - ((x[_mirror_idx(i - 1, n)] +
                         x[_mirror_idx(i + 1, n)]) // 2)
    for i in range(0, n, 2):
        x[i] = x[i] + ((x[_mirror_idx(i - 1, n)] +
                         x[_mirror_idx(i + 1, n)] + 2) // 4)
    return x


def v4_costs(pixels, w, h):
    """S-UNIWARD-style cost (FORMAT.md 2.4 rule 1): 5/3-lifting wavelet
    residual energy of GREEN, exact integers. LL zeroed; 3x3 window sums
    with mirrored borders. Green is never written, so decode-side costs
    equal encode-side costs bit-exact."""
    g = [pixels[3 * i + 1] for i in range(w * h)]
    t = []
    for y in range(h):
        t += _dwt53_1d(g[y * w:(y + 1) * w])
    for x in range(w):
        col = _dwt53_1d([t[y * w + x] for y in range(h)])
        for y in range(h):
            t[y * w + x] = col[y]
    mag = [0] * (w * h)
    for y in range(h):
        for x in range(w):
            if x % 2 == 1 or y % 2 == 1:
                mag[y * w + x] = abs(t[y * w + x])
    cost = [0] * (w * h)
    for y in range(h):
        for x in range(w):
            s = 0
            for dy in (-1, 0, 1):
                yy = _mirror_idx(y + dy, h)
                for dx in (-1, 0, 1):
                    s += mag[yy * w + _mirror_idx(x + dx, w)]
            cost[y * w + x] = s
    return cost


def v4_bucket(cost, q):
    """Bucket index per FORMAT.md 2.4 rule 2. Integer-only. No skip rule:
    every pixel is a candidate; stability comes from green-invariance."""
    lb = cost.bit_length()
    return q - 1 if q <= 1 else min(q - 1, (lb * q) >> 4)


def _v4_order_costs(pixels, w, h, seed, costq, adaptive):
    """(order, costs): candidate pixel order + per-position flip cost
    (Q - bucket, 1 = cheapest texture). Non-adaptive: uniform cost 1.
    Single source for greedy and STC paths."""
    npx = w * h
    if not adaptive:
        order = placement_range(V4_HEADER_PX, npx - V4_HEADER_PX, seed)
        return order, [1] * len(order)
    costs = v4_costs(pixels, w, h)
    buckets = {}
    for i in range(V4_HEADER_PX, npx):
        buckets.setdefault(v4_bucket(costs[i], costq), []).append(i)
    order, bcost = [], []
    for b in sorted(buckets.keys(), reverse=True):
        members = sorted(buckets[b])
        r = Xor128((seed ^ ((b + 1) * 0x9E3779B97F4A7C15)) & MASK64)
        for i in range(len(members) - 1, 0, -1):
            j = r.next() % (i + 1)
            members[i], members[j] = members[j], members[i]
        order.extend(members)
        bcost.extend([costq - b] * len(members))
    return order, bcost


def v4_candidate_order(pixels, w, h, seed, costq, adaptive):
    """Pixel indices carrying body stream slots (header pixels excluded).
    Pure function of (green costs, seed, costq, adaptive) — the decoder
    reproduces it bit-exact from the stego image."""
    order, _ = _v4_order_costs(pixels, w, h, seed, costq, adaptive)
    return order


STC_H = 7  # constraint height (128 trellis states)


def _stc_submatrix(seed):
    # S[0] = 1 (properness: every message bit involves its leading
    # position); S[1..h] from Xor128 keystream LSB-first.
    r = Xor128((seed ^ 0x535443) & MASK64)
    return [1] + [r.next() & 1 for _ in range(STC_H)]


def stc_encode(cover_bits, costs, msg_bytes, sub):
    """Viterbi STC: minimum-cost flips carrying msg_bits in the LSBs.
    cover_bits/costs: length n = M + h. Returns flips list (0/1).
    Integer metrics (exact, no float ties)."""
    h = len(sub) - 1
    msg = [(msg_bytes[i // 8] >> (i % 8)) & 1
           for i in range(len(msg_bytes) * 8)]
    nstates = 1 << h
    mask = nstates - 1
    # Cf[s][f]: flip-dependent part of the syndrome bit.
    cf = [[0, 0] for _ in range(nstates)]
    for s in range(nstates):
        for f in (0, 1):
            v = 0
            for k in range(h):
                if sub[k] and (s >> k) & 1:
                    v ^= 1
            if sub[h] and f:
                v ^= 1
            cf[s][f] = v
    n = len(cover_bits)
    M = len(msg)
    # Cover syndrome per message position (message-independent part).
    cx = [0] * M
    for j in range(M):
        v = 0
        for k in range(h + 1):
            if sub[k] and cover_bits[j + k]:
                v ^= 1
        cx[j] = v
    INF = 1 << 62
    cur = [INF] * nstates
    cur[0] = 0
    prev = [bytearray(nstates) for _ in range(n)]
    for i in range(n):
        nxt = [INF] * nstates
        for s in range(nstates):
            base = cur[s]
            if base >= INF:
                continue
            for f in (0, 1):
                if i >= h:
                    j = i - h
                    if j >= M or (cx[j] ^ cf[s][f]) != msg[j]:
                        continue
                ns = ((s >> 1) | (f << (h - 1))) & mask
                nm = base + (costs[i] if f else 0)
                if nm < nxt[ns]:
                    nxt[ns] = nm
                    prev[i][ns] = s
        cur = nxt
    best = min(range(nstates), key=lambda s: cur[s])
    if cur[best] >= INF:
        return None  # no valid path (should not happen with S[0]=1)
    flips = [0] * n
    s = best
    for i in range(n - 1, -1, -1):
        f = (s >> (h - 1)) & 1 if h > 0 else 0
        flips[i] = f
        s = prev[i][s]
    return flips


def stc_extract(stego_bits, sub, mlen):
    """Syndromes from stego LSBs: m[j] = XOR_k S[k]*y[j+k]."""
    h = len(sub) - 1
    out = bytearray((mlen + 7) // 8)
    for j in range(mlen):
        v = 0
        for k in range(h + 1):
            if sub[k] and stego_bits[j + k]:
                v ^= 1
        if v:
            out[j // 8] |= (1 << (j % 8))
    return bytes(out)


def _v4_slot(order, s):
    """Slot s -> flat channel index. Slots use RED/BLUE only (green is
    never written): candidate pixel order[s//2], R if s even else B."""
    return order[s // 2] * 3 + (0 if s % 2 == 0 else 2)


def _v4_apply_flips(px, w, order, flips, seed64, slot_base):
    # Realize an STC flip pattern via +/-1 (saturation-safe; every f=1
    # flips its LSB by construction).
    for s, f in enumerate(flips):
        if not f:
            continue
        ch = _v4_slot(order, s)
        v = px[ch]
        if v == 0:
            v = 1
        elif v == 255:
            v = 254
        else:
            v += 1 if _v4_dirbit(seed64, slot_base + s) else -1
        px[ch] = v


def _v4_dirbit(seed64, s):
    """Direction bit for global slot s (FORMAT.md 2.5). Stateless
    SplitMix-finalize — no shared RNG state across header/body calls."""
    z = (seed64 ^ ((s * 0x9E3779B97F4A7C15) & MASK64)) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    z = (z ^ (z >> 31)) & MASK64
    return (z >> 32) & 1


def v4_embed_bits(px, w, order, bits, seed64, slot_base):
    """Ternary +/-1 embed (FORMAT.md 2.5) over the R/B slot stream.
    `slot_base` is the global slot number of bits[0] (0 for the header,
    512 for the body) — directions are per-slot-hashed, so split calls
    stay bit-identical with no shared RNG state."""
    slots = 0
    bi = 0
    nbits = len(bits) * 8
    while bi < nbits:
        b = (bits[bi // 8] >> (bi % 8)) & 1
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


def v4_read_bits(pixels, w, order, nbits):
    out = bytearray((nbits + 7) // 8)
    for bi in range(nbits):
        if pixels[_v4_slot(order, bi)] & 1:
            out[bi // 8] |= (1 << (bi % 8))
    return bytes(out)


def _v4_pack_header(flags, seed, orig, comp, costq, salt, kdf_id=0,
                   kdf_m=0, kdf_t=0, kdf_lanes=0):
    hdr = bytearray(MAGIC)
    hdr += struct.pack('<H', FORMAT_V4)
    hdr += struct.pack('<H', flags)
    hdr += struct.pack('<I', seed)
    hdr += struct.pack('<I', orig)
    hdr += struct.pack('<I', comp)
    hdr += struct.pack('<I', costq)
    hdr += salt
    hdr += struct.pack('<I', kdf_id)
    hdr += struct.pack('<I', crc32(bytes(hdr)))
    hdr += struct.pack('<III', kdf_m, kdf_t, kdf_lanes)
    hdr += struct.pack('<I', 0)
    assert len(hdr) == V4_HEADER_LEN
    return bytes(hdr)


def _rs_protect(data):
    """RS framing (FORMAT.md 2.6): pad to 223B blocks, encode, interleave.
    Returns (stream bytes, nblocks). comp_size = nblocks*255."""
    nblocks = (len(data) + 222) // 223
    padded = data + b'\x00' * (nblocks * 223 - len(data))
    cws = [rs_encode_block(padded[i * 223:(i + 1) * 223])
           for i in range(nblocks)]
    stream = bytes(cws[s % nblocks][s // nblocks]
                   for s in range(nblocks * 255))
    return stream, nblocks


def _rs_unprotect(stream, nblocks):
    """Inverse framing: de-interleave + decode each block (None on any
    undecodable block). Returns concatenated data parts (with padding)."""
    if len(stream) != nblocks * 255:
        return None
    parts = []
    for b in range(nblocks):
        cw = bytes(stream[b + k * nblocks] for k in range(255))
        d = rs_decode_block(cw)
        if d is None:
            return None
        parts.append(d)
    return b''.join(parts)    # Returns 96B (msg-key[0..32) + nonce[32..44) + reserved). Bounds
    # enforced by callers (encode validates options, decode validates
    # header) to cap decoder memory/time on hostile headers.
    if kdf_id == 0:
        if isinstance(password, str):
            password = password.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', password, salt,
                                   V4_PBKDF2_ITER, V4_KDF_OUT)
    if kdf_id == 1:
        return argon2id(password, salt, kdf_t, kdf_m, lanes=kdf_lanes,
                         outlen=V4_KDF_OUT)
    raise ValueError('unknown kdf_id')


def _v4_parse_header(hdr):
    if len(hdr) != V4_HEADER_LEN or hdr[:4] != MAGIC:
        return None
    ver, flags = struct.unpack('<H', hdr[4:6])[0], struct.unpack('<H', hdr[6:8])[0]
    seed, orig, comp, costq = struct.unpack('<IIII', hdr[8:24])
    salt = hdr[24:40]
    kdf_id = struct.unpack('<I', hdr[40:44])[0]
    hcrc = struct.unpack('<I', hdr[44:48])[0]
    kdf_m, kdf_t, kdf_lanes = struct.unpack('<III', hdr[48:60])
    if ver != FORMAT_V4 or crc32(hdr[:44]) != hcrc:
        return None
    if flags & F_COMPRESS:
        return None
    if not (flags & F_ENCRYPT) or not (flags & F_AUTH):
        return None  # v4 is always encrypted + authenticated
    if not (1 <= costq <= 16) or orig < 1:
        return None
    if flags & F_ROBUST:
        nblocks = (orig + 20 + 222) // 223
        if comp != nblocks * 255:
            return None
    elif comp != orig + 4 + V4_TAG_LEN:
        return None
    if kdf_id == 0:
        if kdf_m != 0 or kdf_t != 0 or kdf_lanes != 0:
            return None
    elif kdf_id == 1:
        if not (8 <= kdf_m <= 1048576) or not (1 <= kdf_t <= 16) or \
                kdf_lanes != 1:
            return None
    else:
        return None
    return {'flags': flags, 'seed': seed, 'orig': orig, 'comp': comp,
            'costq': costq, 'salt': salt, 'kdf_id': kdf_id, 'kdf_m': kdf_m,
            'kdf_t': kdf_t, 'kdf_lanes': kdf_lanes}


def _v4_slots_avail(npx):
    return 2 * max(0, npx - V4_HEADER_PX)  # R/B channels only


def encode_image_v4(pixels, w, h, payload, password, seed=None, adaptive=True,
                    robust=False, costq=V4_COSTQ_DEFAULT, scatter=True,
                    kdf='argon2id', argon2_m_kib=65536, argon2_time=3,
                    stc=True):
    """v4 encode. Returns new flat pixel list. Password REQUIRED in v4.
    kdf: 'argon2id' (default, memory-hard) or 'pbkdf2' (fast, constrained
    decoders). Argon2id production params: m=65536 KiB, t=3, lanes=1.
    stc: syndrome-trellis coding (default on; off = greedy +/-1)."""
    if not payload:
        raise ValueError('empty payload refused (explicit, documented)')
    if not password:
        raise ValueError('v4 requires a password (ENCRYPT+AUTH always on)')
    if not (1 <= costq <= 16):
        raise ValueError('costq out of range 1..16')
    if kdf in ('argon2id', 1):
        kdf_id, kdf_m, kdf_t, kdf_lanes = 1, argon2_m_kib, argon2_time, 1
        if not (8 <= kdf_m <= 1048576) or not (1 <= kdf_t <= 16):
            raise ValueError('argon2 params out of range')
    elif kdf in ('pbkdf2', 0):
        kdf_id, kdf_m, kdf_t, kdf_lanes = 0, 0, 0, 0
    else:
        raise ValueError('unknown kdf (argon2id|pbkdf2)')
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
    if stc:
        flags |= F_STC
    comp = len(payload) + 4 + V4_TAG_LEN
    if robust:
        # RS framing first (FORMAT.md 2.6): comp becomes codeword bytes.
        nblocks = (comp + 222) // 223
        comp = nblocks * 255
    need_slots = comp * 8

    salt = os.urandom(SALT_LEN)
    dk = _v4_kdf(password, salt, kdf_id, kdf_m, kdf_t, kdf_lanes)
    hdr = _v4_pack_header(flags, seed, len(payload), comp, costq, salt,
                          kdf_id, kdf_m, kdf_t, kdf_lanes)
    pt = struct.pack('<I', crc32(payload)) + bytes(payload)
    body = aead_encrypt(dk[:32], dk[32:44], hdr, pt)
    assert len(body) == len(payload) + 4 + V4_TAG_LEN
    if robust:
        body, _ = _rs_protect(body)
        assert len(body) == comp
    order, ocosts = _v4_order_costs(pixels, w, h, seed, costq, adaptive)
    need_slots = comp * 8 + (STC_H if stc else 0)
    if len(order) * 2 < need_slots:
        raise ValueError('payload too large: %d bits need %d slots' %
                         (need_slots, len(order) * 2))
    # One direction space for header slots then body slots (per-slot
    # hash — split calls stay bit-identical with no shared RNG state).
    seed64 = (seed ^ struct.unpack('<I', salt[:4])[0]) & MASK64
    out = list(pixels)
    v4_embed_bits(out, w, list(range(V4_HEADER_PX)), hdr, seed64, 0)
    if stc:
        sub = _stc_submatrix(seed)
        M = comp * 8
        n = M + STC_H
        cover_bits = [(pixels[_v4_slot(order, s)] & 1) for s in range(n)]
        slot_costs = [ocosts[s // 2] for s in range(n)]
        flips = stc_encode(cover_bits, slot_costs, body, sub)
        if flips is None:
            raise ValueError('STC found no valid flip pattern')
        _v4_apply_flips(out, w, order, flips, seed64, V4_HEADER_LEN * 8)
    else:
        v4_embed_bits(out, w, order, body, seed64, V4_HEADER_LEN * 8)
    # No verify-and-retry: green-invariance makes the decode-side order
    # bit-identical by construction (FORMAT.md 2.4).
    return out


def decode_image_v4(pixels, w, h, password):
    npx = w * h
    if w == 0 or h == 0 or len(pixels) < npx * 3 or npx <= V4_HEADER_PX:
        return None  # truncated/degenerate buffer: fail clean, never OOB
    hdr = v4_read_bits(pixels, w, list(range(V4_HEADER_PX)),
                       V4_HEADER_LEN * 8)
    meta = _v4_parse_header(hdr)
    if meta is None or not password:
        return None
    if meta['comp'] * 8 > _v4_slots_avail(npx):
        return None
    if isinstance(password, str):
        password = password.encode('utf-8')
    dk = _v4_kdf(password, meta['salt'], meta['kdf_id'], meta['kdf_m'],
                 meta['kdf_t'], meta['kdf_lanes'])
    order = v4_candidate_order(pixels, w, h, meta['seed'], meta['costq'],
                               bool(meta['flags'] & F_ADAPTIVE))
    if meta['flags'] & F_STC:
        n = meta['comp'] * 8 + STC_H
        yb = v4_read_bits(pixels, w, order, n)
        y = [(yb[i // 8] >> (i % 8)) & 1 for i in range(n)]
        sub = _stc_submatrix(meta['seed'])
        body = stc_extract(y, sub, meta['comp'] * 8)
    else:
        body = v4_read_bits(pixels, w, order, meta['comp'] * 8)
    if meta['flags'] & F_ROBUST:
        nblocks = meta['comp'] // 255
        cat = _rs_unprotect(body, nblocks)
        if cat is None:
            return None
        body = cat[:meta['orig'] + 4 + V4_TAG_LEN]  # strip RS padding
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
                            V4_HEADER_LEN * 8)
        if hdr4[:4] == MAGIC and \
                struct.unpack('<H', hdr4[4:6])[0] == FORMAT_V4:
            return decode_image_v4(pixels, w, h, password)
    return None
