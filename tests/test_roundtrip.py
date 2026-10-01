#!/usr/bin/env python3
"""test_roundtrip.py - pytest matrix: python self-round-trips + C++ cross-impl.

CROSS_IMPL requires --harness <path-to-stego_harness>.
SHA-256 goldens pin the vendored implementation (NIST vectors).
"""
import hashlib
import os
import struct
import subprocess
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
from stegolib import (crc32, decode_image, encode_image,
                      placement, placement_range, decode_image_v4,
                      encode_image_v4, v4_candidate_order)


def black(w, h):
    return [0] * (w * h * 3)


def test_sha256_nist():
    assert hashlib.sha256(b'').hexdigest() == \
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    assert hashlib.sha256(b'abc').hexdigest() == \
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    # cross-check vendored C++ via harness in test_cross_* (decode path)


def test_crc32_vectors():
    assert crc32(b'') == 0
    assert crc32(b'123456789') == 0xCBF43926


def test_plain_roundtrip():
    w, h = 64, 64
    msg = bytes(range(256)) * 3
    out = encode_image(black(w, h), w, h, msg)
    assert decode_image(out, w, h) == msg


def test_scatter_roundtrip():
    w, h = 64, 64
    msg = os.urandom(500)
    out = encode_image(black(w, h), w, h, msg, seed=12345)
    assert decode_image(out, w, h) == msg


def test_encrypt_auth_roundtrip():
    w, h = 64, 64
    msg = os.urandom(300)
    out = encode_image(black(w, h), w, h, msg, seed=999,
                       password='correct horse', do_auth=True)
    assert decode_image(out, w, h, password='correct horse') == msg
    assert decode_image(out, w, h, password='wrong') is None
    assert decode_image(out, w, h) is None


def test_tamper_rejected():
    w, h = 64, 64
    msg = os.urandom(200)
    out = encode_image(black(w, h), w, h, msg, seed=7,
                       password='pw', do_auth=True)
    out = list(out)
    # Flip header-region LSBs (pixels [0,118) always hold the header):
    # decode must fail, never silently match.
    out[10] ^= 1
    out[11] ^= 1
    got = decode_image(out, w, h, password='pw')
    assert got != msg  # rejected (None) or detectably corrupt


def test_placement_golden():
    # Pins the PRNG (xorshift128+/splitmix64/Fisher-Yates) across impls.
    p = placement_range(75, 100, 12345)
    assert len(p) == 100 and sorted(p) == list(range(75, 175))
    assert p != list(range(75, 175))  # actually shuffled
    assert placement(10, 0) == list(range(10))  # seed 0 = identity


def test_v4_roundtrips():
    # Small Argon2id params (fast); production params covered by
    # test_codec (C++) + envelope interop below. KDF choice is orthogonal
    # to placement: distortion statistics don't depend on it.
    w, h = 64, 64
    msg = os.urandom(200)
    kw = {'kdf': 'argon2id', 'argon2_m_kib': 32, 'argon2_time': 1}
    out = encode_image_v4(black(w, h), w, h, msg, 'pw4', seed=7,
                          adaptive=True, **kw)
    assert decode_image_v4(out, w, h, 'pw4') == msg
    assert decode_image_v4(out, w, h, 'wrong') is None
    out = encode_image_v4(black(w, h), w, h, msg, 'pw4', seed=0,
                          adaptive=False, **kw)
    assert decode_image_v4(out, w, h, 'pw4') == msg
    out = encode_image_v4(black(w, h), w, h, msg, 'pw4', seed=9,
                          robust=True, **kw)
    assert decode_image_v4(out, w, h, 'pw4') == msg


def test_v4_order_covers_once():
    # Adaptive order over a textured cover: every pixel >= 256 exactly
    # once (permutation — the decoder's reproduction premise).
    w, h = 64, 64
    flat = []
    for y in range(h):
        for x in range(w):
            v = (x * 37 + y * 91) % 256
            flat += [v, (v * 5 + 13) % 256, (v * 11 + 71) % 256]
    order = v4_candidate_order(flat, w, h, 7, 8, True)
    assert sorted(order) == list(range(256, w * h))
    # green untouched by a full-capacity-ish embed
    msg = os.urandom(400)
    out = encode_image_v4(flat, w, h, msg, 'pw4', seed=7,
                          kdf='argon2id', argon2_m_kib=32, argon2_time=1)
    assert [out[i] for i in range(len(out)) if i % 3 == 1] == \
           [flat[i] for i in range(len(flat)) if i % 3 == 1]


def test_cross_v4_pyenc_cdec(tmp_path):
    # Textured cover: C++ must reproduce Python's cost/bucket/order
    # exactly to decode (black covers would only exercise the shuffle).
    hx = _harness()
    w, h = 64, 64
    msg = os.urandom(200)
    flat = []
    for y in range(h):
        for x in range(w):
            v = (x * 37 + y * 91) % 256
            flat += [v, (v * 5 + 13) % 256, (v * 11 + 71) % 256]
    rgb = encode_image_v4(flat, w, h, msg, 'xpw', seed=7,
                          kdf='argon2id', argon2_m_kib=32, argon2_time=1)
    raw = tmp_path / 'v4c.rgb'
    raw.write_bytes(bytes(rgb))
    out = tmp_path / 'o.bin'
    r = subprocess.run([hx, 'dec', str(w), str(h), 'xpw', str(raw),
                        str(out)])
    assert r.returncode == 0
    assert out.read_bytes() == msg


def test_cross_v4_cenc_pydec(tmp_path):
    hx = _harness()
    w, h = 64, 64
    msg = os.urandom(200)
    src = tmp_path / 'p.bin'
    src.write_bytes(msg)
    raw = tmp_path / 'v4e.rgb'
    r = subprocess.run([hx, 'enc4', str(w), str(h), '7', 'xpw', '1', '0',
                        '8', '1', '1', '32', '1', str(src), str(raw)])
    assert r.returncode == 0
    rgb = list(raw.read_bytes())
    assert decode_image_v4(rgb, w, h, 'xpw') == msg


def test_cross_v4_cenc_pydec_nostc(tmp_path):
    # Greedy path cross-check (STC off both sides).
    hx = _harness()
    w, h = 64, 64
    msg = os.urandom(200)
    src = tmp_path / 'p.bin'
    src.write_bytes(msg)
    raw = tmp_path / 'v4g.rgb'
    r = subprocess.run([hx, 'enc4', str(w), str(h), '7', 'xpw', '1', '0',
                        '8', '0', '1', '32', '1', str(src), str(raw)])
    assert r.returncode == 0
    rgb = list(raw.read_bytes())
    assert decode_image_v4(rgb, w, h, 'xpw') == msg


def test_cross_v4_kdf0(tmp_path):
    # Legacy PBKDF2 path interop both directions (kdf_id 0).
    hx = _harness()
    w, h = 64, 64
    msg = os.urandom(200)
    rgb = encode_image_v4(black(w, h), w, h, msg, 'xpw', seed=7,
                          kdf='pbkdf2')
    raw = tmp_path / 'v4k.rgb'
    raw.write_bytes(bytes(rgb))
    out = tmp_path / 'o.bin'
    r = subprocess.run([hx, 'dec', str(w), str(h), 'xpw', str(raw),
                        str(out)])
    assert r.returncode == 0
    assert out.read_bytes() == msg


def _harness():
    import pytest
    path = os.environ.get('STEGO_HARNESS', '')
    if not path or not os.path.exists(path):
        pytest.skip('set STEGO_HARNESS to stego_harness exe')
    return path


def _amalgam():
    import pytest
    path = os.environ.get('STEGO_AMALGAM', '')
    if not path or not os.path.exists(path):
        pytest.skip('set STEGO_AMALGAM to stego_amalgam exe')
    return path


def test_amalgam_identity(tmp_path):
    # Split-lib build and single-header build must emit identical bytes.
    hx = _harness()
    am = _amalgam()
    w, h = 48, 48
    msg = os.urandom(200)
    src = tmp_path / 'p.bin'
    src.write_bytes(msg)
    r1 = tmp_path / 'split.rgb'
    r2 = tmp_path / 'amal.rgb'
    for exe, out in ((hx, r1), (am, r2)):
        r = subprocess.run([exe, 'enc', str(w), str(h), '4242', '-', '0',
                            str(src), str(out)])
        assert r.returncode == 0
    assert r1.read_bytes() == r2.read_bytes()


def _rgb(path, w, h, data=None):
    if data is None:
        return [0] * (w * h * 3)
    return list(data)


def test_cross_pyenc_cdec(tmp_path):
    hx = _harness()
    w, h = 48, 48
    msg = os.urandom(200)
    rgb = encode_image(black(w, h), w, h, msg, seed=4242)
    raw = tmp_path / 'c.rgb'
    raw.write_bytes(bytes(rgb))
    out = tmp_path / 'o.bin'
    r = subprocess.run([hx, 'dec', str(w), str(h), '-', str(raw), str(out)])
    assert r.returncode == 0
    assert out.read_bytes() == msg


def test_cross_cenc_pydec(tmp_path):
    hx = _harness()
    w, h = 48, 48
    msg = os.urandom(200)
    src = tmp_path / 'p.bin'
    src.write_bytes(msg)
    raw = tmp_path / 'c.rgb'
    r = subprocess.run([hx, 'enc', str(w), str(h), '4242', '-', '0',
                        str(src), str(raw)])
    assert r.returncode == 0
    rgb = list(raw.read_bytes())
    assert decode_image(rgb, w, h) == msg
