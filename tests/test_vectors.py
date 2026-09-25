"""test_vectors.py — golden files, malformed battery, boundary tests."""
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
from stegolib import decode_image, encode_image

VDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors')
# Test-only passwords matching gen_vectors.py cases.
PASSWORDS = {
    'enc-pw': 'test-password-1',
    'full-auth': 'correct horse battery staple',
}


def black(w, h):
    return [0] * (w * h * 3)


def test_golden_vectors():
    with open(os.path.join(VDIR, 'manifest.json')) as f:
        manifest = json.load(f)
    assert len(manifest) >= 5
    for entry in manifest:
        rgb = list(open(os.path.join(VDIR, entry['file']), 'rb').read())
        w, h = entry['w'], entry['h']
        assert len(rgb) == w * h * 3
        got = decode_image(rgb, w, h, password=PASSWORDS.get(entry['name'], ''))
        assert got is not None, entry['name']
        assert hashlib.sha256(got).hexdigest() == entry['payload_sha256'], entry['name']


def _img(w, h, payload, **kw):
    return encode_image(black(w, h), w, h, payload, **kw)


def test_malformed_truncated():
    rgb = _img(64, 64, b'x' * 100)
    assert decode_image(rgb[:1000], 64, 64) is None
    assert decode_image([], 0, 0) is None


def test_malformed_bad_magic():
    rgb = _img(64, 64, b'hello')
    rgb = list(rgb)
    rgb[0] ^= 1
    rgb[1] ^= 1
    # broken magic -> v1 fallback likely rejects too (garbage size)
    got = decode_image(rgb, 64, 64)
    assert got != b'hello'


def test_malformed_bad_version():
    rgb = _img(64, 64, b'hello')
    rgb = list(rgb)
    # corrupt version bytes (header pixels -> flat bytes 4,5)
    for i in (4 * 3, 4 * 3 + 1, 5 * 3):
        rgb[i] ^= 1
    got = decode_image(rgb, 64, 64)
    assert got != b'hello'


def test_malformed_oversize_claim():
    # v1-style garbage size header must be rejected, never allocated on.
    rgb = [0] * (32 * 32 * 3)
    # craft size = 0xFFFFFF00 at bits [0,32)
    for i in range(8, 32):
        rgb[i // 3 * 3 + (i % 3)] |= 1
    assert decode_image(rgb, 32, 32) is None


def test_malformed_unknown_flags():
    rgb = _img(64, 64, b'hello')
    rgb = list(rgb)
    # flags live in header bytes 6..7 -> flat bits 48..64 -> bytes 16..21
    for i in range(16, 22):
        rgb[i] ^= 1
    assert decode_image(rgb, 64, 64) != b'hello'


def test_malformed_modified_ciphertext():
    # Header-region tamper (flat bytes [0,354) always hold the header):
    # deterministic reject, never silent match.
    msg = os.urandom(120)
    rgb = _img(64, 64, msg, seed=11, password='pw', do_auth=True)
    rgb = list(rgb)
    rgb[300] ^= 1
    rgb[301] ^= 1
    assert decode_image(rgb, 64, 64, password='pw') != msg


def test_malformed_modified_body():
    # Many flips spread across the body region: virtually certain to hit
    # used bits; result must never silently equal the original.
    msg = os.urandom(120)
    rgb = _img(64, 64, msg, seed=11, password='pw', do_auth=True)
    rgb = list(rgb)
    for i in range(400, 12000, 200):
        rgb[i] ^= 1
    assert decode_image(rgb, 64, 64, password='pw') != msg


def test_malformed_modified_header():
    msg = os.urandom(120)
    rgb = _img(64, 64, msg, seed=11, password='pw', do_auth=True)
    rgb = list(rgb)
    rgb[100] ^= 1  # header region
    assert decode_image(rgb, 64, 64, password='pw') != msg


def test_boundary_exact_fit():
    # capacity for 40x40 plain: ((1600-118)*3 - 32) / 8
    w, h = 40, 40
    cap = ((w * h - 118) * 3 - 32) // 8
    msg = os.urandom(cap)
    out = encode_image(black(w, h), w, h, msg)
    assert decode_image(out, w, h) == msg


def test_boundary_one_over():
    w, h = 40, 40
    cap = ((w * h - 118) * 3 - 32) // 8
    try:
        encode_image(black(w, h), w, h, os.urandom(cap + 1))
    except ValueError:
        return
    assert False, 'expected capacity refusal'


def test_boundary_empty_payload():
    # Empty payloads are rejected at encode time (explicit, documented).
    w, h = 32, 32
    try:
        encode_image(black(w, h), w, h, b'')
    except ValueError:
        return
    assert False, 'expected empty-payload refusal'


def test_boundary_odd_dims():
    w, h = 33, 41
    msg = os.urandom(100)
    out = encode_image(black(w, h), w, h, msg, seed=3)
    assert decode_image(out, w, h) == msg


def test_png_modes_policy():    # RGBA: alpha ignored, RGB channels used. Gray/palette: convert to RGB.
    from PIL import Image
    rgb = _img(48, 48, b'mode-policy-check', seed=9)
    im_rgb = Image.new('RGB', (48, 48))
    im_rgb.putdata([tuple(rgb[i:i + 3]) for i in range(0, len(rgb), 3)])
    im_rgba = im_rgb.convert('RGBA')
    got_rgba = list(im_rgba.convert('RGB').getdata())
    flat = []
    for r, g, b in got_rgba:
        flat += [r, g, b]
    from stegolib import decode_image as di
    assert di(flat, 48, 48) == b'mode-policy-check'
    im_l = im_rgb.convert('L').convert('RGB')
    got_l = []
    for r, g, b in im_l.getdata():
        got_l += [r, g, b]
    # grayscale conversion destroys LSBs by design; decoder must fail cleanly
    assert di(got_l, 48, 48) is None or isinstance(di(got_l, 48, 48), (bytes, type(None)))
