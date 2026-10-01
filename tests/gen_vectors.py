#!/usr/bin/env python3
"""gen_vectors.py - generate committed golden vectors (deterministic).

Writes tests/vectors/<name>.{rgb,json}: fixed payloads, fixed seeds and
passwords. Any implementation must reproduce these bytes exactly.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
from stegolib import encode_image, encode_image_v4

HERE = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(HERE, 'vectors')

CASES = [
    # (name, w, h, payload_bytes, kwargs) — kwargs may carry version: 4
    ('plain-64', 64, 64, bytes(range(256)) * 2, {}),
    ('scatter-seed7', 64, 64, b'The quick brown fox.0123456789' * 8, {'seed': 7, 'scatter': True}),
    ('enc-pw', 64, 64, b'secret-data-' * 20, {'password': 'test-password-1'}),
    ('full-auth', 96, 96, bytes((i * 7) & 0xFF for i in range(600)),
     {'seed': 424242, 'password': 'correct horse battery staple', 'do_auth': True}),
    ('empty-cover-edge', 32, 40, b'odd-dims-payload-1234', {'seed': 5, 'scatter': True}),
    ('v4-adapt-64', 64, 64, b'v4-adaptive-payload-' * 10,
     {'version': 4, 'seed': 7, 'password': 'v4-test-pw-1', 'adaptive': True,
      'kdf': 'argon2id', 'argon2_m_kib': 32, 'argon2_time': 1}),
    ('v4-nonadapt-64', 64, 64, b'v4-sequential-payload-' * 8,
     {'version': 4, 'seed': 0, 'password': 'v4-test-pw-2', 'adaptive': False,
      'kdf': 'argon2id', 'argon2_m_kib': 32, 'argon2_time': 1}),
    ('v4-robust-96', 96, 96, bytes((i * 13 + 5) & 0xFF for i in range(400)),
     {'version': 4, 'seed': 9, 'password': 'v4-test-pw-3', 'robust': True,
      'kdf': 'argon2id', 'argon2_m_kib': 32, 'argon2_time': 1}),
]


def black(w, h):
    return [0] * (w * h * 3)


def textured(w, h):
    # Deterministic arithmetic texture (exercises v4 cost buckets without
    # any PRNG state to reproduce).
    px = []
    for y in range(h):
        for x in range(w):
            v = (x * 37 + y * 91 + (x // 8) * (y // 8) * 17) % 256
            px += [v, (v * 5 + 13) % 256, (v * 11 + 71) % 256]
    return px


def main():
    os.makedirs(VDIR, exist_ok=True)
    manifest = []
    for name, w, h, payload, kw in CASES:
        kw = dict(kw)
        version = kw.pop('version', 3)
        cover = textured(w, h) if version == 4 else black(w, h)
        if version == 4:
            rgb = encode_image_v4(cover, w, h, payload, **kw)
        else:
            rgb = encode_image(cover, w, h, payload, **kw)
        raw = bytes(rgb)
        fn = f'{name}.rgb'
        with open(os.path.join(VDIR, fn), 'wb') as f:
            f.write(raw)
        entry = {
            'name': name, 'file': fn, 'w': w, 'h': h, 'version': version,
            'payload_sha256': hashlib.sha256(payload).hexdigest(),
            'image_sha256': hashlib.sha256(raw).hexdigest(),
            'kwargs': {k: ('***' if k == 'password' else v) for k, v in kw.items()},
        }
        manifest.append(entry)
        print(f'[vectors] {name}: {len(payload)}B payload, rgb sha256={entry["image_sha256"][:16]}...')
    with open(os.path.join(VDIR, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f'[vectors] {len(manifest)} golden vectors committed')


if __name__ == '__main__':
    main()
