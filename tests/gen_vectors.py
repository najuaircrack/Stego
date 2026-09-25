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
from stegolib import encode_image

HERE = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(HERE, 'vectors')

CASES = [
    # (name, w, h, payload_bytes, kwargs)
    ('plain-64', 64, 64, bytes(range(256)) * 2, {}),
    ('scatter-seed7', 64, 64, b'The quick brown fox.0123456789' * 8, {'seed': 7, 'scatter': True}),
    ('enc-pw', 64, 64, b'secret-data-' * 20, {'password': 'test-password-1'}),
    ('full-auth', 96, 96, bytes((i * 7) & 0xFF for i in range(600)),
     {'seed': 424242, 'password': 'correct horse battery staple', 'do_auth': True}),
    ('empty-cover-edge', 32, 40, b'odd-dims-payload-1234', {'seed': 5, 'scatter': True}),
]


def black(w, h):
    return [0] * (w * h * 3)


def main():
    os.makedirs(VDIR, exist_ok=True)
    manifest = []
    for name, w, h, payload, kw in CASES:
        rgb = encode_image(black(w, h), w, h, payload, **kw)
        raw = bytes(rgb)
        fn = f'{name}.rgb'
        with open(os.path.join(VDIR, fn), 'wb') as f:
            f.write(raw)
        entry = {
            'name': name, 'file': fn, 'w': w, 'h': h,
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
