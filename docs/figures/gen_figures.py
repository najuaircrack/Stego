#!/usr/bin/env python3
"""Generate docs/figures/*.png (deterministic, reproducible).

Real adaptive-placement output on a synthetic photographic-style cover
(smooth sky + textured ground + hard shapes), using the exact integer
cost math from python/stegolib.py (imported, not duplicated).

Outputs:
  cost_buckets.png      bucket map (8 colors; wet pixels dark) + legend
  selection_overlay.png dimmed cover + selected pixels for a 32 KiB payload

Run:  python docs/figures/gen_figures.py   (from the repo root)
"""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', '..', 'python'))
import stegolib as S
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
W, H = 512, 512
COVER_SEED = 0x57E60
ORDER_SEED = 7
COSTQ = 8
SAMPLE_PAYLOAD = 16 * 1024  # bytes, for the overlay figure

PALETTE = [
    (68, 1, 84), (72, 35, 116), (64, 67, 135), (52, 94, 141),
    (41, 120, 142), (32, 144, 140), (34, 167, 133), (68, 191, 112),
]


def synthetic_cover():
    rng = random.Random(COVER_SEED)
    px = []
    for y in range(H):
        for x in range(W):
            if y < H * 2 // 5:
                # smooth sky: vertical gradient + faint banding
                v = 200 - (y * 40) // (H * 2 // 5) + (x % 7 == 0)
                r, g, b = v, min(255, v + 8), min(255, v + 18)
            else:
                # textured ground: value noise + grain
                base = 90 + ((x * 37 + y * 91) % 60)
                grain = rng.randint(-25, 25)
                r = max(0, min(255, base + grain))
                g = max(0, min(255, base - 12 + grain))
                b = max(0, min(255, base - 30 + (grain // 2)))
            px += [r, g, b]
    # hard shapes (mid-cost rims): dark rectangle + light circle
    for y in range(H // 2, H * 3 // 4):
        for x in range(W // 4, W // 2):
            i = (y * W + x) * 3
            px[i], px[i + 1], px[i + 2] = 30, 30, 34
    cx, cy, rad = int(W * 0.72), int(H * 0.62), 60
    for y in range(max(0, cy - rad), min(H, cy + rad)):
        for x in range(max(0, cx - rad), min(W, cx + rad)):
            if (x - cx) ** 2 + (y - cy) ** 2 <= rad * rad:
                i = (y * W + x) * 3
                px[i], px[i + 1], px[i + 2] = 225, 220, 210
    return px


def main():
    px = synthetic_cover()
    costs = S.v4_costs(px, W, H)
    npx = W * H

    buckets = [0] * npx
    hist = [0] * COSTQ
    for i in range(npx):
        b = S.v4_bucket(costs[i], COSTQ)
        buckets[i] = b
        hist[b] += 1
    print('pixels=%d' % npx)
    print('bucket histogram: ' + ' '.join('b%d=%d' % (i, c)
                                          for i, c in enumerate(hist)))

    # --- cost_buckets.png ---
    img = Image.new('RGB', (W, H + 46), (16, 18, 24))
    mp = img.load()
    for y in range(H):
        for x in range(W):
            mp[x, y] = PALETTE[buckets[y * W + x]]
    for b in range(COSTQ):  # legend chips
        for y in range(H + 8, H + 28):
            for x in range(14 + b * 60, 14 + b * 60 + 44):
                mp[x, y] = PALETTE[b]
    img.save(os.path.join(HERE, 'cost_buckets.png'))

    # --- selection_overlay.png ---
    order = S.v4_candidate_order(px, W, H, ORDER_SEED, COSTQ, True)
    need_bits = (SAMPLE_PAYLOAD + 4 + S.V4_TAG_LEN) * 8
    need_px = (need_bits + 1) // 2  # 2 R/B slots per candidate pixel
    assert len(order) * 2 >= need_bits, 'synthetic cover too small?!'
    sel = set(order[:need_px])
    base = Image.new('RGB', (W, H))
    bp = base.load()
    for y in range(H):
        for x in range(W):
            i = y * W + x
            if i in sel:
                bp[x, y] = (232, 30, 40)
            else:
                bp[x, y] = (px[3 * i] // 3, px[3 * i + 1] // 3,
                            px[3 * i + 2] // 3)
    canvas = Image.new('RGB', (W, H + 30), (16, 18, 24))
    canvas.paste(base, (0, 0))
    canvas.save(os.path.join(HERE, 'selection_overlay.png'))
    print('cover=%dx%d Q=%d seed=%d payload=%d KiB -> %d px used (%.1f%%)' %
          (W, H, COSTQ, ORDER_SEED, SAMPLE_PAYLOAD // 1024, need_px,
           100.0 * need_px / npx))
    print('wrote cost_buckets.png + selection_overlay.png')


if __name__ == '__main__':
    main()
