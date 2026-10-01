#!/usr/bin/env python3
"""bench_steganalysis.py — classical-detector benchmark, v3 vs v4.

Matched conditions: same covers, same payload bytes, same bpp. Detectors
(chi-square PoV, RS regular/singular imbalance, even/odd pair-difference,
LSB smoothness) run pooled over all channels, plus a hand-rolled logistic
linear probe over the four features. Every detector is sanity-checked
against synthetic 100%-randomized LSBs first: a detector that cannot see
*that* is marked BROKEN and excluded (never silently trusted).

Outputs: console table + docs/figures/bench_v4.json + bench_auc.svg +
bench_roc.svg (hand-rolled SVG, no matplotlib needed).

Run from the repo root:  python python/bench_steganalysis.py
"""
import hashlib
import json
import math
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import stegolib as S

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
FIGDIR = os.path.normpath(os.path.join(HERE, '..', 'docs', 'figures'))
COVER_W, COVER_H = 256, 256
N_COVERS = 12
BPPS = [(2048, '0.25bpp'), (8192, '1.0bpp')]
PASSWORD = 'benchmark-password-0147'
PAYLOAD = bytes((i * 37 + 11) % 256 for i in range(8192))
METHODS = [
    ('v3seq', lambda px, w, h, p: S.encode_image(
        px, w, h, p, seed=0, password=PASSWORD, do_auth=True)),
    ('v3scatter', lambda px, w, h, p: S.encode_image(
        px, w, h, p, seed=7, password=PASSWORD, do_auth=True)),
    ('v4adapt', lambda px, w, h, p: S.encode_image_v4(
        px, w, h, p, PASSWORD, seed=7, adaptive=True)),
    ('v4nonadapt', lambda px, w, h, p: S.encode_image_v4(
        px, w, h, p, PASSWORD, seed=0, adaptive=False)),
]


def synthetic_cover(seed, w=COVER_W, h=COVER_H):
    rng = random.Random(seed)
    px = []
    for y in range(h):
        for x in range(w):
            if y < h * 2 // 5:
                v = 200 - (y * 40) // (h * 2 // 5) + (x % 7 == 0)
                px += [v, min(255, v + 8), min(255, v + 18)]
            else:
                base = 90 + ((x * 37 + y * 91) % 60)
                grain = rng.randint(-25, 25)
                px += [max(0, min(255, base + grain)),
                       max(0, min(255, base - 12 + grain)),
                       max(0, min(255, base - 30 + (grain // 2)))]
    return px


# ---------------------------------------------------------------- detectors

def _gser(a, x):
    gln = math.lgamma(a)
    ap, s, d = a, 1.0 / a, 1.0 / a
    for _ in range(200):
        ap += 1.0
        d *= x / ap
        s += d
        if abs(d) < abs(s) * 1e-12:
            break
    return s * math.exp(-x + a * math.log(x) - gln)


def _gcf(a, x):
    gln = math.lgamma(a)
    eps, fpmin = 1e-12, 1e-300
    b, c, d, h = x + 1.0 - a, 1.0 / fpmin, 1.0 / fpmin, 1.0 / fpmin
    for i in range(1, 200):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = fpmin if abs(d) < fpmin else d
        c = b + an / c
        c = fpmin if abs(c) < fpmin else c
        d = 1.0 / d
        dl = d * c
        h *= dl
        if abs(dl - 1.0) < eps:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def gammaincc(a, x):
    if x <= 0:
        return 1.0
    if x < a + 1.0:
        return max(0.0, min(1.0, 1.0 - _gser(a, x)))
    return max(0.0, min(1.0, _gcf(a, x)))


def det_chi2(px):
    """PoV chi-square over LSB pairs, pooled channels. Returns upper-tail
    p: replacement equalizes pairs, so STEGO scores HIGHER (p -> 1)."""
    h = np.bincount(np.asarray(px, dtype=np.uint8), minlength=256
                    ).astype(np.float64)
    chi, used = 0.0, 0
    for k in range(128):
        n = h[2 * k] + h[2 * k + 1]
        if n == 0:
            continue
        e = n / 2.0
        chi += ((h[2 * k] - e) ** 2 + (h[2 * k + 1] - e) ** 2) / e
        used += 1
    if used < 2:
        return 1.0
    return gammaincc((used - 1) / 2.0, chi / 2.0)


def _rs_channel(a):
    a = a.astype(np.int32)
    h, w = a.shape
    h2, w2 = (h // 2) * 2, (w // 2) * 2
    a = a[:h2, :w2]
    b = a.reshape(h2 // 2, 2, w2 // 2, 2)
    g0, g1, g2, g3 = b[:, 0, :, 0], b[:, 0, :, 1], b[:, 1, :, 0], b[:, 1, :, 1]

    def disc(x0, x1, x2, x3):
        return (np.abs(x0 - x1) + np.abs(x0 - x2) +
                np.abs(x1 - x3) + np.abs(x2 - x3))

    def f1(x):
        return x ^ 1

    def fm1(x):
        # F_{-1}: pairs (2i-1 <-> 2i). Boundaries saturate (fixed points),
        # the standard 8-bit treatment.
        return np.where(x % 2 == 1, np.minimum(x + 1, 255),
                        np.maximum(x - 1, 0))

    f0 = disc(g0, g1, g2, g3)
    m1 = (g1, g2)  # mask [[0,1],[1,0]] positions
    fM = disc(g0, f1(g1), f1(g2), g3)
    fmM = disc(g0, fm1(g1), fm1(g2), g3)
    n = f0.size
    rm = np.mean(fM > f0)
    sm = np.mean(fM < f0)
    rmm = np.mean(fmM > f0)
    smm = np.mean(fmM < f0)
    return ((rm - sm) - (rmm - smm)) / 2.0


def det_rs(px, w, h):
    """Regular/singular imbalance, max over luminance + R/G/B (analyst
    tries everything). Clean images score positive; randomization drives
    the score toward 0. Suspiciousness = baseline-relative drop."""
    arr = np.asarray(px, dtype=np.uint8).reshape(h, w, 3)
    r, g, b = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]
    y = ((299 * r.astype(np.int32) + 587 * g.astype(np.int32) +
          114 * b.astype(np.int32)) // 1000).astype(np.uint8)
    return max(_rs_channel(y), _rs_channel(r), _rs_channel(g),
               _rs_channel(b))


def det_spa(px, w, h):
    """Even/odd horizontal pair-difference imbalance (|E_2m| vs |O_2m+1|,
    |m| <= 3). Replacement equalizes them; clean covers differ."""
    arr = np.asarray(px, dtype=np.uint8).reshape(h, w, 3).astype(np.int32)
    d = (arr[:, 1:, :] - arr[:, :-1, :]).ravel()
    tot = d.size
    s = 0.0
    for m in range(-3, 3):
        a = np.mean(d == 2 * m)
        b = np.mean(d == 2 * m + 1)
        s += abs(a - b)
    return s


def det_smooth(px, w, h):
    """Fraction of horizontally adjacent channels sharing LSB."""
    arr = np.asarray(px, dtype=np.uint8).reshape(h, w, 3)
    return float(np.mean((arr[:, 1:, :] & 1) == (arr[:, :-1, :] & 1)))


DETECTORS = [('chi2', lambda px, w, h: det_chi2(px)),
             ('rs', det_rs),
             ('spa', det_spa),
             ('smooth', det_smooth)]


def synth_flip(px, seed):
    rng = random.Random(seed)
    out = list(px)
    rb = bytes(rng.getrandbits(1) for _ in range(len(out)))
    for i in range(len(out)):
        out[i] = (out[i] & 0xFE) | rb[i]
    return out


# ---------------------------------------------------------------- metrics

def auc(stego, clean):
    m, n = len(stego), len(clean)
    vals = sorted([(s, 1) for s in stego] + [s, 0] for s in clean)
    # Mann-Whitney with average tied ranks
    rank_sum, i = 0.0, 0
    vals = sorted([(s, 1) for s in stego] + [(s, 0) for s in clean])
    while i < len(vals):
        j = i
        while j < len(vals) and vals[j][0] == vals[i][0]:
            j += 1
        avg = (i + 1 + j) / 2.0
        rank_sum += sum(avg for k in range(i, j) if vals[k][1] == 1)
        i = j
    return (rank_sum - m * (m + 1) / 2.0) / (m * n)


def roc_points(stego, clean):
    pts = [(1.0, 1.0)]
    for t in sorted(set(stego) | set(clean), reverse=True):
        tp = sum(1 for s in stego if s >= t) / len(stego)
        fp = sum(1 for s in clean if s >= t) / len(clean)
        pts.append((fp, tp))
    pts.append((0.0, 0.0))
    return sorted(set(pts))


def det_at_fpr(stego, clean, fpr=0.05):
    best = 0.0
    for t in sorted(set(stego) | set(clean), reverse=True):
        fp = sum(1 for s in clean if s >= t) / len(clean)
        if fp <= fpr + 1e-12:
            tp = sum(1 for s in stego if s >= t) / len(stego)
            best = max(best, tp)
    return best


def psnr(a, b):
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    mse = np.mean((a - b) ** 2)
    if mse == 0:
        return float('inf')
    return 10.0 * math.log10(255.0 * 255.0 / mse)


def train_probe(X, y, iters=800, lr=0.5, l2=1e-3):
    n = len(X)
    mu = [sum(r[j] for r in X) / n for j in range(len(X[0]))]
    sd = []
    for j in range(len(X[0])):
        v = sum((r[j] - mu[j]) ** 2 for r in X) / n
        sd.append(math.sqrt(v) or 1.0)
    Z = [[(r[j] - mu[j]) / sd[j] for j in range(len(X[0]))] for r in X]
    w = [0.0] * len(X[0])
    b = 0.0
    for _ in range(iters):
        gw = [0.0] * len(w)
        gb = 0.0
        for i in range(n):
            z = sum(w[j] * Z[i][j] for j in range(len(w))) + b
            p = 1.0 / (1.0 + math.exp(-max(-50.0, min(50.0, z))))
            e = p - y[i]
            for j in range(len(w)):
                gw[j] += e * Z[i][j]
            gb += e
        for j in range(len(w)):
            w[j] -= lr * (gw[j] / n + l2 * w[j])
        b -= lr * gb / n
    def score(r):
        z = sum(w[j] * (r[j] - mu[j]) / sd[j] for j in range(len(w))) + b
        return 1.0 / (1.0 + math.exp(-max(-50.0, min(50.0, z))))
    return score


def cv_probe_auc(feats_clean, feats_stego):
    X = feats_clean + feats_stego
    y = [0] * len(feats_clean) + [1] * len(feats_stego)
    idx = list(range(len(X)))
    aucs = []
    for fold in range(5):
        te = [i for i in idx if i % 5 == fold]
        tr = [i for i in idx if i % 5 != fold]
        sc = train_probe([X[i] for i in tr], [y[i] for i in tr])
        s1 = [sc(X[i]) for i in te if y[i] == 1]
        s0 = [sc(X[i]) for i in te if y[i] == 0]
        if s1 and s0:
            aucs.append(auc(s1, s0))
    return sum(aucs) / len(aucs) if aucs else 0.5


# ---------------------------------------------------------------- SVG

def _svg_open(w, h, title):
    return ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
            'viewBox="0 0 %d %d" font-family="ui-monospace, Consolas, monospace">'
            % (w, h, w, h),
            '<text x="20" y="30" font-size="19" font-weight="bold" '
            'fill="#1a2233">%s</text>' % title]


def svg_bars(path, title, groups, series, values, note):
    # values[group][series] in [0,1]
    W, H = 960, 420
    cols = ['#3f7fbf', '#3aa655', '#c98a2b', '#7c5cd6']
    L = {'l': 70, 'r': 20, 't': 70, 'b': 90}
    pw, ph = W - L['l'] - L['r'], H - L['t'] - L['b']
    out = _svg_open(W, H, title)
    out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#3a4763" '
               'stroke-width="2"/>' % (L['l'], L['t'] + ph, L['l'] + pw,
                                       L['t'] + ph))
    for q in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = L['t'] + ph * (1 - q)
        out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#d4d9e2"/>'
                   % (L['l'], y, L['l'] + pw, y))
        out.append('<text x="%d" y="%d" font-size="11" fill="#6b7690" '
                   'text-anchor="end">%.2f</text>' % (L['l'] - 8, y + 4, q))
    gw = pw / len(groups)
    bw = min(44, (gw - 30) / len(series))
    for gi, g in enumerate(groups):
        for si, s in enumerate(series):
            v = max(0.0, min(1.0, values[g][s]))
            bh = ph * v
            x = L['l'] + gi * gw + 15 + si * bw
            y = L['t'] + ph - bh
            out.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" '
                       'fill="%s"/>' % (x, y, bw - 3, bh, cols[si % 4]))
            out.append('<text x="%.1f" y="%.1f" font-size="10" fill="#1a2233" '
                       'text-anchor="middle">%.2f</text>'
                       % (x + (bw - 3) / 2, y - 5, v))
        out.append('<text x="%.1f" y="%d" font-size="12" fill="#1a2233" '
                   'text-anchor="middle">%s</text>'
                   % (L['l'] + gi * gw + gw / 2, L['t'] + ph + 22, g))
    for si, s in enumerate(series):
        x = L['l'] + si * 130
        out.append('<rect x="%d" y="%d" width="14" height="14" fill="%s"/>'
                   % (x, H - 48, cols[si % 4]))
        out.append('<text x="%d" y="%d" font-size="12" fill="#1a2233">%s</text>'
                   % (x + 20, H - 36, s))
    out.append('<text x="%d" y="%d" font-size="11" fill="#6b7690">%s</text>'
               % (L['l'], H - 12, note))
    out.append('</svg>')
    open(path, 'w', encoding='utf-8').write('\n'.join(out))


def svg_roc(path, title, curves, note):
    # curves: [(label, [(fpr,tpr)...], color, dash)]
    W, H = 960, 500
    L = {'l': 70, 'r': 230, 't': 60, 'b': 100}
    pw, ph = W - L['l'] - L['r'], H - L['t'] - L['b']
    out = _svg_open(W, H, title)
    out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#3a4763" '
               'stroke-width="2"/>' % (L['l'], L['t'] + ph, L['l'] + pw,
                                       L['t'] + ph))
    out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#3a4763" '
               'stroke-width="2"/>' % (L['l'], L['t'], L['l'], L['t'] + ph))
    out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#c0c6d2" '
               'stroke-dasharray="6,5"/>' % (L['l'], L['t'] + ph,
                                             L['l'] + pw, L['t']))
    out.append('<text x="%d" y="%d" font-size="11" fill="#6b7690" '
               'text-anchor="middle">false positive rate →</text>'
               % (L['l'] + pw / 2, L['t'] + ph + 34))
    for ci, (label, pts, color, dash) in enumerate(curves):
        d = 'M' + ' L'.join('%.1f,%.1f' % (L['l'] + f * pw, L['t'] + ph -
                                           t * ph) for f, t in pts)
        dashs = ' stroke-dasharray="7,4"' if dash else ''
        out.append('<path d="%s" fill="none" stroke="%s" stroke-width="2.5"%s/>'
                   % (d, color, dashs))
        out.append('<text x="%d" y="%d" font-size="11" fill="%s">%s</text>'
                   % (L['l'] + pw + 16, L['t'] + 20 + ci * 23, color, label))
    out.append('<text x="%d" y="%d" font-size="11" fill="#6b7690">%s</text>'
               % (L['l'], H - 12, note))
    out.append('</svg>')
    open(path, 'w', encoding='utf-8').write('\n'.join(out))


# ---------------------------------------------------------------- main

def main():
    covers = [synthetic_cover(101 + i) for i in range(N_COVERS)]
    clean_scores = {name: [] for name, _ in DETECTORS}
    clean_feats = []
    for px in covers:
        for name, fn in DETECTORS:
            clean_scores[name].append(fn(px, COVER_W, COVER_H))
        clean_feats.append([fn(px, COVER_W, COVER_H) for _, fn in DETECTORS])

    # sanity: every detector must see synthetic 100%-randomized LSBs
    orientations, broken = {}, []
    for name, fn in DETECTORS:
        s = [fn(synth_flip(px, 5000 + i), COVER_W, COVER_H)
             for i, px in enumerate(covers)]
        mc = sum(clean_scores[name]) / len(clean_scores[name])
        ms = sum(s) / len(s)
        if abs(ms - mc) < 1e-12:
            broken.append(name)
            print('SANITY %s: BROKEN (no response to randomized LSBs)' % name)
            continue
        orientations[name] = 1.0 if ms > mc else -1.0
        print('SANITY %s: clean=%.4g synth=%.4g dir=%+.0f' %
              (name, mc, ms, orientations[name]))
    live = [(n, f) for n, f in DETECTORS if n not in broken]
    assert live, 'all detectors broken?!'

    def oriented(name, v):
        return orientations[name] * v

    results = {'covers': N_COVERS, 'dims': [COVER_W, COVER_H],
               'password': '(fixed bench password)', 'methods': {},
               'sanity': {n: {'dir': orientations.get(n, 0)} for n, _ in DETECTORS}}
    roc_curves = []
    for plen, blabel in BPPS:
        payload = PAYLOAD[:plen]
        bpp = plen * 8 / (COVER_W * COVER_H)
        for mname, mfn in METHODS:
            stego, feats, psnrs, chfrac = [], [], [], []
            for px in covers:
                e = mfn(list(px), COVER_W, COVER_H, payload)
                stego.append(e)
                feats.append([fn(e, COVER_W, COVER_H) for _, fn in DETECTORS])
                psnrs.append(psnr(px, e))
                chfrac.append(sum(1 for a, b in zip(px, e) if a != b) /
                              len(px))
            key = '%s@%s' % (mname, blabel)
            entry = {'bpp': round(bpp, 4), 'payload': plen,
                     'psnr_mean': round(sum(psnrs) / len(psnrs), 2),
                     'changed_frac': round(sum(chfrac) / len(chfrac), 4),
                     'detectors': {}}
            for di, (name, _) in enumerate(DETECTORS):
                if name in broken:
                    entry['detectors'][name] = {'status': 'BROKEN'}
                    continue
                s1 = [oriented(name, f[di]) for f in feats]
                s0 = [oriented(name, v) for v in clean_scores[name]]
                a = auc(s1, s0)
                entry['detectors'][name] = {
                    'auc': round(a, 3),
                    'det05': round(det_at_fpr(s1, s0), 3),
                    'stego_mean': round(sum(s1) / len(s1), 4)}
                if blabel == BPPS[0][1]:
                    pts = roc_points(s1, s0)
                    roc_curves.append(
                        ('%s %s (AUC %.2f)' % (mname, name, a), pts,
                         mname.startswith('v3')))
            # linear probe (live detectors only)
            li = [di for di, (n, _) in enumerate(DETECTORS) if n not in broken]
            pa = cv_probe_auc([[f[i] for i in li] for f in clean_feats],
                              [[f[i] for i in li] for f in feats])
            entry['probe_auc'] = round(pa, 3)
            results['methods'][key] = entry
            row = ' '.join('%s:%.2f' % (n, entry['detectors'][n].get('auc', -1))
                           for n, _ in DETECTORS if n not in broken)
            print('%-16s psnr=%6.2f chg=%.3f probe=%.2f %s' %
                  (key, entry['psnr_mean'], entry['changed_frac'],
                   entry['probe_auc'], row))

    # ROC colors: v4 solid green family, v3 dashed blue family
    palette = {'v3seq': '#3f7fbf', 'v3scatter': '#7a5fd0',
               'v4adapt': '#2e9e5b', 'v4nonadapt': '#c98a2b'}
    styled = []
    for label, pts, dashed in roc_curves:
        m = label.split()[0]
        styled.append((label, pts, palette.get(m, '#333333'), dashed))
    svg_roc(os.path.join(FIGDIR, 'bench_roc.svg'),
            'ROC — clean vs stego, %s, %d covers' % (BPPS[0][1], N_COVERS),
            styled, 'solid=v4 (AEAD+adaptive) · dashed=v3 (CTR+LSB replacement)')

    # AUC bars per bpp
    for plen, blabel in BPPS:
        groups = [m for m, _ in METHODS]
        series = [n for n, _ in DETECTORS if n not in broken] + ['probe']
        values = {}
        for m, _ in METHODS:
            e = results['methods']['%s@%s' % (m, blabel)]
            values[m] = {n: e['detectors'][n].get('auc', 0) for n in series
                         if n != 'probe'}
            values[m]['probe'] = e['probe_auc']
        svg_bars(os.path.join(FIGDIR, 'bench_auc_%s.svg' % blabel.replace(
            '.', '')),
            'Detector AUC (0.5 = blind) — %s, %d covers' % (blabel, N_COVERS),
            groups, series, values,
            'AUC: clean-vs-stego separation per detector · probe = 5-fold CV logistic')
    json.dump(results, open(os.path.join(FIGDIR, 'bench_v4.json'), 'w'),
              indent=1)
    print('wrote bench_v4.json + bench_auc_*.svg + bench_roc.svg')


if __name__ == '__main__':
    main()
