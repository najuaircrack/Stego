# ANALYSIS.md — v4 security analysis + measured detectability

Companion to `FORMAT.md` (normative construction) and `SECURITY.md`
(threat model). This document argues each component and then MEASURES
the embedding layer against classical detectors — with the harness,
the raw numbers, and the charts checked in alongside. Claims are bounded
by what is shown here; anything else is a non-goal (§7).

## 1. Component arguments

**KDF — PBKDF2-HMAC-SHA256, 210,000 iterations, 16B fresh salt, 96B out.**
OWASP 2023 parameters for HMAC-SHA-256. The salt is CSPRNG-fresh per
encode, so identical passwords yield independent (key, nonce) pairs per
message. Offline guessing cost is ~0.25 s per candidate on commodity
hardware — the KDF buys time against weak passwords, not immunity; the
password guidance (≥20 random chars, `SECURITY.md`) does the real work.

**AEAD — ChaCha20-Poly1305 (RFC 8439), header as associated data.**
One key, one 12-byte nonce, one encryption per message; nonces never
repeat because the salt (hence the derived nonce) is fresh per message.
The FULL 64-byte header is AAD, so version/flags/sizes/salt tampering
fails the open. Decryption failure, wrong password, truncation, and
bit-flips are indistinguishable (single reject path — no oracle beyond
pass/fail). The inner `data_crc32` is defense-in-depth against
implementation divergence between ports, not a security boundary.

**Ordering — green-channel invariance (the load-bearing argument).**
Costs derive from the GREEN channel only; embedding writes RED/BLUE
only. Green is therefore bit-identical on both sides, so decode-side
costs equal encode-side costs EXACTLY — no statistical margin argument,
no retries, no convergence to hope for. Bucket flips are impossible by
construction, not unlikely by measurement. The residual assumption is
stated plainly: both ports must implement the integer cost formula
bit-exact (golden vectors enforce this in Stage 3).

**±1 symmetry.** LSB replacement maps `2k→{2k,2k+1}` asymmetrically and
never touches `2k+1→2k+2`; ±1 (LSB matching) preserves
`E[count(2k)] ≈ E[count(2k+1)]` in expectation. Chi-square/RS/SPA key on
exactly this asymmetry — §5 measures how much of it survives.

**Robustness (ROBUST).** Repetition-3 + majority vote corrects isolated
LSB flips (PNG re-encode, metadata rewrite). It provably does NOT survive
resampling (resize/crop/JPEG): the slot map is pixel-registered. Stated
as a non-goal, not a limitation to fix later.

## 2. Benchmark methodology

Harness: `python/bench_steganalysis.py` (one file, no new dependencies
beyond numpy/Pillow). Raw output: `docs/figures/bench_v4.json`; charts
are hand-rolled SVG (`bench_auc_*.svg`, `bench_roc.svg`).

- **Covers:** 12 synthetic photographic-style 256×256 (smooth gradient
  sky + seeded texture + hard shapes; seeds 101–112). Synthetic, not
  BOSSbase — see §7 for what this does and doesn't prove.
- **Payloads:** fixed 2048 B (`0.25bpp`) and 8192 B (`1.0bpp`) prefixes
  of one seeded buffer — same bytes for every method (fair comparison).
- **Methods:** `v3seq` (seed 0), `v3scatter` (seed 7), `v4adapt`
  (seed 7), `v4nonadapt` (seed 0); fixed password; salts random per
  embed (AEAD nonces unique — as deployed).
- **Detectors** (pooled over all channels; orientation auto-locked
  against synthetic 100%-randomized LSBs, then frozen for evaluation):
  - `chi2` — pairs-of-values chi-square, upper-tail p (replacement
    equalizes pairs → stego scores higher).
  - `rs` — regular/singular 2×2-block imbalance, max over
    luminance+R/G/B; reported as baseline-relative drop (calibrated
    score, not the Fridrich closed-form estimator — stated).
  - `spa` — even/odd horizontal pair-difference imbalance (|m|≤3).
  - `smooth` — adjacent-channel LSB equality fraction.
  - `probe` — hand-rolled logistic regression over the four features,
    5-fold CV AUC (small-n: 12+12 samples per task — §7).
- **Sanity gate:** each detector must separate clean covers from
  synthetic randomized LSBs first; a detector that cannot see *that* is
  marked BROKEN and excluded (this fired once during development — an
  `F_{-1}` implementation identical to `F1` — and was fixed, not
  ignored).
- **Metrics:** AUC (Mann-Whitney), detection rate at 5% FPR, PSNR,
  changed-channel fraction.

## 3. Results (0.25 bpp, operational point)

AUC (0.5 = blind) / detection @ 5% FPR:

| method | chi2 | rs | spa | smooth | probe | PSNR |
|---|---|---|---|---|---|---|
| v3seq | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 | 61.79 |
| v3scatter | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 | 61.79 |
| v4adapt | 0.98 / 0.92 | **0.52 / 0.00** | 0.83 / 0.50 | **0.54 / 0.00** | 0.77 | 61.81 |
| v4nonadapt | 1.00 / 1.00 | 0.54 / 0.17 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 | 61.82 |

![AUC @0.25bpp](figures/bench_auc_025bpp.svg)
![ROC @0.25bpp](figures/bench_roc.svg)

## 4. Results (1.0 bpp, stress point)

| method | chi2 | rs | spa | smooth | probe | PSNR |
|---|---|---|---|---|---|---|
| v3seq | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 | 55.88 |
| v3scatter | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 | 55.88 |
| v4adapt | 1.00 / 1.00 | **0.42 / 0.00** | 0.97 / 0.92 | **0.60 / 0.00** | 1.00 | 55.88 |
| v4nonadapt | 1.00 / 1.00 | 0.42 / 0.08 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 | 55.88 |

![AUC @1.0bpp](figures/bench_auc_10bpp.svg)

## 5. Interpretation (per detector)

- **RS is blind to v4** (AUC 0.42–0.54, det@5% ≈ 0 at both bpps) while
  v3 is perfectly detected (1.00). This is the predicted effect: RS keys
  on LSB-replacement asymmetry; ±1 preserves regular/singular balance.
  The headline v4 result.
- **smooth is blind to v4adapt** (0.54–0.60, det@5% = 0) but sees
  v4nonadapt (1.00). LSB-equality in smooth regions survives because
  adaptive placement never touches them — placement, not the ±1
  mechanism, earns this one (v4nonadapt proves the control).
- **chi2/spa still see everything** (0.83–1.00). Global first-order
  tests respond to total equalized mass, which is bpp-driven: at
  0.25–1.0 bpp on these covers there is enough of it under any placement.
  v4adapt shaves spa to 0.83/0.50 at the operational point — reduction,
  not invisibility.
- **The linear probe mostly still sees v4** (0.77 at 0.25 bpp, 1.00 at
  1.0 bpp) because its features are dominated by chi2/spa. A probe with
  higher-order (co-occurrence) features would be the next evaluation
  step — listed, not claimed.
- **PSNR is identical across methods** (61.8 / 55.9): v4 changes the
  same number of channels — the win is WHERE (texture) and HOW
  (symmetric), never "fewer changes". Anyone reporting a PSNR win for an
  adaptive scheme at matched bpp is measuring an artifact.

## 6. Reproduce

```
python python/bench_steganalysis.py   # ~2 min; rewrites bench_v4.json + SVGs
```
Cover seeds, payload bytes, method seeds, and password are fixed in the
harness; per-embed salts are random (as deployed), so AUCs vary ±0.03
run to run — the qualitative pattern (RS/smooth blind on v4adapt,
chi2/spa seeing all) is stable across runs (verified ×3).

## 7. Non-claims and limits (read before citing)

1. **Synthetic covers, not natural photos.** RS/chi-square behave
   differently on BOSSbase-type imagery; natural-image validation is
   open future work, not a held result.
2. **No ML-steganalysis claim.** The probe is linear over four
   classical features (small-n CV at that). No CNN/SRNet evaluation is
   claimed or implied.
3. **No robustness claim** beyond §1 (repetition-3 vs re-encode).
4. **No undetectability claim**, for v4 or anything else. Measured
   reduction on specific detectors at specific bpps — the tables above
   are the entire claim.
5. **Deployment note:** v4 images are unreadable by v3-only decoders
   (including third-party tooling that speaks the v3 envelope) —
   migration is a coordinated rollout, not a flag flip.
