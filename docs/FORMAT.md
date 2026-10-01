# STEGO format specification (normative)

Two envelopes, one file. **v3 (§1) is frozen**: v3 bytes decode
identically forever, and every v3 MUST below still holds. **v4 (§2)** is
the modern envelope (AEAD, adaptive ±1 placement); decoders dispatch on
the header version and accept `{0x0003, 0x0004}`. All integers
little-endian. All cryptography uses SHA-256 (`src/sha256.cpp`) plus, for
v4 only, the vendored ChaCha20-Poly1305 (`src/chacha20poly1305.cpp`,
RFC 8439). Visual map: `figures/envelope.svg` (header layouts),
`figures/pipeline.svg` (v4 data flow), `figures/cost_buckets.png` and
`figures/selection_overlay.png` (real adaptive-placement output).

## 1. Envelope v3 (frozen)

Key derivation (password mode):

- Password encoding: UTF-8 bytes as given.
- KDF: PBKDF2-HMAC-SHA256, **100,000 iterations**, 16-byte random salt
  (stored in header), 64-byte output: `[0..32)` encryption key,
  `[32..64)` authentication key.
- Salt doubles as the CTR nonce (unique keystream per message).

Header (44 bytes, always present):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | `"STG2"` (`0x53 0x54 0x47 0x32`) |
| 4 | 2 | version | `0x0003` |
| 6 | 2 | flags | bit0 `COMPRESS`, bit1 `SCATTER`, bit2 `ENCRYPT`, bit3 `AUTH` |
| 8 | 4 | seed | PRNG seed for scatter placement (`0` = sequential) |
| 12 | 4 | orig_size | plaintext payload bytes (u32) |
| 16 | 4 | comp_size | bytes after compress+encrypt stages (u32) |
| 20 | 4 | reserved | zero |
| 24 | 16 | salt | random per encode (KDF salt + CTR nonce) |
| 40 | 4 | header_crc32 | CRC32 (zlib poly `0xEDB88320`) of bytes `[0..40)` |

Data region: header pixels `[0,118)` are ALWAYS sequential (findable
without the seed). The body stream (ciphertext + `data_crc32` [+ HMAC
tag]) starts at body stream bit 0, placed via `PlacementRange(118,
N-118, seed)` — i.e. body bit `m` lives in pixel `perm[m/3]`, channel
`m%3`, where `perm` is the Fisher-Yates permutation of pixels `[118,N)`.
`seed == 0` degenerates to sequential placement for the whole image.

Images without the magic, with a wrong version, or with failing CRC/HMAC
are rejected outright - there is no legacy layout to fall back to.

Stage pipeline (encode order; decode reverses):

1. Optional `COMPRESS` (rejected by encoders - backend deferred).
2. Optional `ENCRYPT`: SHA-256-CTR keystream over the 32-byte encryption key.
   `keystream = SHA256(enckey || BE32(counter))` concatenated from counter 0.
3. Scatter placement (if `SCATTER` or `seed != 0`): pixel permutation from
   xorshift128+ seeded by `splitmix64(seed)` (exact algorithm in `codec.cpp`;
   both implementations must match bit-for-bit - see golden vectors).
4. `data_crc32`: CRC32 of the ORIGINAL plaintext payload, appended as bits.
5. `AUTH` (requires `ENCRYPT`): `HMAC-SHA256(authkey, header[0..44) ||
   embedded-ciphertext-bytes)`, appended as bits.
   NOTE: the tag covers header + ciphertext ONLY - `data_crc32` is
   deliberately outside the HMAC input (both sides must match exactly).

## 2. Envelope v4 (normative, version 4.0.0)

| v3 weakness | v4 answer |
|---|---|
| LSB *replacement* (asymmetric: never maps `2k+1 -> 2k+2`) | Ternary ±1 (LSB *matching*): symmetric, defeats chi-square / sample-pair |
| Uniform scatter (smooth sky pixels carry secrets) | Cost-ordered adaptive placement (texture-first, smooth skipped) |
| SHA-256-CTR + separate HMAC (two keys, two passes, malleable framing) | ChaCha20-Poly1305 AEAD, full header as associated data (one pass) |
| PBKDF2 100k | PBKDF2-HMAC-SHA256 **210,000** iterations (OWASP 2023), 96-byte output |
| Header integrity = CRC32 only | CRC32 (fast reject) + AEAD associated-data cover (cryptographic) |
| No robustness story | Optional repetition-3 + majority vote (`ROBUST`; survives PNG re-encode, NOT resize) |

### 2.1 Key derivation (password mode, agile)

- Password encoding: UTF-8 bytes as given.
- `kdf_id` selects the function (header field `[40..44)`):
  - `0` — PBKDF2-HMAC-SHA256, **210,000 iterations**, 16-byte salt,
    **96-byte** output (`[0..32)` message key, `[32..44)` base nonce,
    rest reserved). Legacy v4.0 images always carry `kdf_id 0` with
    zeroed `kdf_m_kib/time/lanes`.
  - `1` — Argon2id (RFC 9106, version `0x13`), 16-byte salt, **96-byte**
    tag output with the identical split. Recommended production
    parameters: `m = 65536 KiB`, `t = 3`, `lanes = 1` (RFC 9106
    second recommendation, single-lane).
- `kdf_m_kib` (`[48..52)`), `kdf_time` (`[52..56)`), `kdf_lanes`
  (`[56..60)`): Argon2id parameters. For `kdf_id 0` all three MUST be
  zero (decoders reject nonzero). For `kdf_id 1`: `m` in
  `[8, 1048576]`, `t` in `[1, 16]`, `lanes == 1` (only single-lane is
  specified; anything else is rejected fail-closed — this also bounds
  decoder memory/time against malicious headers).
- Salt is fresh CSPRNG output per encode under both ids: unique
  (key, nonce) per message even under password reuse. Each message uses
  one 12-byte nonce for one AEAD encryption, so nonces never repeat.

### 2.2 Header (64 bytes, always present)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | `"STG2"` (family marker; version selects the envelope) |
| 4 | 2 | version | `0x0004` |
| 6 | 2 | flags | see below |
| 8 | 4 | seed | u32 PRNG seed: intra-bucket shuffle + ±1 directions (`0` forbidden when `ADAPTIVE`; encoders MUST pick nonzero random) |
| 12 | 4 | orig_size | plaintext payload bytes (u32) |
| 16 | 4 | comp_size | AEAD ciphertext bytes INCLUDING the 16-byte tag (u32) |
| 20 | 4 | costq | cost buckets Q, `1..16` (`8` default; `1` = degenerate uniform order) |
| 24 | 16 | salt | fresh random per encode (KDF salt) |
| 40 | 4 | kdf_id | `0` = PBKDF2-210k (v4.0 legacy), `1` = Argon2id |
| 44 | 4 | header_crc32 | CRC32 of bytes `[0..44)` (fast reject only) |
| 48 | 4 | kdf_m_kib | Argon2id memory KiB (`0` unless `kdf_id == 1`) |
| 52 | 4 | kdf_time | Argon2id passes (`0` unless `kdf_id == 1`) |
| 56 | 4 | kdf_lanes | Argon2id lanes, MUST be `1` (`0` unless `kdf_id == 1`) |
| 60 | 4 | reserved2 | zero |

Flags (v4): bit0 `COMPRESS` (reserved, encoders reject), bit1 `SCATTER`
(keyed shuffle; `ADAPTIVE` implies bucket order first), bit2 `ENCRYPT`
(MUST be 1 in v4), bit3 `AUTH` (MUST be 1 in v4), bit4 `ADAPTIVE`
(cost-ordered placement; else v3-style sequential-after-header with ±1
embedding), bit5 `ROBUST` (RS-ECC + interleave, §2.6), bit6 `STC`
(syndrome-trellis coding, §2.4b; default on for new encodes).
`STEGO_HEADER_PX_V4 = 176` (176 px × 3 ch = 528 ≥ 512 header bits).

### 2.3 AEAD construction (encode order; decode reverses)

1. Plaintext P = `data_crc32` (4 bytes LE, CRC32 of the payload) `||`
   payload bytes. (Belt-and-braces: the AEAD tag already authenticates;
   the CRC catches implementation divergence between ports.)
2. Ciphertext C = `ChaCha20-Poly1305(key, nonce, AAD=header[0..64), P)`.
   `comp_size = len(C) = len(P) + 16`. The FULL 64-byte header (including
   both reserved areas) is associated data.
3. Body stream = C bits only (the tag is inside C; no separate trailer).
4. Decoder: parse header, CRC pre-check, KDF, AEAD-open with the same
   AAD. ANY failure (version, CRC, AEAD tag, inner CRC, sizes) → reject
   with the same indistinguishable error. No oracles beyond pass/fail.

### 2.4 Adaptive cost-ordered placement (ADAPTIVE)

Goal: touch textured pixels first, leave smooth pixels exact — minimising
first-order and second-order statistical disturbance per embedded bit.
The ordering is PROVABLY stable: decode reproduces it bit-exact with no
retries. See `figures/cost_buckets.png` (real bucket map) and
`figures/selection_overlay.png` (real selection order).

Invariance design (the load-bearing idea): costs are computed from the
GREEN channel only, and embedding touches ONLY red and blue. Green stays
bit-exact end-to-end, so decode-side costs equal encode-side costs
exactly — bucket flips are impossible, not merely unlikely. (Side
benefit: green carries ~60% of luminance, so the luminance histogram is
nearly preserved.) Kerckhoffs note: the method is public; adaptivity
minimises distortion, it does not hide the method.

1. Cost = S-UNIWARD-style wavelet residual energy of the GREEN channel
   (mirror edges), computed with the INTEGER 5/3 lifting DWT (JPEG2000
   lifting, bit-exact across ports — floor division everywhere, never
   `>>` on possibly-negative intermediates):
   predict `d[n] = odd[n] - floor((even[n] + even[n+1]) / 2)`,
   update `s[n] = even[n] + floor((d[n-1] + d[n] + 2) / 4)`,
   applied separably rows-then-columns (symmetric extension: out-of-range
   taps mirror, i.e. index `-1 → 1`, `N → N-2`, matching the lifting
   convention). Subbands LH/HL/HH give the high-frequency maps (LL
   positions zeroed);
   `cost(p) = Σ |LH| + |HL| + |HH|` over the 3x3 window at `p`
   (window borders mirrored the same way; all integer, exact).
   Green-only + R/B-only embedding keep the
   invariance argument (§2.4 head) intact: decode-side costs equal
   encode-side costs exactly.
2. Bucket (integer-only): `L = bit_length(cost)` (`0` for cost `0`);
   `bucket = min(Q-1, (L*Q) >> 4)`, where `Q = costq` from the header.
   (`cost` fits in 15 bits for 8-bit imagery, so `L <= 15`.) There is NO
   wet-paper margin and NO skip rule: every pixel at index `>= 256` is a
   candidate. Stability comes from invariance (above), not from margins.
3. Candidate order: all pixels `>= 256`, bucket DESCENDING (highest
   texture first); ties (same bucket) broken by Fisher-Yates driven by
   xorshift128+ with per-bucket stream
   `Xor128(seed XOR ((b+1) * 0x9E3779B97F4A7C15))` (`b` = bucket index;
   same xorshift128+/splitmix64 core as v3 — bit-exact across ports).
   Within-bucket member lists are sorted ascending before the shuffle,
   so the order is a pure function of (green costs, seed).
4. Slots use RED/BLUE channels only (green is never written): slot `s`
   → candidate pixel `order[s/2]`, channel R if `s` even else B (integer
   division). The header ALWAYS occupies slots `[0, 512)` over pixels
   `[0,256)` sequentially, regardless of flags.
   (`STEGO_HEADER_PX_V4 = 256`: 256 px × 2 ch = 512 header bits exactly,
   zero waste. v3's 118-pixel reservation is unchanged for v3 images.)
   Body stream bit `m` → the slot stream of the candidate order.
   (`ROBUST`: each body bit occupies 3 consecutive slots; decode takes
   majority vote, ties → 0.)
5. Capacity: 2 body bits per candidate pixel (ECC framing under
   `ROBUST`, §2.6, changes the payload-to-slot math, not the order).
   Encoders refuse oversize payloads explicitly, same as v3.
   Non-`ADAPTIVE` v4: v3-style `PlacementRange(256, N-256, seed)` order
   over the same R/B slot mapping (header identical).

### 2.4b Syndrome-trellis coding (STC, default on)

Greedy ±1 flips the first bits that fit; STC finds the globally cheapest
flip pattern for the whole message given per-position costs — near the
theoretical distortion bound instead of merely under it.

1. Message bits `m[0..M)` (the AEAD body, or the RS codeword under
   `ROBUST`) are embedded into the first `n = M + h` candidate slots'
   LSBs, `h = 7` (constraint height, fixed).
2. Parity-check band: message bit `j` = XOR over `k = 0..h` of
   `S[k] · y[j+k]`, where `y` are the stego LSBs and the submatrix is
   `S[0] = 1`, `S[1..h]` = the next `h` bits of
   `Xor128(seed XOR 0x535443)` output LSB-first (`0x535443` = ASCII
   "STC" domain tag; same xorshift core — bit-exact across ports).
3. Flip cost of position `i` = `Q - bucket(i)` (`1` = cheapest texture
   … `Q` = smoothest). Costs never touch the wire (only the bucket
   order does), so cost granularity may evolve without format impact.
4. Encoder runs Viterbi over `2^h = 128` states with integer metrics
   (exact, no float ties-to-break); traceback yields the minimum-cost
   flip pattern, realized via ±1 with the §2.5 direction rule. Reader
   recomputes the syndromes from the LSBs — it needs no costs, no
   trellis, no order beyond the candidate list both sides share.
5. `STC` off = greedy ±1 in slot order (kept for constrained decoders;
   same wire positions, same reader for the order — only the flip
   pattern differs, which the AEAD authenticates either way).

### 2.5 Ternary ±1 embedding (all v4 modes, header AND body)

To embed bit `b` into channel value `v` (`LSB(v) != b` case only):
- `v == 0` → `1`; `v == 255` → `254` (saturation, forced direction);
- else `v + 1` if direction-bit is 1 else `v - 1`.
Direction bit for global slot `s` (header slots `0..512`, body slots
continuing from `512`, robust triplets included):
`seed64 = seed XOR u32le(salt[0..4])`;
`t = seed64 XOR ((s · 0x9E3779B97F4A7C15) mod 2^64)`;
SplitMix-finalize `t` (the `z`-mixing half of `splitmix64`:
`z = ((z^(z>>30))·0xBF58476D1CE4E5B9)`,
`z = ((z^(z>>27))·0x94D049BB133111EB)`, `z ^= (z>>31)`, all mod 2^64);
direction = bit 32 of `z`. Stateless and seekable: header, body, and
robust triplets need no shared RNG state, and ports agree trivially.
Public (salt is in the header); it exists to break directional bias, not
to hide anything. Decode reads LSBs only; directions are never stored.

Rationale (documented, not claimed): ±1 keeps `E[count(2k)] ≈
E[count(2k+1)]` symmetric, which is exactly what chi-square / RS / SPA
detectors key on under LSB replacement. Benchmarks in `docs/ANALYSIS.md`
quantify the gap; v4 claims REDUCTION, never invisibility.

### 2.6 Robustness (ROBUST)

Reed–Solomon `RS(255,223)` over `GF(2^8)` (primitive poly `0x11D`,
generator roots α^0..α^31, `t = 16` correctable bytes per block) +
full block interleave, then the codeword stream is embedded exactly
like a normal body (STC/greedy per flags). Precise framing
(bit-exact across ports):
- Input is the AEAD ciphertext `C` (`orig+20` bytes). Pad with zero
  bytes to a multiple of 223 → `nblocks`; each 223B chunk encodes
  systematically to 255B as `data || parity` (parity = remainder of
  `data·x^32` by the generator polynomial).
- Interleave (depth = block count): stream byte `s` ← block
  `(s mod nblocks)` byte `(s div nblocks)`. A burst of `B` bytes hits
  each block ~`B/nblocks` times (tolerated while ≤ 16 per block).
- `comp_size = nblocks·255`. Decoders recompute
  `nblocks = ceil((orig+20)/223)` from `orig_size` and REQUIRE
  `comp_size == nblocks·255` exactly, depad by truncating the
  concatenated data parts to `orig+20`, and fail closed on any
  undecodable block. Survives: PNG re-encode (lossless), scattered
  burst flips within budget, metadata rewrite. Does NOT survive:
  resize, crop, rotation, JPEG recompression (documented non-goal).

### 2.7 Non-goals (explicit)

- No JPEG-domain mode in v4 (carriers are PNG end-to-end; a DCT mode
  would be a different library, not a flag).
- No deniability / public-key stego (password-pre-shared model only).
- No ML-proof claims: `docs/ANALYSIS.md` reports measured detector
  response (chi-square, RS, SPA, calibrated-feature linear probe), never
  "undetectable".

### 2.8 Version / ABI

`STEGO_FORMAT_V4 = 0x0004` names the v4 envelope;
`STEGO_FORMAT_VERSION` keeps meaning "newest envelope this build WRITES"
(= `0x0004`), while decoders accept `{0x0003, 0x0004}`. `STEGO_ABI_VERSION`
is unchanged (`0x0001`): the C ABI is untouched (same function signatures;
the version rides inside the image bytes). KDF agility (`kdf_id`,
§2.1) and the `STC`/`ROBUST` framings are backward-safe by AEAD: old
decoders fail closed on what they cannot parse — never misdecode.
Golden vectors: all v3 vectors MUST still pass byte-identical; new v4
vectors are added alongside.
