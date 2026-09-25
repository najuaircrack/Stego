# STEGO format specification (normative, version 2.0.0)

All integers little-endian. Layout versions: v1 `[u32 size][payload]`
sequential (read-only legacy); v2 28-byte header (read-only legacy);
**v3 44-byte salted envelope (current write path)**. Decoders try v3, then
v2, then v1. `STEGO_FORMAT_VERSION` (currently `0x0003`) names the written
layout; `STEGO_ABI_VERSION` (currently `0x0001`) names the C ABI — a format
bump MUST NOT imply an ABI bump. All cryptography uses SHA-256 (see note
inside `src/sha256.cpp` for the implementation source).

## Key derivation (v3 password mode)

- Password encoding: UTF-8 bytes as given.
- KDF: PBKDF2-HMAC-SHA256, **100,000 iterations**, 16-byte random salt
  (stored in header), 64-byte output: `[0..32)` encryption key,
  `[32..64)` authentication key.
- Salt doubles as the CTR nonce (unique keystream per message).
- v2 legacy path (read-only): raw-password CTR + domain-separated auth key
  (kept byte-compatible; never written by current encoders).

## v3 header (44 bytes, always present)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | `"STG2"` (`0x53 0x54 0x47 0x32`) |
| 4 | 2 | version | `0x0003` |
| 6 | 2 | flags | bit0 `COMPRESS`, bit1 `SCATTER`, bit2 `ENCRYPT`, bit3 `AUTH` |
| 8 | 4 | seed | PRNG seed for scatter placement (`0` = sequential legacy layout) |
| 12 | 4 | orig_size | plaintext payload bytes (u32) |
| 16 | 4 | comp_size | bytes after compress+encrypt stages (u32) |
| 20 | 4 | reserved | zero |
| 24 | 16 | salt | random per encode (KDF salt + CTR nonce) |
| 40 | 4 | header_crc32 | CRC32 (zlib poly `0xEDB88320`) of bytes `[0..40)` |

## v2 header (28 bytes, read-only legacy path)

Same as v3 minus the salt field: magic, version `0x0002`, flags, seed,
orig, comp, reserved, then `header_crc32` over bytes `[0..24)`.

## Data region

Header pixels `[0,75)` are ALWAYS sequential (findable without the seed).
The body stream (ciphertext + `data_crc32` [+ HMAC tag]) starts at body
stream bit 0, placed via `PlacementRange(75, N-75, seed)` — i.e. body bit
`m` lives in pixel `perm[m/3]`, channel `m%3`, where `perm` is the
Fisher-Yates permutation of pixels `[75,N)`. `seed == 0` degenerates to
sequential (legacy-compatible layout for the whole image).

v1 compatibility: v1 images carry no header; decoders attempt the
current header first (magic + header CRC), then fall back to the legacy
`[u32 size][payload]` sequential layout (read-only, deprecated).

## Stage pipeline (encode order; decode reverses)

1. Optional `COMPRESS` (currently rejected by encoders — backend deferred).
2. Optional `ENCRYPT`: SHA-256-CTR keystream.
   `keystream = SHA256(pw || BE32(counter))` concatenated from counter 0.
3. Scatter placement (if `SCATTER` or `seed != 0`): pixel permutation from
   xorshift128+ seeded by `splitmix64(seed)` (exact algorithm in `codec.cpp`;
   both implementations must match bit-for-bit — see golden vectors).
4. `data_crc32`: CRC32 of the ORIGINAL plaintext payload, appended as bits.
5. `AUTH` (requires `ENCRYPT`): `HMAC-SHA256(authkey, header[0..28) ||
   embedded-ciphertext-bytes)`, appended as bits, where
   `authkey = SHA256("stego-auth-v2" || password)`.
   NOTE: the tag covers header + ciphertext ONLY — `data_crc32` is
   deliberately outside the HMAC input (both sides must match exactly).

## Key derivation

- Encryption keystream: raw password bytes (UTF-8), no stretching
  (documented limitation; use long random passwords).
- Auth key: `SHA256("stego-auth-v2" || password)`.
