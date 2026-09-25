# STEGO format specification (normative, version 3.0.0)

All integers little-endian. One envelope format, no fallbacks: decoders
read the 44-byte header (magic + version + header CRC) and reject anything
else. `STEGO_FORMAT_VERSION` (currently `0x0003`) names the envelope
layout; `STEGO_ABI_VERSION` (currently `0x0001`) names the C ABI - a format
bump MUST NOT imply an ABI bump. All cryptography uses SHA-256 (see note
inside `src/sha256.cpp` for the implementation source).

## Key derivation (password mode)

- Password encoding: UTF-8 bytes as given.
- KDF: PBKDF2-HMAC-SHA256, **100,000 iterations**, 16-byte random salt
  (stored in header), 64-byte output: `[0..32)` encryption key,
  `[32..64)` authentication key.
- Salt doubles as the CTR nonce (unique keystream per message).

## Envelope header (44 bytes, always present)

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

## Data region

Header pixels `[0,118)` are ALWAYS sequential (findable without the seed).
The body stream (ciphertext + `data_crc32` [+ HMAC tag]) starts at body
stream bit 0, placed via `PlacementRange(118, N-118, seed)` - i.e. body bit
`m` lives in pixel `perm[m/3]`, channel `m%3`, where `perm` is the
Fisher-Yates permutation of pixels `[118,N)`. `seed == 0` degenerates to
sequential placement for the whole image.

Images without the magic, with a wrong version, or with failing CRC/HMAC
are rejected outright - there is no legacy layout to fall back to.

## Stage pipeline (encode order; decode reverses)

1. Optional `COMPRESS` (currently rejected by encoders - backend deferred).
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

## Key derivation

- Password encoding: UTF-8 bytes as given.
- KDF: PBKDF2-HMAC-SHA256, 100,000 iterations, 16-byte random salt stored
  in the header, 64-byte output split into encryption key `[0..32)` and
  authentication key `[32..64)`.
- Salt doubles as the CTR nonce: unique keystream per message.
