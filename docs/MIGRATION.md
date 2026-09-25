# MIGRATION — legacy layouts to the current format

## Legacy layouts (read-only forever)

- **v1:** `[u32 LE size][payload]`, sequential LSBs from pixel 0, R,G,B order.
  Produced by the original v1 `embed.py` (since replaced by `python/embed.py`).
- **v2:** 28-byte header (magic/version/flags/seed/sizes/reserved/header-CRC),
  body, data CRC, optional HMAC; raw-password CTR + domain-separated auth key.
  Produced by early 2.0.0 builds. Superseded, never fielded at scale.

Both remain **readable** by current decoders (deprecated read-only paths in
`Decode` / `decode_image`).

## Current format (v3, `STEGO_FORMAT_VERSION 0x0003`)

Headered salted envelope per `docs/FORMAT.md`: magic, version, flags, seed,
sizes, reserved, 16B salt, header CRC, scattered body, data CRC, optional
HMAC. Produced by `python/embed.py` (no flags = plain mode) or the C/C++
API. Password mode uses PBKDF2-HMAC-SHA256 (100k iterations) with split
enc/auth keys — v2-era raw-password images are NOT forward-readable by
design (re-embed them).

## Migrating a fielded image (e.g. agent channel)

1. Extract with the old tool: `old-extract.py <old.png> <payload.bin>`.
2. Re-embed current: `python/embed.py <cover.png> <payload.bin> <new.png>`.
3. Round-trip proof: extract the new image, SHA256-compare with the payload.
4. Update ALL consumers to current decoders BEFORE switching the hosted
   file (old decoders cannot read headered images — verify by reading the
   new image back with each consumer's code path).
5. Host the new file; retire the old one only after confirming end-to-end
   delivery on the new path.

## What changed and why

- Integrity: CRC32 header + payload (+ optional HMAC) replace blind trust.
- Placement: seeded scatter defeats sequential-scan steganalysis.
- Confidentiality: SHA-256-CTR replaces repeating-XOR (broken under
  known-plaintext).
- Deprecated, not removed: legacy read path stays so existing images
  remain recoverable during migration windows.
