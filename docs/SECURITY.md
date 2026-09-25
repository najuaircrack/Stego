# SECURITY.md — stego threat model (read before shipping)

## What this library is and is not

- **Steganography is not encryption.** LSB embedding hides the *existence
  and location* of a payload from casual inspection. It does **not** make
  the payload undetectable: classic LSB is visible to chi-square and RS
  steganalysis, and scatter placement is a *distribution* mechanism, not a
  security guarantee. Do not claim undetectability.
- **Encryption protects contents.** Password mode (PBKDF2-HMAC-SHA256,
  100k iterations, 16B random salt, split enc/auth keys, SHA-256-CTR,
  HMAC-SHA256) is a defined construction (see `docs/FORMAT.md`). Raw
  no-password images provide **zero confidentiality**.
- **Recovered data is untrusted data.** Decoders validate structure
  (magic, version, CRC, HMAC) and fail cleanly, but a successfully decoded
  payload is still arbitrary bytes. This library **never executes**
  recovered payloads; execution examples do not exist in this project.

## Carrier rules

- **PNG only.** LSB layout is undefined for JPEG/WebP (lossy) and other
  formats. RGB is native; RGBA uses RGB channels (alpha ignored, stated);
  grayscale/palette inputs must be converted to RGB before encoding.
- Capacity is pixel-derived (`w*h*3` bits minus header/tag overhead), never
  file-size-derived. Encoders refuse oversize payloads explicitly.

## Password guidance

- Minimum 20 random characters for real secrecy; KDF is CPU-hard (~0.1s)
  but the keystream has no nonce beyond the per-message salt (reused
  passwords across images are isolated by unique salts — by design).
- Wrong password and tampered images fail with indistinguishable errors
  (no oracle beyond pass/fail).

## Reporting

Security issues in the crypto/format handling: open a private report with
a minimal reproducer (image + expected/actual). While pre-1.0, breaking
format fixes land as minor version bumps with migration notes.
