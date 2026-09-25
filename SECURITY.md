# Security Policy

Supported versions (security fixes only):

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| < 2.1   | :x:                |

## Scope

In scope: the codec (`src/`), key derivation and authentication
(`src/sha256.cpp`), format parsing (`Decode` paths in all implementations),
and the C ABI boundary.

Out of scope: `examples/fetch_run.*` operator behavior (dual-use templates;
see `docs/SECURITY.md`), third-party toolchains, hosting infrastructure.

## Reporting a vulnerability

Open a GitHub issue with the `security` label including a minimal reproducer
(image + expected vs actual behavior), or contact the maintainers through
https://github.com/najuaircrack/Stego. Please allow 90 days before public
disclosure.

## Guarantees this project makes

- Decoders fail cleanly on corrupt, truncated, mistyped, oversized-claim,
  wrong-password, and tampered inputs (proven by the malformed battery in
  `tests/`). They never allocate from untrusted sizes and never execute
  recovered bytes.
- What this project does NOT promise: undetectability of LSB embedding
  (chi-square/RS-visible by design), confidentiality without a strong
  password, or safety of any payload you choose to run.

Full threat model: `docs/SECURITY.md`.
