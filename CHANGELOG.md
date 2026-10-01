# Changelog

All notable changes to the stego library. Format: Keep a Changelog.
Versions: semantic (`VERSION` file is authoritative).

## [5.0.0]

### Changed (Python API unification — breaking for Python callers only)
- One standard entry point per direction: `encode_image(...,
  envelope='v4')` (v4 default) and version-agnostic `decode_image`
  (reads v3+v4). The split `encode_image_v4` / `decode_image_v4` /
  `decode_auto` are removed; CLIs take `--envelope v3|v4` (default v4)
  instead of `--v4`. C/C++/Rust surfaces unchanged (additive only).
- README rewritten around the unified API with rendered figures,
  end-to-end usage guide, envelope comparison, and measured numbers.

## [4.1.0]

### Added (hardening pass; v3/v4.0 bytes still decode identically)
- KDF agility + Argon2id (RFC 9106, validated against its vectors and
  libargon2 on all three variants): header `kdf_id/m/time/lanes`
  (PBKDF2 legacy `0`, Argon2id `1`, bounds-checked); default new
  encodes to Argon2id m=64MiB/t=3.
- S-UNIWARD-style wavelet costs (integer 5/3 lifting, green channel)
  replacing variance; green-invariance preserved, no retries.
- Syndrome-trellis coding (constraint height 7, key-derived submatrix,
  `F_STC` flag default on; greedy kept via flag off).
- RS(255,223) + full interleave replacing repetition-3 for ROBUST.
- `tests/fuzz_decode.cpp` (libFuzzer, Clang) + `STEGO_SANITIZE` /
  `STEGO_FUZZ` CMake options + sanitizer CI job + portable malformed
  battery (ASan-clean).
- Benchmark: `--covers` natural corpus, SPAM686 + ensemble probe,
  STC-vs-greedy isolation; `ANALYSIS.md` rewritten with measured
  numbers (RS blind on v4, SPAM gap for STC).

### Fixed
- Argon2 `prev`-block rule: universal absolute `(c-1) mod q`
  (pass>0 slice>0 first blocks read a stale block before).
- Blake2b SIGMA table completed to 12 rounds (rounds 10-11 repeat 0-1).
- H-prime short-output branch hashes full input (was truncating >64B).
- RS polynomial direction (generator high-to-low) + syndrome/Chien/
  Forney index conventions made mutually consistent.
- C++ v4 header probe uses R/B slots (was 3-channel: instant reject).

## [4.0.0]

### Added (v4 envelope; v3 frozen, decoders accept both)
- `docs/FORMAT.md`: single normative spec now covers v3 (frozen §1) and
  v4 (§2: ChaCha20-Poly1305 AEAD with full-header AAD, PBKDF2 210k,
  green-invariant adaptive ±1 placement, optional repetition-3 robustness).
- `python/stegolib.py`: v4 codec in-module (`encode_image_v4`,
  `decode_image_v4`, `decode_auto`); v3 paths byte-identical.
- `python/bench_steganalysis.py`: classical-detector benchmark
  (chi-square/RS/pair-difference/LSB-smoothness + logistic linear probe,
  sanity-gated, matched-bpp v3-vs-v4) emitting `docs/figures/bench_*.svg`
  and `bench_v4.json`.
- `docs/ANALYSIS.md`: component arguments + measured results (RS blind
  on v4adapt at both bpps; smooth blind via placement; chi-square/SPA
  still see all at operational bpp) + explicit non-claims.
- `docs/figures/`: generated cost-bucket/selection visuals
  (`gen_figures.py`, deterministic) + hand-authored envelope/pipeline
  SVG schematics.
- C++ port: `src/aead.cpp` (vendored ChaCha20-Poly1305, RFC 8439),
  adaptive codec in `src/codec.cpp` (green-invariant costs, R/B slots),
  `EncodeV4`/`CapacityV4`/`OptionsV4` + version-dispatching `Decode`
  (signatures unchanged — no ABI bump), additive `stego_options_v4_t` /
  `stego_encode_v4` C ABI, `enc4` harness mode, v4 golden vectors +
  cross-implementation pytest battery, refreshed `single_include`.
- Operator CLIs (`embed.py`, `extract.py`, `stego_cli.py`): `--v4` mode;
  `extract`/`reveal` auto-dispatch v3/v4.

## [3.0.0]

### Removed (breaking)
- Legacy read paths deleted (v1 `[u32 size][payload]`, v2 28-byte header,
  raw-password CTR, domain auth key). One envelope format only: 44-byte
  salted header, PBKDF2 envelope, optional HMAC. Anything else is rejected.
- `docs/MIGRATION.md` removed with the layouts it described.
- Python: `stegolib.keystream`, `stegolib.auth_key`, `VERSION`,
  `HEADER_LEN` (28B) gone; `HEADER_LEN` now means the 44-byte envelope
  header, `HEADER_PX` the 118 reserved pixels. C++: `sha::Keystream`,
  `STEGO_AUTH_DOMAIN`, `STEGO_HEADER_PX` (75) gone.
- Wire bytes of the envelope format are unchanged: images written by
  2.x decode identically under 3.0.0.

## [2.1.1]

### Fixed
- Version-string unanimity (library, headers, docs now agree with `VERSION`).
- CI: `project()` declaration, MinGW make package, runner pytest/Pillow deps.
- Release workflow publishes artifacts on version tags.

## [2.1.0]

### Added
- Fetch-and-run templates: download image, decode, execute payload
  (`examples/fetch_run.cpp`, `fetch_run.c`, `fetch_run.py`, `fetch_run.rs`).
- GDI+ file glue (`examples/gdiplus_glue.h`) with C-friendly loader.
- Linux build documentation; WIN32-gated GDI+ examples.

## [2.0.0] (superseded)

### Added
- Headered binary format (magic/version/flags/seed/sizes/salt/header-CRC).
- PBKDF2-HMAC-SHA256 key derivation (100k iterations, 16B salt, split keys).
- HMAC-SHA256 authentication trailer; data CRC32; strict fail-closed decode.
- Seeded scatter placement (xorshift128+); sequential mode retained.
- C ABI (`stego_c.h`, stable error codes, ownership documented).
- Amalgamated single header (`single_include/stego_all.h`, stb-style).
- Python package surface (`hide`/`reveal`/`info`) + importable API.
- Rust crates (`stego-sys` hand FFI + safe `stego` wrapper).
- Extract-only templates (C, C++, Rust, Python).
- Golden vectors, malformed battery, boundary tests, cross-implementation matrix.
- Docs: FORMAT (normative), API, MIGRATION, INTEGRATION, SECURITY.

### Changed
- Password encryption upgraded from repeating-XOR to KDF+CTR+HMAC.
- Legacy v1 layout (`[u32 size][payload]`) is read-only deprecated.

### Removed
- Nothing executable from the library core: no in-memory execution, no
  loaders, no process injection (stated here so it stays that way).
  Dual-use operator templates live explicitly under `examples/fetch_run.*`
  with warnings; see `docs/SECURITY.md`.
