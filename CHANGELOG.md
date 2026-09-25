# Changelog

All notable changes to the stego library. Format: Keep a Changelog.
Versions: semantic (`VERSION` file is authoritative).

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
