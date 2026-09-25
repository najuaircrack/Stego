# Stego — portable steganography library + tools (2.0.0)

> **stego** is a portable steganography library and set of language bindings
> for storing arbitrary byte payloads inside PNG images. Deterministic
> encode/decode, capacity calculation, format/version handling, optional
> authenticated encryption, bindings for C/C++, Python, and Rust.
> The library does **not** execute recovered payloads.

## Layout

```
include/stego/   stego.h (C++ API), stego_c.h (C ABI), format.h (constants)
src/             sha256.cpp, codec.cpp, api.cpp
single_include/  stego_all.h (amalgamated; STEGO_IMPLEMENTATION in one TU)
python/          stegolib.py + embed.py / extract.py + stego_cli.py + pyproject
bindings/rust/   stego-sys (hand FFI) + stego (safe wrapper)
examples/        extract.{cpp,c,rs,py} — decode-to-file templates ONLY
tests/           CTest matrix + pytest (goldens, malformed, boundary, cross-impl)
docs/            FORMAT (normative) · API · MIGRATION · INTEGRATION · SECURITY
```

Success criterion: `encode(payload) → image → decode(image) == payload`,
identical across implementations.

## Quickstart

```powershell
# C++ library + tests (libraries only by default):
cmake -S tools/stego -B tools/stego/build -G "Visual Studio 18 2026" -A x64
cmake --build tools/stego/build --config Release            # stego.lib only
cmake -S tools/stego -B tools/stego/build -G "Visual Studio 18 2026" -A x64 `
  -DSTEGO_BUILD_TESTS=ON -DSTEGO_BUILD_EXAMPLES=ON          # + tests/examples

# Python (single command: hide / reveal / info):
python tools/stego/python/stego_cli.py hide payload.bin --cover cover.png -o out.png [--seed N] [--password P] [--auth] [--scatter]
python tools/stego/python/stego_cli.py reveal out.png -o back.bin [--password P]
python tools/stego/python/stego_cli.py info out.png

# Rust: see bindings/rust (cargo test; no libclang needed — hand FFI + cc crate)
```

```bash
# Linux (GCC): core library + C tests. GDI+ examples are Windows-only and
# skip automatically; extract.c (portable C99 + C ABI) builds everywhere.
cmake -S tools/stego -B build -DSTEGO_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure

# MinGW (.a static archive path): same tree with -G "MinGW Makefiles".
# Python anywhere: pip install Pillow && pytest tools/stego/tests/ -q
# Rust anywhere with a C++ toolchain: cargo test --manifest-path \
#   tools/stego/bindings/rust/stego/Cargo.toml
```

## Dependency honesty

- C/C++ core: standard library only. No third-party code.
- Python: Pillow (image IO only).
- Rust: a C++ toolchain (hand-written FFI compiles the core via `cc`).

## Security model (summary)

LSB embedding is **detectable** (chi-square/RS); scatter is distribution,
not invisibility. Encryption protects contents; steganography hides
existence/location. Raw mode = zero confidentiality. Recovered bytes are
untrusted. Full statement: `docs/SECURITY.md` (read before shipping).
