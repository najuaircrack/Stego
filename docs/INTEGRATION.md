# INTEGRATION — linking the library into products

## CMake (recommended)

```cmake
add_subdirectory(<path-to-stego>)          # provides stego::stego
target_link_libraries(myproduct PRIVATE stego::stego)
```

Requires C++17. No third-party dependencies (SHA-256/CRC/HMAC/PRNG are
vendored; compression backend intentionally absent — see `FORMAT.md`).
`STEGO_BUILD_TESTS=OFF` skips the test targets for slim embeds.

## Replacing hand-rolled decoders

Both in-tree consumers (`tools/installer/src/stego.cpp`,
`tools/dist-windows/modules/common/src/stego.cpp`) duplicate a subset of
this library (sequential LSB + size header + MZ check). Migration:

1. Link `stego::stego`, delete the local decoder.
2. Convert PNG to RGB (GDI+ glue in `examples/`, or existing product code).
3. Call `stego::Decode(rgb)`: current images AND legacy v1 images both
   decode, so already-hosted files keep working during rollout.
4. Re-embed hosted images in the current format when convenient
   (procedure: `docs/MIGRATION.md`); keep the legacy read path until then.

## Constraints the library guarantees

- No file IO, no network, no logging, no exceptions across the API.
- No global state (PRNG/stream state is per-call; thread-safe).
- Deterministic: same inputs produce identical output on all platforms
  (fixed integer widths, no float, no RNG beyond the seeded stream).
