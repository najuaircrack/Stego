# INTEGRATION - linking the library into products

## CMake (recommended)

```cmake
add_subdirectory(<path-to-stego>)          # provides stego::stego
target_link_libraries(myproduct PRIVATE stego::stego)
```

Requires C++17. No third-party dependencies (SHA-256/CRC/HMAC/PRNG are
vendored; compression backend intentionally absent - see `FORMAT.md`).
`STEGO_BUILD_TESTS=OFF` skips the test targets for slim embeds.

## Replacing hand-rolled decoders

If your product duplicates a subset of this library (sequential LSB + size
header + magic check), migration is:

1. Link `stego::stego`, delete the local decoder.
2. Convert PNG to RGB (GDI+ glue in `examples/`, or existing product code).
3. Call `stego::Decode(rgb)` with the channel password: valid envelope
   images decode, everything else is rejected.
4. (Re-)embed hosted images with `stego_cli.py hide --password P --auth`.

## Constraints the library guarantees

- No file IO, no network, no logging, no exceptions across the API.
- No global state (PRNG/stream state is per-call; thread-safe).
- Deterministic: same inputs produce identical output on all platforms
  (fixed integer widths, no float, no RNG beyond the seeded stream).
