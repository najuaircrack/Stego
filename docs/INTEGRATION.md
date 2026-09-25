# INTEGRATION - linking the library into products

## CMake (recommended)

```cmake
add_subdirectory(<path-to-stego>)          # provides stego::stego
target_link_libraries(myproduct PRIVATE stego::stego)
```

Requires C++17. No third-party dependencies (SHA-256/CRC/HMAC/PRNG are
vendored; compression backend intentionally absent - see `FORMAT.md`).
`STEGO_BUILD_TESTS=OFF` skips the test targets for slim embeds.

## Prebuilt static lib (Windows x64, no library build)

Each release ships `stego.lib` + `stego_all.h` (same version - never mix).
The header without `STEGO_IMPLEMENTATION` is the declarations file; the
`.lib` provides the symbols. Proven combo (round-trip verified):

```cpp
// app.cpp - include the header WITHOUT STEGO_IMPLEMENTATION.
// Defining STEGO_IMPLEMENTATION here duplicates the .lib symbols.
#include "stego_all.h"

stego::Image cover{ w, h, rgb };
stego::Options opt;
opt.password = "pw"; opt.auth = true;
stego::Image out;
stego::Encode(cover, payload, len, opt, out);
```

Rules:

- **CRT must match.** The published `stego.lib` is built with the default
  dynamic CRT (`/MD` - check with `dumpbin /DIRECTIVES stego.lib`, look
  for `/DEFAULTLIB:MSVCRT`). Your project must use `/MD` too; mixing
  `/MT` gives `LNK2038` mismatch errors. Need `/MT` (or another
  platform)? Use the `add_subdirectory` path above instead - same code,
  your flags.
- **C++17, x64.** `cl /MD /O2 /std:c++17 app.cpp stego.lib`
  (Developer Prompt), or in CMake:
  `target_link_libraries(myapp PRIVATE <path-to>/stego.lib)` with the
  header dir on the include path.
- **Smoke check first.** `stego::Version()` must equal the release tag
  (e.g. `"3.0.0"`) before trusting any other call.

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
