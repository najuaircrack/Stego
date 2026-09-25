# API - stego library usage

Version: 3.0.0 (`stego_version()` / `VERSION` file).

## C++

```cpp
#include "stego/stego.h"

stego::Image cover{ w, h, rgb };          // RGB triplets, w*h*3 bytes
stego::Options opt;
opt.scatter = true; opt.seed = 12345;     // or all-default = plain mode
opt.password = "pw"; opt.auth = true;     // optional

stego::Image stego_img;
if (!stego::Encode(cover, payload, len, opt, stego_img)) { /* capacity/params */ }

std::vector<uint8_t> out;
if (!stego::Decode(stego_img, "pw", out)) { /* format/CRC/auth failure */ }

size_t max = stego::Capacity(w, h);       // payload-byte budget (conservative)
```

Rules: `COMPRESS` is rejected (no backend - see `docs/FORMAT.md`);
`AUTH` requires a non-empty password; `SCATTER` requires nonzero seed.
`Decode` accepts the single envelope format only; anything else is
rejected.
Failures are silent booleans - no exceptions, no logging (library never
touches disk, network, or stdout).

## C ABI (`stego/stego_c.h`)

Same semantics over `stego_image_t` / `stego_options_t`; `stego_decode`
mallocs (free with `stego_free`); error codes `STEGO_C_OK`,
`_ERR_PARAM/_CAPACITY/_FORMAT/_CRC/_AUTH/_UNSUPPORTED`.
NOTE: the current implementation collapses all decode failures to
`_FORMAT`; `_CRC`/`_AUTH` are reserved for granular reporting in a later
ABI bump (`STEGO_ABI_VERSION` will change if their meaning is ever used).

## Python (`python/stego_cli.py`, package `stego-tool`)

```powershell
python python/stego_cli.py hide payload.bin --cover cover.png -o out.png [--seed N] [--password P] [--auth] [--scatter]
python python/stego_cli.py reveal out.png -o back.bin [--password P]
python python/stego_cli.py info out.png
```

Older `python/embed.py` / `python/extract.py` predate the unified CLI and
remain working; new automation should use `stego_cli.py`.

`stegolib.encode_image / decode_image / capacity` mirror the C++ codec
bit-for-bit (proven by cross-implementation tests). Pillow required for
PNG IO only.

## Rust (`bindings/rust/stego` over `stego-sys`)

```rust
use stego::{encode, decode, Options};

let opt = Options { scatter: true, seed: 7,
                    password: Some("pw".into()), auth: true };
let img: Vec<u8> = encode(&cover_rgb, w, h, &payload, &opt)?;
let back: Vec<u8> = decode(&img, w, h, Some("pw"))?;
```

Safe wrapper: owned `Vec<u8>` in/out, `StegoError` enum, no panics on
library paths (NUL passwords and short buffers return errors). Raw FFI
lives in `stego-sys` (hand-written, no libclang; requires a C++ toolchain
to compile the core via the `cc` crate). `cargo test` covers round-trip,
wrong-password, and malformed inputs.

## GDI+ glue (`examples/gdiplus_glue.h`, header-only, Windows)

`StegoLoadPng / StegoSavePng` convert PNG files to the RGB buffers the
library operates on. Caller owns `GdiplusStartup/Shutdown`.
