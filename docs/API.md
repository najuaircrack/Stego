# API — stego library usage

Version: 2.0.0 (`stego_version()` / `VERSION` file).

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

Rules: `COMPRESS` is rejected (no backend — see `docs/FORMAT.md`);
`AUTH` requires a non-empty password; `SCATTER` requires nonzero seed.
`Decode` accepts current images plus legacy v1 (`[u32 size][payload]`,
read-only deprecated path). Failures are silent booleans — no exceptions,
no logging (library never touches disk, network, or stdout).

## C ABI (`stego/stego_c.h`)

Same semantics over `stego_image_t` / `stego_options_t`; `stego_decode`
mallocs (free with `stego_free`); error codes `STEGO_C_OK`,
`_ERR_PARAM/_CAPACITY/_FORMAT/_CRC/_AUTH/_UNSUPPORTED`.

## Python (`python/stegolib.py` + CLIs)

```powershell
python python/embed.py <cover.png> <payload.bin> <out.png> [--seed N] [--password P] [--auth] [--scatter]
python python/extract.py <stego.png> <out.bin> [--password P]
```

`stegolib.encode_image / decode_image` mirror the C++ codec bit-for-bit
(proven by cross-implementation tests). Pillow required for PNG IO only.

## GDI+ glue (`examples/gdiplus_glue.h`, header-only, Windows)

`StegoLoadPng / StegoSavePng` convert PNG files to the RGB buffers the
library operates on. Caller owns `GdiplusStartup/Shutdown`.
