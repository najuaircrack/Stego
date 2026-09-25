# stego-tool (Python)

`stego hide / reveal / info` command plus the importable `stegolib` API -
PNG steganography bindings for the Stego C++ core (pure-Python codec,
bit-identical with all implementations).

```powershell
pip install stego-tool
stego hide payload.bin --cover photo.png -o out.png [--seed N] [--password P] [--auth] [--scatter]
stego reveal out.png -o back.bin [--password P]
stego info out.png
```

```python
from stegolib import encode_image, decode_image, capacity
```

Full docs: `../README.md`, spec: `../docs/FORMAT.md`. Pillow required.
License: MIT.
