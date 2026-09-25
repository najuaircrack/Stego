# Contributing to stego

1. **Spec first.** Behavior changes start in `docs/FORMAT.md`. No code
   without a spec paragraph.
2. **No new dependencies** without discussion (C++ core must stay
   stdlib-only; Python: Pillow only; Rust: C++ toolchain only).
3. **Vectors required.** Every codec change ships golden vectors
   (`tests/gen_vectors.py`) plus malformed/boundary cases. Cross-impl
   matrix (C++/Python/Rust/harness/amalgam) must stay green.
4. **Execution boundary.** The library encodes/decodes bytes and never
   executes payloads. The `examples/fetch_run.*` templates are the single
   sanctioned place for download-decode-execute flows: they carry explicit
   warnings, validate magic bytes, and refuse on decode failure. New
   execution-adjacent features (loaders, runners, persistence) do not
   belong here - propose them as separate projects instead.
5. **Interop is sacred.** C++, Python, and Rust must agree bit-for-bit;
   prove it with vectors, not reasoning.
6. **Docs with code.** API/FORMAT/MIGRATION updates ride in the same change.
