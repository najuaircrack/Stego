// build.rs - compile the C++ core with the `cc` crate (no libclang needed).
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = root.join("../../..");
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .file(base.join("src/sha256.cpp"))
        .file(base.join("src/codec.cpp"))
        .file(base.join("src/api.cpp"))
        .include(base.join("include"))
        .compile("stego");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../include/stego/stego.h");
    println!("cargo:rerun-if-changed=../../include/stego/stego_c.h");
    println!("cargo:rerun-if-changed=../../include/stego/format.h");
    println!("cargo:rerun-if-changed=../../src/sha256.cpp");
    println!("cargo:rerun-if-changed=../../src/codec.cpp");
    println!("cargo:rerun-if-changed=../../src/api.cpp");
}
