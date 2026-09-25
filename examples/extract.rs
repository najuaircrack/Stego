// extract.rs — template: decode an image file to a payload file.
// Usage: extract <image.png> <out.bin> [password]
// Decode only. What you DO with the bytes afterwards is your responsibility.
//
// PNG loading: `image` crate (add `image = "0.25"` to your own Cargo.toml;
// kept out of the library so the template stays dependency-explicit).
use std::env;
use stego::{decode, StegoError};

fn load_rgb(path: &str) -> Result<(Vec<u8>, u32, u32), String> {
    let img = image::open(path).map_err(|e| e.to_string())?.to_rgb8();
    let (w, h) = img.dimensions();
    Ok((img.into_raw(), w, h))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: extract <image.png> <out.bin> [password]");
        std::process::exit(2);
    }
    let pw = args.get(3).map(|s| s.as_str());
    let (rgb, w, h) = load_rgb(&args[1]).unwrap_or_else(|e| {
        eprintln!("load failed: {e}");
        std::process::exit(2);
    });
    match decode(&rgb, w, h, pw) {
        Ok(payload) => {
            std::fs::write(&args[2], &payload).unwrap_or_else(|e| {
                eprintln!("write failed: {e}");
                std::process::exit(1);
            });
            println!("decoded {} bytes", payload.len());
        }
        Err(StegoError::Auth) => {
            eprintln!("decode failed: authentication/password");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("decode failed: {e:?}");
            std::process::exit(1);
        }
    }
}
