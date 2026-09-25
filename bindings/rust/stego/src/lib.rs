//! Safe wrapper over `stego-sys`: steganographic encode/decode of
//! arbitrary bytes in RGB images. Decode-only extraction; this crate does
//! not execute recovered payloads.
use std::ffi::CString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoError {
    Param,
    Capacity,
    Format,
    Crc,
    Auth,
    Unsupported,
    Unknown(i32),
}

impl StegoError {
    fn from_code(c: i32) -> Self {
        match c {
            -1 => StegoError::Param,
            -2 => StegoError::Capacity,
            -3 => StegoError::Format,
            -4 => StegoError::Crc,
            -5 => StegoError::Auth,
            -6 => StegoError::Unsupported,
            x => StegoError::Unknown(x),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub scatter: bool,
    pub seed: u32,
    pub password: Option<String>,
    pub auth: bool,
}

/// Encode `payload` into `cover_rgb` (w*h*3 bytes). Returns full RGB image.
pub fn encode(
    cover_rgb: &[u8],
    w: u32,
    h: u32,
    payload: &[u8],
    opt: &Options,
) -> Result<Vec<u8>, StegoError> {
    if cover_rgb.len() < w as usize * h as usize * 3 {
        return Err(StegoError::Param);
    }
    let pw = opt.password.as_ref().map(|s| CString::new(s.as_str()).unwrap());
    let raw = stego_sys::stego_options_t {
        compress: 0,
        scatter: opt.scatter as std::os::raw::c_int,
        seed: opt.seed,
        password: pw.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null()),
        auth: opt.auth as std::os::raw::c_int,
    };
    let img = stego_sys::stego_image_t {
        w,
        h,
        rgb: cover_rgb.as_ptr() as *mut u8,
    };
    let mut out = vec![0u8; cover_rgb.len()];
    let rc = unsafe {
        stego_sys::stego_encode(&img, payload.as_ptr(), payload.len(), &raw, out.as_mut_ptr())
    };
    if rc == stego_sys::STEGO_C_OK {
        Ok(out)
    } else {
        Err(StegoError::from_code(rc))
    }
}

/// Decode an RGB image. `password` required iff the image demands it.
pub fn decode(
    rgb: &[u8],
    w: u32,
    h: u32,
    password: Option<&str>,
) -> Result<Vec<u8>, StegoError> {
    if rgb.len() < w as usize * h as usize * 3 {
        return Err(StegoError::Param);
    }
    let pw = password.map(|s| CString::new(s).unwrap());
    let img = stego_sys::stego_image_t {
        w,
        h,
        rgb: rgb.as_ptr() as *mut u8,
    };
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut len: usize = 0;
    let rc = unsafe {
        stego_sys::stego_decode(
            &img,
            pw.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null()),
            &mut out,
            &mut len,
        )
    };
    if rc != stego_sys::STEGO_C_OK {
        return Err(StegoError::from_code(rc));
    }
    let v = unsafe { std::slice::from_raw_parts(out, len).to_vec() };
    unsafe { stego_sys::stego_free(out) };
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cover(w: u32, h: u32) -> Vec<u8> {
        vec![0u8; w as usize * h as usize * 3]
    }

    #[test]
    fn roundtrip_plain() {
        let img = cover(64, 64);
        let msg = b"hello-rust".to_vec();
        let enc = encode(&img, 64, 64, &msg, &Options::default()).unwrap();
        assert_eq!(decode(&enc, 64, 64, None).unwrap(), msg);
    }

    #[test]
    fn roundtrip_scatter_auth() {
        let img = cover(64, 64);
        let msg: Vec<u8> = (0..300).map(|i| (i * 7) as u8).collect();
        let opt = Options {
            scatter: true,
            seed: 4242,
            password: Some("pw".into()),
            auth: true,
        };
        let enc = encode(&img, 64, 64, &msg, &opt).unwrap();
        assert_eq!(decode(&enc, 64, 64, Some("pw")).unwrap(), msg);
    }

    #[test]
    fn wrong_password_fails() {
        let img = cover(64, 64);
        let opt = Options {
            password: Some("right".into()),
            auth: true,
            ..Default::default()
        };
        let enc = encode(&img, 64, 64, b"data", &opt).unwrap();
        assert!(decode(&enc, 64, 64, Some("wrong")).is_err());
    }

    #[test]
    fn malformed_rejected() {
        let img = cover(32, 32); // 3072 zero bytes: v1 size 0 -> reject
        assert!(decode(&img, 32, 32, None).is_err());
    }
}
