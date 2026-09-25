//! Raw FFI bindings to `stego_c.h` (hand-written: the C ABI is five
//! functions, so no bindgen/libclang dependency). Types mirror the header
//! with `repr(C)` and fixed-width integers.
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_uchar};
// NOTE: size_t maps to usize (c_ulong is 32-bit on MSVC Windows — must NOT
// be used for size_t). All buffer lengths are usize.

pub const STEGO_C_OK: c_int = 0;
pub const STEGO_C_ERR_PARAM: c_int = -1;
pub const STEGO_C_ERR_CAPACITY: c_int = -2;
pub const STEGO_C_ERR_FORMAT: c_int = -3;
pub const STEGO_C_ERR_CRC: c_int = -4;
pub const STEGO_C_ERR_AUTH: c_int = -5;
pub const STEGO_C_ERR_UNSUPPORTED: c_int = -6;

#[repr(C)]
pub struct stego_image_t {
    pub w: u32,
    pub h: u32,
    pub rgb: *mut u8,
}

#[repr(C)]
pub struct stego_options_t {
    pub compress: c_int,
    pub scatter: c_int,
    pub seed: u32,
    pub password: *const c_char,
    pub auth: c_int,
}

extern "C" {
    pub fn stego_encode(
        cover: *const stego_image_t,
        payload: *const u8,
        payload_len: usize,
        opt: *const stego_options_t,
        out_rgb: *mut u8,
    ) -> c_int;
    pub fn stego_decode(
        img: *const stego_image_t,
        password: *const c_char,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn stego_free(p: *mut u8);
    pub fn stego_version() -> *const c_char;
}

// ABI note: the C side uses size_t throughout; usize is the only correct
// mapping on all supported targets (MSVC, GCC, Clang, 32- and 64-bit).
