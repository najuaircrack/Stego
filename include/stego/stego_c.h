// stego_c.h - thin C ABI (FFI/Lua-ready). Mirrors stego.h semantics.
//
// Ownership: all inputs are borrowed (caller retains). Outputs marked
// callee-allocated MUST be released with stego_free(). Error codes are
// stable across STEGO_ABI_VERSION bumps (new codes only ever appended).
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "stego/format.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEGO_C_OK 0
#define STEGO_C_ERR_PARAM -1
#define STEGO_C_ERR_CAPACITY -2
#define STEGO_C_ERR_FORMAT -3
#define STEGO_C_ERR_CRC -4
#define STEGO_C_ERR_AUTH -5
#define STEGO_C_ERR_UNSUPPORTED -6  // e.g. COMPRESS flag (no backend yet)

typedef struct {
    uint32_t w, h;
    uint8_t* rgb;      // caller-owned w*h*3 buffer
} stego_image_t;

typedef struct {
    int compress;      // reserved, must be 0
    int scatter;
    uint32_t seed;
    const char* password;  // NULL/empty = none
    int auth;
} stego_options_t;

// out_rgb must hold w*h*3 bytes. Returns STEGO_C_*.
int stego_encode(const stego_image_t* cover,
                 const uint8_t* payload, size_t payload_len,
                 const stego_options_t* opt, uint8_t* out_rgb);

// out/out_len: callee mallocs (caller frees with stego_free).
// NOTE: stego_decode currently collapses all decode failures (bad format,
// CRC mismatch, auth failure, wrong password) to STEGO_C_ERR_FORMAT.
// _CRC/_AUTH codes are reserved for granular reporting in a later ABI
// bump (STEGO_ABI_VERSION will change if their meaning is ever used).
int stego_decode(const stego_image_t* img, const char* password,
                 uint8_t** out, size_t* out_len);
void stego_free(void* p);
const char* stego_version(void);

#ifdef __cplusplus
}
#endif
