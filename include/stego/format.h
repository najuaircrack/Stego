// format.h - wire constants (mirrors docs/FORMAT.md).
#pragma once
#include <stdint.h>

#define STEGO_MAGIC_0 'S'
#define STEGO_MAGIC_1 'T'
#define STEGO_MAGIC_2 'G'
#define STEGO_MAGIC_3 '2'

// The frozen v3 envelope id. v3 bytes decode identically forever; v3
// encoders always write this (never STEGO_FORMAT_VERSION).
#define STEGO_FORMAT_V3 0x0003
// The v4 envelope id (AEAD + adaptive ternary placement, FORMAT.md §2).
#define STEGO_FORMAT_V4 0x0004
// Newest envelope this build WRITES. Decoders accept V3 and V4.
// A format bump MUST NOT imply an ABI bump (STEGO_ABI_VERSION below).
#define STEGO_FORMAT_VERSION STEGO_FORMAT_V4
// C ABI stability marker.
#define STEGO_ABI_VERSION 0x0001

#define STEGO_HEADER_LEN 44  // v3 envelope header bytes
#define STEGO_HEADER_PX 118  // v3 header pixels reserved (always sequential)

// v4 envelope (FORMAT.md §2): 64B header, R/B slots, AEAD body.
#define STEGO_V4_HEADER_LEN 64
#define STEGO_V4_HEADER_PX 256  // 256 px * 2 ch (R/B) = 512 header bits
#define STEGO_V4_SALT_LEN 16
#define STEGO_V4_PBKDF2_ITER 210000
#define STEGO_V4_KDF_OUT 96     // 32 msg-key + 12 nonce + 52 reserved
#define STEGO_V4_TAG_LEN 16
#define STEGO_V4_COSTQ_DEFAULT 8

#define STEGO_SALT_LEN 16
#define STEGO_PBKDF2_ITER 100000
#define STEGO_PBKDF2_OUT 64     // 32 enc-key + 32 auth-key

#define STEGO_F_COMPRESS 0x0001  // reserved: encoders reject for now
#define STEGO_F_SCATTER  0x0002
#define STEGO_F_ENCRYPT  0x0004
#define STEGO_F_AUTH     0x0008
#define STEGO_F_ADAPTIVE 0x0010  // v4: cost-ordered placement
#define STEGO_F_ROBUST   0x0020  // v4: repetition-3 + majority vote

#define STEGO_HMAC_LEN 32
