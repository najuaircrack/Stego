// format.h - wire constants (mirrors docs/FORMAT.md).
#pragma once
#include <stdint.h>

#define STEGO_MAGIC_0 'S'
#define STEGO_MAGIC_1 'T'
#define STEGO_MAGIC_2 'G'
#define STEGO_MAGIC_3 '2'

// The single envelope format. Decoders accept ONLY this version -
// anything else (including the retired v1/v2 layouts) is rejected.
#define STEGO_FORMAT_VERSION 0x0003
// C ABI stability marker. A format bump MUST NOT imply an ABI bump.
#define STEGO_ABI_VERSION 0x0001

#define STEGO_HEADER_LEN 44  // envelope header bytes
#define STEGO_HEADER_PX 118  // header pixels reserved (always sequential)

#define STEGO_SALT_LEN 16
#define STEGO_PBKDF2_ITER 100000
#define STEGO_PBKDF2_OUT 64     // 32 enc-key + 32 auth-key

#define STEGO_F_COMPRESS 0x0001  // reserved: encoders reject for now
#define STEGO_F_SCATTER  0x0002
#define STEGO_F_ENCRYPT  0x0004
#define STEGO_F_AUTH     0x0008

#define STEGO_HMAC_LEN 32
