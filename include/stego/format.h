// format.h — wire constants (mirrors docs/FORMAT.md).
#pragma once
#include <stdint.h>

#define STEGO_MAGIC_0 'S'
#define STEGO_MAGIC_1 'T'
#define STEGO_MAGIC_2 'G'
#define STEGO_MAGIC_3 '2'

// Latest WRITTEN format. Decoders additionally accept 0x0002 and legacy v1.
#define STEGO_FORMAT_VERSION 0x0003
// C ABI stability marker. A format bump MUST NOT imply an ABI bump.
#define STEGO_ABI_VERSION 0x0001

#define STEGO_HEADER_LEN 28     // v2 header bytes (legacy read path)
#define STEGO_HEADER_V3_LEN 44  // v3 header bytes (current write path)
#define STEGO_HEADER_PX 75      // header pixels reserved (v2 layout)
#define STEGO_HEADER_V3_PX 118  // header pixels reserved (v3 layout)

#define STEGO_SALT_LEN 16
#define STEGO_PBKDF2_ITER 100000
#define STEGO_PBKDF2_OUT 64     // 32 enc-key + 32 auth-key

#define STEGO_F_COMPRESS 0x0001  // reserved: encoders reject for now
#define STEGO_F_SCATTER  0x0002
#define STEGO_F_ENCRYPT  0x0004
#define STEGO_F_AUTH     0x0008

#define STEGO_HMAC_LEN 32
#define STEGO_AUTH_DOMAIN "stego-auth-v2"
