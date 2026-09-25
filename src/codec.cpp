// codec.cpp - header, scatter placement, LSB engine, CRC helpers.
// Splits exactly per docs/FORMAT.md. PRNG must match python/stegolib.py
// bit-for-bit (golden vectors in tests/vectors/).
#include "stego/format.h"
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

namespace stego {
namespace sha {
std::vector<uint8_t> Hash(const uint8_t* data, size_t len);
void KeystreamRaw(const uint8_t* key32, uint8_t* out, size_t len);
std::vector<uint8_t> Hmac(const uint8_t* key, size_t klen,
                           const uint8_t* msg, size_t mlen);
uint32_t Crc32(const uint8_t* data, size_t len);
}  // namespace sha

namespace codec {

void PutU16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back((uint8_t)v);
    b.push_back((uint8_t)(v >> 8));
}

void PutU32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; i++) b.push_back((uint8_t)(v >> (i * 8)));
}

// splitmix64 -> xorshift128+ (matches python/stegolib.py exactly).
static uint64_t Splitmix64(uint64_t& s) {
    uint64_t z = (s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

struct Xor128 {
    uint64_t s[2];
    explicit Xor128(uint64_t seed) {
        uint64_t t = seed;
        s[0] = Splitmix64(t);
        s[1] = Splitmix64(t);
        if (s[0] == 0 && s[1] == 0) s[1] = 0x9E3779B97F4A7C15ull;
    }
    uint64_t Next() {
        uint64_t x = s[0], y = s[1];
        s[0] = y;
        x ^= x << 23;
        s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
        return s[1] + y;
    }
};

// Placement order for nPx pixels: identity when seed==0, else Fisher-Yates
// with Xor128 draws (j = Next() % (i+1), walking i from n-1 down).
std::vector<uint32_t> Placement(uint32_t nPx, uint32_t seed) {
    std::vector<uint32_t> p(nPx);
    for (uint32_t i = 0; i < nPx; i++) p[i] = i;
    if (seed != 0 && nPx > 1) {
        Xor128 r(seed);
        for (uint32_t i = nPx - 1; i > 0; i--) {
            uint32_t j = (uint32_t)(r.Next() % (i + 1));
            uint32_t t = p[i];
            p[i] = p[j];
            p[j] = t;
        }
    }
    return p;
}

// Placement over pixel range [base, base+count): same shuffle, offset ids.
// Header pixels [0,75) are always sequential; body uses PlacementRange.
std::vector<uint32_t> PlacementRange(uint32_t base, uint32_t count,
                                            uint32_t seed) {
    std::vector<uint32_t> p(count);
    for (uint32_t i = 0; i < count; i++) p[i] = base + i;
    if (seed != 0 && count > 1) {
        Xor128 r(seed);
        for (uint32_t i = count - 1; i > 0; i--) {
            uint32_t j = (uint32_t)(r.Next() % (i + 1));
            uint32_t t = p[i];
            p[i] = p[j];
            p[j] = t;
        }
    }
    return p;
}

// Set bit k of the bitstream into image (3 bits per pixel, R,G,B order).
void PutBit(std::vector<uint8_t>& rgb, uint32_t w,
                   const std::vector<uint32_t>& place, size_t k, int bit) {
    uint32_t p = place[k / 3];
    uint32_t y = p / w, x = p % w;
    uint8_t& ch = rgb[(y * w + x) * 3 + (k % 3)];
    ch = (uint8_t)((ch & 0xFE) | (bit & 1));
}

int GetBit(const std::vector<uint8_t>& rgb, uint32_t w,
                  const std::vector<uint32_t>& place, size_t k) {
    uint32_t p = place[k / 3];
    uint32_t y = p / w, x = p % w;
    return rgb[(y * w + x) * 3 + (k % 3)] & 1;
}

}  // namespace codec
}  // namespace stego
