// codec.cpp - header, scatter placement, LSB engine, CRC helpers.
// Splits exactly per docs/FORMAT.md. PRNG must match python/stegolib.py
// bit-for-bit (golden vectors in tests/vectors/).
#include "stego/format.h"
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <algorithm>

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

// --- v4 adaptive placement (FORMAT.md §2.4): green-channel costs,
// R/B slots. Green is never written, so decode-side costs are bit-exact.

static uint32_t ClampDim(int v, uint32_t lim) {
    if (v < 0) return 0;
    if ((uint32_t)v >= lim) return lim - 1;
    return (uint32_t)v;
}

// 3x3 green variance at every pixel (mirror edges), exact integer math:
// cost = (9*sumSq - sum*sum) / 81. Max ~5.3M: fits uint32, never underflows.
void CostMapGreen(const std::vector<uint8_t>& rgb, uint32_t w, uint32_t h,
                  std::vector<uint32_t>& cost) {
    cost.assign((size_t)w * h, 0);
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            uint32_t s = 0, q = 0;
            for (int dy = -1; dy <= 1; dy++) {
                uint32_t yy = ClampDim((int)y + dy, h);
                for (int dx = -1; dx <= 1; dx++) {
                    uint32_t xx = ClampDim((int)x + dx, w);
                    uint32_t v = rgb[((size_t)yy * w + xx) * 3 + 1];
                    s += v;
                    q += v * v;
                }
            }
            cost[(size_t)y * w + x] = (9 * q - s * s) / 81;
        }
    }
}

static unsigned BitLen32(uint32_t v) {
    unsigned n = 0;
    while (v) {
        n++;
        v >>= 1;
    }
    return n;
}

uint32_t CostBucket(uint32_t cost, uint32_t q) {
    if (q <= 1) return 0;
    uint64_t b = ((uint64_t)BitLen32(cost) * q) >> 4;
    return b >= q ? q - 1 : (uint32_t)b;
}

std::vector<uint32_t> CandidateOrderV4(const std::vector<uint8_t>& rgb,
                                       uint32_t w, uint32_t h, uint32_t seed,
                                       uint32_t q, bool adaptive) {
    uint32_t nPx = w * h;
    if (!adaptive)
        return PlacementRange(STEGO_V4_HEADER_PX, nPx - STEGO_V4_HEADER_PX,
                              seed);
    std::vector<uint32_t> cost;
    CostMapGreen(rgb, w, h, cost);
    std::vector<uint32_t> members[16];
    for (uint32_t i = STEGO_V4_HEADER_PX; i < nPx; i++) {
        uint32_t b = CostBucket(cost[i], q);
        if (b < 16) members[b].push_back(i);
    }
    std::vector<uint32_t> order;
    order.reserve(nPx);
    for (int b = 15; b >= 0; b--) {
        if (members[b].empty()) continue;
        std::vector<uint32_t>& m = members[b];
        std::sort(m.begin(), m.end());
        Xor128 r((uint64_t)seed ^ ((uint64_t)(b + 1) * 0x9E3779B97F4A7C15ull));
        for (uint32_t i = (uint32_t)m.size() - 1; i > 0; i--) {
            uint32_t j = (uint32_t)(r.Next() % (i + 1));
            uint32_t t = m[i];
            m[i] = m[j];
            m[j] = t;
        }
        order.insert(order.end(), m.begin(), m.end());
    }
    return order;
}

// R/B slot map: slot s -> flat channel index (green never touched).
static size_t SlotChannel(const std::vector<uint32_t>& order, size_t s) {
    return (size_t)order[s / 2] * 3 + (s % 2 == 0 ? 0 : 2);
}

// SplitMix-finalize hash for direction bits (FORMAT.md §2.5): stateless,
// seekable across header/body/robust splits.
static int DirBit(uint64_t seed64, size_t s) {
    uint64_t z = (seed64 ^ (uint64_t)((uint64_t)s * 0x9E3779B97F4A7C15ull));
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z = z ^ (z >> 31);
    return (int)((z >> 32) & 1);
}

bool EmbedV4(std::vector<uint8_t>& rgb, const std::vector<uint32_t>& order,
             const uint8_t* src, size_t srcLen, bool robust, uint64_t seed64,
             size_t slotBase) {
    size_t need = srcLen * 8 * (robust ? 3 : 1);
    if (need > order.size() * 2) return false;
    size_t slots = 0;
    for (size_t bi = 0; bi < srcLen * 8; bi++) {
        int b = (src[bi / 8] >> (bi % 8)) & 1;
        size_t rep = robust ? 3 : 1;
        for (size_t k = 0; k < rep; k++) {
            uint8_t& ch = rgb[SlotChannel(order, slots)];
            if ((ch & 1) != b) {
                if (ch == 0)
                    ch = 1;
                else if (ch == 255)
                    ch = 254;
                else
                    ch = (uint8_t)(ch + (DirBit(seed64, slotBase + slots) ? 1 : -1));
            }
            slots++;
        }
    }
    return true;
}

bool ReadV4(const std::vector<uint8_t>& rgb, const std::vector<uint32_t>& order,
            size_t nBytes, bool robust, std::vector<uint8_t>& out) {
    size_t need = nBytes * 8 * (robust ? 3 : 1);
    if (need > order.size() * 2) return false;
    out.assign(nBytes, 0);
    for (size_t bi = 0; bi < nBytes * 8; bi++) {
        int b;
        if (robust) {
            int votes = 0;
            for (int k = 0; k < 3; k++)
                votes += rgb[SlotChannel(order, 3 * bi + (size_t)k)] & 1;
            b = votes >= 2 ? 1 : 0;  // ties -> 0
        } else {
            b = rgb[SlotChannel(order, bi)] & 1;
        }
        if (b) out[bi / 8] |= (uint8_t)(1 << (bi % 8));
    }
    return true;
}

}  // namespace codec
}  // namespace stego
