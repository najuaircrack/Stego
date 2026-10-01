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

// --- v4 adaptive placement (FORMAT.md §2.4): S-UNIWARD-style wavelet
// costs over GREEN, R/B slots. Green is never written, so decode-side
// costs are bit-exact. All math is integer with portable floor division
// (never >> on negatives) to match the Python port bit-for-bit.

static int32_t MirrorIdx(int i, int n) {
    while (i < 0 || i >= n) {
        if (i < 0)
            i = -i;
        else
            i = 2 * (n - 1) - i;
    }
    return i;
}

static int32_t FDiv2(int32_t v) { return v >= 0 ? v / 2 : -((-v + 1) / 2); }
static int32_t FDiv4(int32_t v) { return v >= 0 ? v / 4 : -((-v + 3) / 4); }

// In-place integer 5/3 lifting on one row/column (symmetric extension).
// Predict odds from ORIGINAL evens, then update evens from predicted odds.
static void Dwt53Row(int32_t* x, int n) {
    for (int i = 1; i < n; i += 2) {
        int32_t l = x[MirrorIdx(i - 1, n)], r = x[MirrorIdx(i + 1, n)];
        x[i] = x[i] - FDiv2(l + r);
    }
    for (int i = 0; i < n; i += 2) {
        int32_t l = x[MirrorIdx(i - 1, n)], r = x[MirrorIdx(i + 1, n)];
        x[i] = x[i] + FDiv4(l + r + 2);
    }
}

void CostMapGreen(const std::vector<uint8_t>& rgb, uint32_t w, uint32_t h,
                  std::vector<uint32_t>& cost) {
    std::vector<int32_t> t((size_t)w * h);
    for (size_t i = 0; i < t.size(); i++) t[i] = (int32_t)rgb[i * 3 + 1];
    std::vector<int32_t> line(w > h ? w : h);
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) line[x] = t[(size_t)y * w + x];
        Dwt53Row(line.data(), (int)w);
        for (uint32_t x = 0; x < w; x++) t[(size_t)y * w + x] = line[x];
    }
    for (uint32_t x = 0; x < w; x++) {
        for (uint32_t y = 0; y < h; y++) line[y] = t[(size_t)y * w + x];
        Dwt53Row(line.data(), (int)h);
        for (uint32_t y = 0; y < h; y++) t[(size_t)y * w + x] = line[y];
    }
    // Magnitude map (LL zeroed: even row + even col), then 3x3 sums.
    cost.assign((size_t)w * h, 0);
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            uint32_t s = 0;
            for (int dy = -1; dy <= 1; dy++) {
                uint32_t yy = (uint32_t)MirrorIdx((int)y + dy, (int)h);
                for (int dx = -1; dx <= 1; dx++) {
                    uint32_t xx = (uint32_t)MirrorIdx((int)x + dx, (int)w);
                    int32_t c = t[(size_t)yy * w + xx];
                    if (xx % 2 == 1 || yy % 2 == 1)
                        s += (uint32_t)(c < 0 ? -c : c);
                }
            }
            cost[(size_t)y * w + x] = s;
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

void OrderCostsV4(const std::vector<uint8_t>& rgb, uint32_t w, uint32_t h,
                  uint32_t seed, uint32_t q, bool adaptive,
                  std::vector<uint32_t>& order, std::vector<uint8_t>& costs);
static size_t SlotChannel(const std::vector<uint32_t>& order, size_t s);
static int DirBit(uint64_t seed64, size_t s);

std::vector<uint32_t> CandidateOrderV4(const std::vector<uint8_t>& rgb,
                                       uint32_t w, uint32_t h, uint32_t seed,
                                       uint32_t q, bool adaptive) {
    uint32_t nPx = w * h;
    if (!adaptive)
        return PlacementRange(STEGO_V4_HEADER_PX, nPx - STEGO_V4_HEADER_PX,
                              seed);
    std::vector<uint32_t> order;
    std::vector<uint8_t> costs;
    OrderCostsV4(rgb, w, h, seed, q, adaptive, order, costs);
    return order;
}

// Order + per-position flip costs (Q - bucket; uniform 1 when flat).
// Single source for greedy and STC paths.
void OrderCostsV4(const std::vector<uint8_t>& rgb, uint32_t w, uint32_t h,
                  uint32_t seed, uint32_t q, bool adaptive,
                  std::vector<uint32_t>& order, std::vector<uint8_t>& costs) {
    uint32_t nPx = w * h;
    if (!adaptive) {
        order = PlacementRange(STEGO_V4_HEADER_PX, nPx - STEGO_V4_HEADER_PX,
                               seed);
        costs.assign(order.size(), 1);
        return;
    }
    std::vector<uint32_t> cmap;
    CostMapGreen(rgb, w, h, cmap);
    std::vector<uint32_t> members[16];
    for (uint32_t i = STEGO_V4_HEADER_PX; i < nPx; i++) {
        uint32_t b = CostBucket(cmap[i], q);
        if (b < 16) members[b].push_back(i);
    }
    order.clear();
    costs.clear();
    order.reserve(nPx);
    costs.reserve(nPx);
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
        uint8_t c = (uint8_t)(q - (uint32_t)b);
        order.insert(order.end(), m.begin(), m.end());
        costs.insert(costs.end(), m.size(), c ? c : 1);
    }
}

// --- Syndrome-trellis coding (FORMAT.md §2.4b): Viterbi over 2^7 states,
// integer metrics. Submatrix S[0]=1, S[1..7] from Xor128 keystream.

void StcSubmatrix(uint32_t seed, uint8_t sub[8]) {
    Xor128 r((uint64_t)seed ^ 0x535443ull);
    sub[0] = 1;
    for (int k = 1; k < 8; k++) sub[k] = (uint8_t)(r.Next() & 1);
}

bool StcEncode(const uint8_t* cover, const uint8_t* costs, size_t n,
               const uint8_t* msg, size_t msgLen, const uint8_t sub[8],
               uint8_t* flips) {
    const size_t M = msgLen * 8;
    if (n < M + 7) return false;
    // Cf[s][f]: flip-dependent syndrome part.
    uint8_t cf[128][2];
    for (int s = 0; s < 128; s++) {
        for (int f = 0; f < 2; f++) {
            uint8_t v = 0;
            for (int k = 0; k < 7; k++)
                if (sub[k] && (s >> k) & 1) v ^= 1;
            if (sub[7] && f) v ^= 1;
            cf[s][f] = v;
        }
    }
    // Cover syndrome per message position.
    std::vector<uint8_t> cx(M);
    for (size_t j = 0; j < M; j++) {
        uint8_t v = 0;
        for (int k = 0; k < 8; k++)
            if (sub[k] && cover[j + k]) v ^= 1;
        cx[j] = v;
    }
    uint8_t msgBit = 0;
    const uint64_t INF = (uint64_t)1 << 62;
    uint64_t cur[128], nxt[128];
    for (int s = 0; s < 128; s++) cur[s] = INF;
    cur[0] = 0;
    std::vector<uint8_t> prev(n * 128, 0);
    for (size_t i = 0; i < n; i++) {
        for (int s = 0; s < 128; s++) nxt[s] = INF;
        for (int s = 0; s < 128; s++) {
            if (cur[s] >= INF) continue;
            for (int f = 0; f < 2; f++) {
                if (i >= 7) {
                    size_t j = i - 7;
                    if (j >= M) continue;
                    msgBit = (uint8_t)((msg[j / 8] >> (j % 8)) & 1);
                    if ((uint8_t)(cx[j] ^ cf[s][f]) != msgBit) continue;
                }
                int ns = ((s >> 1) | (f << 6)) & 127;
                uint64_t nm = cur[s] + (f ? costs[i] : 0);
                if (nm < nxt[ns]) {
                    nxt[ns] = nm;
                    prev[i * 128 + ns] = (uint8_t)s;
                }
            }
        }
        memcpy(cur, nxt, sizeof(cur));
    }
    int best = 0;
    for (int s = 1; s < 128; s++)
        if (cur[s] < cur[best]) best = s;
    if (cur[best] >= INF) return false;
    int s = best;
    for (size_t i = n; i-- > 0;) {
        flips[i] = (uint8_t)((s >> 6) & 1);
        s = prev[i * 128 + s];
    }
    return true;
}

void StcExtract(const uint8_t* y, size_t mBits, const uint8_t sub[8],
                uint8_t* msg, size_t msgLen) {
    memset(msg, 0, msgLen);
    for (size_t j = 0; j < mBits; j++) {
        uint8_t v = 0;
        for (int k = 0; k < 8; k++)
            if (sub[k] && y[j + k]) v ^= 1;
        if (v) msg[j / 8] |= (uint8_t)(1 << (j % 8));
    }
}

void ApplyFlipsV4(std::vector<uint8_t>& rgb, const std::vector<uint32_t>& order,
                   const uint8_t* flips, size_t n, uint64_t seed64,
                   size_t slotBase) {
    for (size_t s = 0; s < n; s++) {
        if (!flips[s]) continue;
        uint8_t& ch = rgb[SlotChannel(order, s)];
        if (ch == 0)
            ch = 1;
        else if (ch == 255)
            ch = 254;
        else
            ch = (uint8_t)(ch + (DirBit(seed64, slotBase + s) ? 1 : -1));
    }
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
             const uint8_t* src, size_t srcLen, uint64_t seed64,
             size_t slotBase) {
    size_t need = srcLen * 8;
    if (need > order.size() * 2) return false;
    size_t slots = 0;
    for (size_t bi = 0; bi < srcLen * 8; bi++) {
        int b = (src[bi / 8] >> (bi % 8)) & 1;
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
    return true;
}

bool ReadV4(const std::vector<uint8_t>& rgb, const std::vector<uint32_t>& order,
            size_t nBytes, std::vector<uint8_t>& out) {
    size_t need = nBytes * 8;
    if (need > order.size() * 2) return false;
    out.assign(nBytes, 0);
    for (size_t bi = 0; bi < nBytes * 8; bi++) {
        if (rgb[SlotChannel(order, bi)] & 1)
            out[bi / 8] |= (uint8_t)(1 << (bi % 8));
    }
    return true;
}

}  // namespace codec
}  // namespace stego
