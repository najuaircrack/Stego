// argon2.cpp - Argon2id (RFC 9106, version 0x13) for v4 KDF agility.
// Transcribed from the RFC text (GB with multiplies per Fig.19, H0/H'
// framing per Fig.1/8, indexing per 3.4); validated against the RFC
// Argon2id test vector (see tests/test_codec.cpp), not from memory.
// Single-lane production use; multi-lane implemented for validation.
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

namespace stego {
namespace argon2 {

// --- BLAKE2b (RFC 7693), variable digest length, no key ---

static const uint64_t B2IV[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
    0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
    0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};

static const uint8_t B2SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static inline uint64_t Rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t Load64LE(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (i * 8);
    return v;
}

static inline uint32_t Load32LE(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void Store32LE(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void Store64LE(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

#define B2G(v, a, b, c, d, x, y)          \
    v[a] += v[b] + (x);                   \
    v[d] = Rotr64(v[d] ^ v[a], 32);       \
    v[c] += v[d];                         \
    v[b] ^= v[c];                         \
    v[b] = Rotr64(v[b], 24);              \
    v[a] += v[b] + (y);                   \
    v[d] ^= v[a];                         \
    v[d] = Rotr64(v[d], 16);              \
    v[c] += v[d];                         \
    v[b] ^= v[c];                         \
    v[b] = Rotr64(v[b], 63);

static void Blake2bCompress(uint64_t h[8], const uint8_t block[128],
                            uint64_t ctrLo, uint64_t ctrHi, bool last) {
    uint64_t m[16];
    for (int i = 0; i < 16; i++) m[i] = Load64LE(block + i * 8);
    uint64_t v[16];
    for (int i = 0; i < 8; i++) v[i] = h[i];
    for (int i = 0; i < 8; i++) v[i + 8] = B2IV[i];
    v[12] ^= ctrLo;
    v[13] ^= ctrHi;
    if (last) v[14] = ~v[14];
    for (int r = 0; r < 12; r++) {
        B2G(v, 0, 4, 8, 12, m[B2SIGMA[r][0]], m[B2SIGMA[r][1]]);        B2G(v, 1, 5, 9, 13, m[B2SIGMA[r][2]], m[B2SIGMA[r][3]]);
        B2G(v, 2, 6, 10, 14, m[B2SIGMA[r][4]], m[B2SIGMA[r][5]]);
        B2G(v, 3, 7, 11, 15, m[B2SIGMA[r][6]], m[B2SIGMA[r][7]]);
        B2G(v, 0, 5, 10, 15, m[B2SIGMA[r][8]], m[B2SIGMA[r][9]]);
        B2G(v, 1, 6, 11, 12, m[B2SIGMA[r][10]], m[B2SIGMA[r][11]]);
        B2G(v, 2, 7, 8, 13, m[B2SIGMA[r][12]], m[B2SIGMA[r][13]]);
        B2G(v, 3, 4, 9, 14, m[B2SIGMA[r][14]], m[B2SIGMA[r][15]]);
    }
    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

// One-shot Blake2b, digest length outLen (1..64), no key.
static void Blake2b(const uint8_t* in, size_t inLen, uint8_t* out,
                    size_t outLen) {
    uint64_t h[8];
    for (int i = 0; i < 8; i++) h[i] = B2IV[i];
    h[0] ^= 0x01010000 ^ (uint64_t)outLen;
    uint64_t ctr = 0;
    size_t off = 0;
    if (inLen == 0) {
        uint8_t blk[128] = {0};
        Blake2bCompress(h, blk, 0, 0, true);
    } else {
        while (off < inLen) {
            size_t take = inLen - off < 128 ? inLen - off : 128;
            uint8_t blk[128] = {0};
            memcpy(blk, in + off, take);
            off += take;
            ctr += take;
            Blake2bCompress(h, blk, ctr, 0, off >= inLen);
        }
    }
    uint8_t full[64];
    for (int i = 0; i < 8; i++) Store64LE(full + i * 8, h[i]);
    memcpy(out, full, outLen);
    memset(full, 0, sizeof(full));
}

// Variable-length H' (RFC Fig.8): BOTH branches prepend LE32(outLen)
// (the T<=64 branch is H^T(LE32(T)||A), not bare H^T(A)).
static void HPrime(const uint8_t* a, size_t aLen, uint8_t* out,
                   size_t outLen) {
    if (outLen <= 64) {
        // Hash ALL of A (A can exceed one block, e.g. the 1024-byte C).
        std::vector<uint8_t> buf(4 + aLen);
        buf[0] = (uint8_t)outLen;
        buf[1] = (uint8_t)(outLen >> 8);
        buf[2] = (uint8_t)(outLen >> 16);
        buf[3] = (uint8_t)(outLen >> 24);
        memcpy(buf.data() + 4, a, aLen);
        Blake2b(buf.data(), buf.size(), out, outLen);
        return;
    }
    size_t r = (outLen + 31) / 32 - 2;
    std::vector<uint8_t> buf(4 + aLen);
    buf[0] = (uint8_t)outLen;
    buf[1] = (uint8_t)(outLen >> 8);
    buf[2] = (uint8_t)(outLen >> 16);
    buf[3] = (uint8_t)(outLen >> 24);
    memcpy(buf.data() + 4, a, aLen);
    std::vector<uint8_t> v(64);
    Blake2b(buf.data(), buf.size(), v.data(), 64);
    memcpy(out, v.data(), 32);
    size_t done = 32;
    for (size_t i = 1; i < r; i++) {
        Blake2b(v.data(), 64, v.data(), 64);
        memcpy(out + done, v.data(), 32);
        done += 32;
    }
    size_t lastLen = outLen - 32 * r;
    Blake2b(v.data(), 64, out + done, lastLen);
}

// --- Argon2id compression (RFC Fig.19 GB with multiplies) ---

static inline uint64_t Trunc32(uint64_t x) { return x & 0xFFFFFFFFull; }

#define AGB(a, b, c, d)                                   \
    (a) = (a) + (b) + 2 * Trunc32(a) * Trunc32(b);        \
    (d) = Rotr64((d) ^ (a), 32);                          \
    (c) = (c) + (d) + 2 * Trunc32(c) * Trunc32(d);        \
    (b) = Rotr64((b) ^ (c), 24);                          \
    (a) = (a) + (b) + 2 * Trunc32(a) * Trunc32(b);        \
    (d) = Rotr64((d) ^ (a), 16);                          \
    (c) = (c) + (d) + 2 * Trunc32(c) * Trunc32(d);        \
    (b) = Rotr64((b) ^ (c), 63);

// P over 16 words (Fig.18 feeding order, verbatim).
static void PermuteP(uint64_t v[16]) {
    AGB(v[0], v[4], v[8], v[12]);
    AGB(v[1], v[5], v[9], v[13]);
    AGB(v[2], v[6], v[10], v[14]);
    AGB(v[3], v[7], v[11], v[15]);
    AGB(v[0], v[5], v[10], v[15]);
    AGB(v[1], v[6], v[11], v[12]);
    AGB(v[2], v[7], v[8], v[13]);
    AGB(v[3], v[4], v[9], v[14]);
}

// G(X, Y): R = X^Y; rowwise P; columnwise P; out = Z^R. Blocks are
// 1024 bytes = 128 words; rows are 16-word strips, columns strided.
static void CompressG(const uint8_t x[1024], const uint8_t y[1024],
                      uint8_t out[1024]) {
    uint64_t r[128], q[128], z[128], t[16];
    for (int i = 0; i < 128; i++)
        r[i] = Load64LE(x + i * 8) ^ Load64LE(y + i * 8);
    for (int row = 0; row < 8; row++) {
        for (int i = 0; i < 16; i++) t[i] = r[row * 16 + i];
        PermuteP(t);
        for (int i = 0; i < 16; i++) q[row * 16 + i] = t[i];
    }
    for (int col = 0; col < 8; col++) {
        // column c = registers c, c+8, ..., c+56 (each = 2 words)
        for (int i = 0; i < 8; i++) {
            uint32_t k = (uint32_t)col + 8u * (uint32_t)i;
            t[2 * i] = q[2 * k];
            t[2 * i + 1] = q[2 * k + 1];
        }
        PermuteP(t);
        for (int i = 0; i < 8; i++) {
            uint32_t k = (uint32_t)col + 8u * (uint32_t)i;
            z[2 * k] = t[2 * i];
            z[2 * k + 1] = t[2 * i + 1];
        }
    }
    for (int i = 0; i < 128; i++) Store64LE(out + i * 8, z[i] ^ r[i]);
}

// Reference-block mapping (RFC 3.4.2): cyclic formulation verified
// against the reference area rules. l = forced current lane on
// (pass 0, slice 0), else J2 mod lanes. W is the `area` blocks ending
// just before the excluded previous block; zz picks within it.
static bool MapRef(uint32_t lane, uint32_t lanes, uint32_t r, uint32_t sl,
                   uint32_t segLen, uint32_t j, uint32_t J1, uint32_t J2,
                   uint32_t& l, uint32_t& z) {
    uint32_t q = segLen * 4;
    if (r == 0 && sl == 0)
        l = lane;
    else
        l = lanes == 0 ? lane : J2 % lanes;
    uint32_t c = sl * segLen + j;  // absolute column of current block
    int64_t area;
    uint32_t start;
    if (l == lane) {
        area = (r == 0) ? (int64_t)sl * segLen + (int64_t)j - 1
                        : (int64_t)3 * segLen + (int64_t)j - 1;
        int64_t s = (int64_t)c - 1 - area;
        s %= (int64_t)q;
        if (s < 0) s += q;
        start = (uint32_t)s;
    } else {
        int64_t E = (int64_t)sl * segLen - 1;  // most recent finished
        E %= (int64_t)q;
        if (E < 0) E += q;
        if (r == 0)
            area = (int64_t)sl * segLen + (j == 0 ? -1 : 0);
        else
            area = (int64_t)3 * segLen + (j == 0 ? -1 : 0);
        int64_t Ep = (j == 0) ? E - 1 : E;  // first block of a segment
        int64_t s = Ep - area + 1;          // excludes the very last index
        s %= (int64_t)q;
        if (s < 0) s += q;
        start = (uint32_t)s;
    }
    if (area <= 0) return false;  // unreachable by construction; fail closed
    uint64_t x = ((uint64_t)J1 * J1) >> 32;
    uint64_t y = ((uint64_t)(uint32_t)area * x) >> 32;
    uint32_t zz = (uint32_t)area - 1 - (uint32_t)y;
    z = (start + zz) % q;
    return true;
}

static void PutU32Le(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back((uint8_t)v);
    b.push_back((uint8_t)(v >> 8));
    b.push_back((uint8_t)(v >> 16));
    b.push_back((uint8_t)(v >> 24));
}

// Argon2id (y=2, v=0x13) tag derivation. Secret/AD empty in our use;
// supported (nullable) so the RFC vectors validate exactly.
bool Derive(const uint8_t* pw, size_t pwLen, const uint8_t* salt,
            size_t saltLen, const uint8_t* secret, size_t secretLen,
            const uint8_t* ad, size_t adLen, uint32_t passes,
            uint32_t mem_kib, uint32_t lanes, uint8_t* out, size_t outLen) {
    if (!pw || !salt || !out) return false;
    if (lanes < 1 || outLen < 16 || outLen > (1u << 20)) return false;
    if (mem_kib < 8 * lanes) return false;
    if ((secretLen && !secret) || (adLen && !ad)) return false;
    const uint32_t y = 2, v = 0x13;

    // H0 = H^64(LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) ||
    //          LE32(y) || LE32(lenP) || P || ...). Zero-length K/X/S are
    // absent but their length fields remain.
    std::vector<uint8_t> h0in;
    PutU32Le(h0in, lanes);
    PutU32Le(h0in, (uint32_t)outLen);
    PutU32Le(h0in, mem_kib);
    PutU32Le(h0in, passes);
    PutU32Le(h0in, v);
    PutU32Le(h0in, y);
    PutU32Le(h0in, (uint32_t)pwLen);
    h0in.insert(h0in.end(), pw, pw + pwLen);
    PutU32Le(h0in, (uint32_t)saltLen);
    h0in.insert(h0in.end(), salt, salt + saltLen);
    PutU32Le(h0in, (uint32_t)secretLen);
    if (secretLen) h0in.insert(h0in.end(), secret, secret + secretLen);
    PutU32Le(h0in, (uint32_t)adLen);
    if (adLen) h0in.insert(h0in.end(), ad, ad + adLen);
    uint8_t h0[64];
    Blake2b(h0in.data(), h0in.size(), h0, sizeof(h0));

    uint64_t mprime = (uint64_t)4 * lanes * (mem_kib / (4 * lanes));
    uint32_t q = (uint32_t)(mprime / lanes);
    uint32_t segLen = q / 4;
    std::vector<uint8_t> mem(mprime * 1024, 0);
    auto block = [&](uint32_t lane, uint32_t col) -> uint8_t* {
        return mem.data() + ((size_t)lane * q + col) * 1024;
    };
    // Initial blocks: B[i][0] = H'^1024(H0||0||i), B[i][1] = H'^1024(H0||1||i).
    uint8_t init[72];
    memcpy(init, h0, 64);
    uint8_t tmp[1024];
    for (uint32_t lane = 0; lane < lanes; lane++) {
        Store32LE(init + 64, 0);
        Store32LE(init + 68, lane);
        HPrime(init, sizeof(init), block(lane, 0), 1024);
        Store32LE(init + 64, 1);
        HPrime(init, sizeof(init), block(lane, 1), 1024);
    }

    uint8_t zero[1024] = {0};
    uint8_t input[1024], inner[1024], addr[1024];
    for (uint32_t r = 0; r < passes; r++) {
        for (uint32_t sl = 0; sl < 4; sl++) {
            for (uint32_t lane = 0; lane < lanes; lane++) {
                bool indep = (r == 0 && sl < 2);  // Argon2id rule
                // Positional address consumption (matches ref.c): block j
                // consumes stream value j; chunks generated on demand.
                std::vector<uint64_t> addrVals;
                uint64_t addrCtr = 0;
                if (indep) {
                    memset(input, 0, sizeof(input));
                    Store64LE(input + 0, r);
                    Store64LE(input + 8, lane);
                    Store64LE(input + 16, sl);
                    Store64LE(input + 24, mprime);
                    Store64LE(input + 32, passes);
                    Store64LE(input + 40, y);
                }
                uint32_t j0 = (r == 0 && sl == 0) ? 2 : 0;
                for (uint32_t j = j0; j < segLen; j++) {
                    uint32_t c = sl * segLen + j;
                    // Previous block: absolute (c-1) mod q, universally.
                    // (For pass>0 slice>0 j=0 this is the previous slice's
                    // last block, NOT the lane's last block.)
                    uint32_t pc = (c + q - 1) % q;
                    uint8_t* prev = block(lane, pc);
                    uint32_t J1, J2;
                    if (indep) {
                        while (addrVals.size() <= j) {
                            addrCtr++;
                            Store64LE(input + 48, addrCtr);
                            CompressG(zero, input, inner);
                            CompressG(zero, inner, addr);
                            for (int k = 0; k < 128; k++)
                                addrVals.push_back(Load64LE(addr + k * 8));
                        }
                        uint64_t val = addrVals[j];
                        J1 = (uint32_t)val;
                        J2 = (uint32_t)(val >> 32);
                    } else {
                        J1 = Load32LE(prev + 0);
                        J2 = Load32LE(prev + 4);
                    }
                    uint32_t l, z;
                    if (!MapRef(lane, lanes, r, sl, segLen, j, J1, J2, l, z))
                        return false;
                    CompressG(prev, block(l, z), tmp);
                    uint8_t* dst = block(lane, c);
                    if (r == 0) {
                        memcpy(dst, tmp, 1024);
                    } else {
                        for (int i = 0; i < 1024; i++) dst[i] ^= tmp[i];
                    }
                }
            }
        }
    }
    // Final: C = XOR of last column; tag = H'^outLen(C).
    uint8_t C[1024] = {0};
    for (uint32_t lane = 0; lane < lanes; lane++) {
        uint8_t* b = block(lane, q - 1);
        for (int i = 0; i < 1024; i++) C[i] ^= b[i];
    }
    HPrime(C, sizeof(C), out, outLen);
    memset(C, 0, sizeof(C));
    memset(tmp, 0, sizeof(tmp));
    return true;
}

}  // namespace argon2
}  // namespace stego
