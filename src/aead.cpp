// aead.cpp - ChaCha20-Poly1305 (RFC 8439) for the v4 envelope AEAD.
// Self-contained (no external deps), matches src/sha256.cpp style: plain
// functions under stego::aead. Poly1305 uses 5x26-bit limbs (portable to
// MSVC, which has no __int128). Test vectors: python/stegolib.py agrees
// bit-for-bit (see tests/test_roundtrip.py cross-impl battery).
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

namespace stego {
namespace aead {

static inline uint32_t Rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
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
    Store32LE(p, (uint32_t)v);
    Store32LE(p + 4, (uint32_t)(v >> 32));
}

#define QR(x, a, b, c, d)           \
    x[a] += x[b];                   \
    x[d] ^= x[a];                   \
    x[d] = Rotl32(x[d], 16);        \
    x[c] += x[d];                   \
    x[b] ^= x[c];                   \
    x[b] = Rotl32(x[b], 12);        \
    x[a] += x[b];                   \
    x[d] ^= x[a];                   \
    x[d] = Rotl32(x[d], 8);         \
    x[c] += x[d];                   \
    x[b] ^= x[c];                   \
    x[b] = Rotl32(x[b], 7);

void ChaChaBlock(const uint8_t key[32], const uint8_t nonce[12],
                 uint32_t counter, uint8_t out[64]) {
    static const uint8_t sigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ',
                                      '3', '2', '-', 'b', 'y', 't', 'e',
                                      ' ', 'k'};
    uint32_t st[16];
    st[0] = Load32LE(sigma + 0);
    st[1] = Load32LE(sigma + 4);
    st[2] = Load32LE(sigma + 8);
    st[3] = Load32LE(sigma + 12);
    for (int i = 0; i < 8; i++) st[4 + i] = Load32LE(key + i * 4);
    st[12] = counter;
    st[13] = Load32LE(nonce + 0);
    st[14] = Load32LE(nonce + 4);
    st[15] = Load32LE(nonce + 8);
    uint32_t w[16];
    memcpy(w, st, sizeof(w));
    for (int i = 0; i < 10; i++) {
        QR(w, 0, 4, 8, 12);
        QR(w, 1, 5, 9, 13);
        QR(w, 2, 6, 10, 14);
        QR(w, 3, 7, 11, 15);
        QR(w, 0, 5, 10, 15);
        QR(w, 1, 6, 11, 12);
        QR(w, 2, 7, 8, 13);
        QR(w, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) Store32LE(out + i * 4, w[i] + st[i]);
}

// --- Poly1305 (donna 5x26-bit form) ---

static void PolyMul(const uint32_t h[5], const uint32_t r[5],
                    uint32_t out[5]) {
    uint64_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    uint64_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint64_t d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    uint64_t d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    uint32_t c;
    c = (uint32_t)(d0 >> 26);
    out[0] = (uint32_t)d0 & 0x3ffffff;
    d1 += c;
    c = (uint32_t)(d1 >> 26);
    out[1] = (uint32_t)d1 & 0x3ffffff;
    d2 += c;
    c = (uint32_t)(d2 >> 26);
    out[2] = (uint32_t)d2 & 0x3ffffff;
    d3 += c;
    c = (uint32_t)(d3 >> 26);
    out[3] = (uint32_t)d3 & 0x3ffffff;
    d4 += c;
    c = (uint32_t)(d4 >> 26);
    out[4] = (uint32_t)d4 & 0x3ffffff;
    out[0] += c * 5;
    c = out[0] >> 26;
    out[0] &= 0x3ffffff;
    out[1] += c;
}

void Poly1305(const uint8_t key[32], const uint8_t* msg, size_t len,
              uint8_t tag[16]) {
    uint32_t r[5], h[5] = {0, 0, 0, 0, 0};
    r[0] = Load32LE(key + 0) & 0x3ffffff;
    r[1] = (Load32LE(key + 3) >> 2) & 0x3ffff03;
    r[2] = (Load32LE(key + 6) >> 4) & 0x3ffc0ff;
    r[3] = (Load32LE(key + 9) >> 6) & 0x3f03fff;
    r[4] = (Load32LE(key + 12) >> 8) & 0x00fffff;
    // The extraction masks above ARE the RFC 8439 §2.5 clamp (they clear
    // exactly r-byte top-nibbles 3/7/11/15 and low pairs 4/8/12).
    while (len > 0) {
        size_t take = len < 16 ? len : 16;
        uint8_t blk[16] = {0};
        memcpy(blk, msg, take);
        int hibit = (take == 16) ? 1 : 0;
        // The manual 0x01 byte lands inside blk for partial chunks;
        // hibit carries it for full chunks (donna convention).
        if (!hibit) blk[take] = 0x01;
        uint32_t t0 = Load32LE(blk + 0);
        uint32_t t1 = Load32LE(blk + 3);
        uint32_t t2 = Load32LE(blk + 6);
        uint32_t t3 = Load32LE(blk + 9);
        uint32_t t4 = Load32LE(blk + 12);
        h[0] += t0 & 0x3ffffff;
        h[1] += (((uint64_t)t1 >> 2)) & 0x3ffffff;
        h[2] += (((uint64_t)t2 >> 4)) & 0x3ffffff;
        h[3] += (((uint64_t)t3 >> 6)) & 0x3ffffff;
        h[4] += (((uint64_t)t4 >> 8) | ((uint64_t)hibit << 24));
        PolyMul(h, r, h);
        msg += take;
        len -= take;
    }
    // Freeze h (fully carry + conditional subtract p).
    uint32_t c, g[5];
    c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;
    g[0] = h[0] + 5;
    c = g[0] >> 26;
    g[0] &= 0x3ffffff;
    g[1] = h[1] + c;
    c = g[1] >> 26;
    g[1] &= 0x3ffffff;
    g[2] = h[2] + c;
    c = g[2] >> 26;
    g[2] &= 0x3ffffff;
    g[3] = h[3] + c;
    c = g[3] >> 26;
    g[3] &= 0x3ffffff;
    g[4] = h[4] + c - (1u << 26);
    uint32_t mask = (g[4] >> 31) - 1;
    g[0] &= mask;
    g[1] &= mask;
    g[2] &= mask;
    g[3] &= mask;
    g[4] &= mask;
    mask = ~mask;
    h[0] = (h[0] & mask) | g[0];
    h[1] = (h[1] & mask) | g[1];
    h[2] = (h[2] & mask) | g[2];
    h[3] = (h[3] & mask) | g[3];
    h[4] = (h[4] & mask) | g[4];
    // h = h % 2^128, serialized LE.
    uint32_t h0 = ((h[0]) | (h[1] << 26)) & 0xffffffff;
    uint32_t h1 = ((h[1] >> 6) | (h[2] << 20)) & 0xffffffff;
    uint32_t h2 = ((h[2] >> 12) | (h[3] << 14)) & 0xffffffff;
    uint32_t h3 = ((h[3] >> 18) | (h[4] << 8)) & 0xffffffff;
    // mac = (h + s) % 2^128.
    uint32_t s0 = Load32LE(key + 16);
    uint32_t s1 = Load32LE(key + 20);
    uint32_t s2 = Load32LE(key + 24);
    uint32_t s3 = Load32LE(key + 28);
    uint64_t f = (uint64_t)h0 + s0;
    h0 = (uint32_t)f;
    f = (uint64_t)h1 + s1 + (f >> 32);
    h1 = (uint32_t)f;
    f = (uint64_t)h2 + s2 + (f >> 32);
    h2 = (uint32_t)f;
    f = (uint64_t)h3 + s3 + (f >> 32);
    h3 = (uint32_t)f;
    Store32LE(tag + 0, h0);
    Store32LE(tag + 4, h1);
    Store32LE(tag + 8, h2);
    Store32LE(tag + 12, h3);
}

// One-shot encrypt: ct = pt (ptLen bytes), tag = Poly1305 over
// pad16(aad) || pad16(ct) || le64(aadLen) || le64(ctLen).
void AeadEncrypt(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen, const uint8_t* pt,
                 size_t ptLen, uint8_t* ct, uint8_t tag[16]) {
    uint8_t otk[32];
    uint8_t blk[64];
    ChaChaBlock(key, nonce, 0, blk);
    memcpy(otk, blk, 32);
    memset(blk, 0, sizeof(blk));
    uint32_t ctr = 1;
    size_t off = 0;
    while (off < ptLen) {
        ChaChaBlock(key, nonce, ctr++, blk);
        size_t take = ptLen - off < 64 ? ptLen - off : 64;
        for (size_t i = 0; i < take; i++) ct[off + i] = (uint8_t)(pt[off + i] ^ blk[i]);
        off += take;
    }
    memset(blk, 0, sizeof(blk));
    size_t macLen = ((aadLen + 15) & ~(size_t)15) + ((ptLen + 15) & ~(size_t)15) + 16;
    std::vector<uint8_t> mac;
    mac.reserve(macLen);
    mac.insert(mac.end(), aad, aad + aadLen);
    mac.insert(mac.end(), ((aadLen + 15) & ~(size_t)15) - aadLen, 0);
    mac.insert(mac.end(), ct, ct + ptLen);
    mac.insert(mac.end(), ((ptLen + 15) & ~(size_t)15) - ptLen, 0);
    uint8_t lens[16];
    Store32LE(lens + 0, (uint32_t)(aadLen & 0xFFFFFFFF));
    Store32LE(lens + 4, (uint32_t)((aadLen >> 32) & 0xFFFFFFFF));
    Store32LE(lens + 8, (uint32_t)(ptLen & 0xFFFFFFFF));
    Store32LE(lens + 12, (uint32_t)((ptLen >> 32) & 0xFFFFFFFF));
    mac.insert(mac.end(), lens, lens + 16);
    Poly1305(otk, mac.data(), mac.size(), tag);
    memset(otk, 0, sizeof(otk));
}

static bool TagEqual(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t d = 0;
    for (int i = 0; i < 16; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

// Returns false on auth failure (pt left untouched); true + pt filled.
bool AeadDecrypt(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen, const uint8_t* ct,
                 size_t ctLen, const uint8_t tag[16], uint8_t* pt) {
    uint8_t otk[32];
    uint8_t blk[64];
    ChaChaBlock(key, nonce, 0, blk);
    memcpy(otk, blk, 32);
    memset(blk, 0, sizeof(blk));
    size_t macLen = ((aadLen + 15) & ~(size_t)15) + ((ctLen + 15) & ~(size_t)15) + 16;
    std::vector<uint8_t> mac;
    mac.reserve(macLen);
    mac.insert(mac.end(), aad, aad + aadLen);
    mac.insert(mac.end(), ((aadLen + 15) & ~(size_t)15) - aadLen, 0);
    mac.insert(mac.end(), ct, ct + ctLen);
    mac.insert(mac.end(), ((ctLen + 15) & ~(size_t)15) - ctLen, 0);
    uint8_t lens[16];
    Store32LE(lens + 0, (uint32_t)(aadLen & 0xFFFFFFFF));
    Store32LE(lens + 4, (uint32_t)((aadLen >> 32) & 0xFFFFFFFF));
    Store32LE(lens + 8, (uint32_t)(ctLen & 0xFFFFFFFF));
    Store32LE(lens + 12, (uint32_t)((ctLen >> 32) & 0xFFFFFFFF));
    mac.insert(mac.end(), lens, lens + 16);
    uint8_t good[16];
    Poly1305(otk, mac.data(), mac.size(), good);
    memset(otk, 0, sizeof(otk));
    if (!TagEqual(good, tag)) {
        memset(good, 0, sizeof(good));
        return false;
    }
    memset(good, 0, sizeof(good));
    uint32_t ctr = 1;
    size_t off = 0;
    while (off < ctLen) {
        ChaChaBlock(key, nonce, ctr++, blk);
        size_t take = ctLen - off < 64 ? ctLen - off : 64;
        for (size_t i = 0; i < take; i++) pt[off + i] = (uint8_t)(ct[off + i] ^ blk[i]);
        off += take;
    }
    memset(blk, 0, sizeof(blk));
    return true;
}

}  // namespace aead
}  // namespace stego
