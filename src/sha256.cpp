// sha256.cpp - compact SHA-256 (public-domain algorithm, FIPS 180-4).
// Verified against NIST vectors in tests/test_codec.cpp + pytest goldens.
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

namespace stego {
namespace sha {

static inline uint32_t Ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

struct Ctx {
    uint32_t h[8];
    uint64_t total;
    uint8_t buf[64];
    size_t buflen;
};

static void Init(Ctx& c) {
    c.h[0] = 0x6a09e667; c.h[1] = 0xbb67ae85; c.h[2] = 0x3c6ef372; c.h[3] = 0xa54ff53a;
    c.h[4] = 0x510e527f; c.h[5] = 0x9b05688c; c.h[6] = 0x1f83d9ab; c.h[7] = 0x5be0cd19;
    c.total = 0;
    c.buflen = 0;
}

static void Block(Ctx& c, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = Ror(w[i - 15], 7) ^ Ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Ror(w[i - 2], 17) ^ Ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c.h[0], b = c.h[1], c2 = c.h[2], d = c.h[3];
    uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22);
        uint32_t maj = (a & b) ^ (a & c2) ^ (b & c2);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c2; c2 = b; b = a; a = t1 + t2;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += c2; c.h[3] += d;
    c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}

static void Update(Ctx& c, const uint8_t* data, size_t len) {
    c.total += len;
    while (len) {
        size_t take = 64 - c.buflen;
        if (take > len) take = len;
        memcpy(c.buf + c.buflen, data, take);
        c.buflen += take;
        data += take;
        len -= take;
        if (c.buflen == 64) {
            Block(c, c.buf);
            c.buflen = 0;
        }
    }
}

static void Final(Ctx& c, uint8_t out[32]) {
    uint64_t bitlen = c.total * 8;
    uint8_t pad = 0x80;
    Update(c, &pad, 1);
    uint8_t zero = 0;
    while (c.buflen != 56) Update(c, &zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bitlen >> (56 - i * 8));
    // Feed length without disturbing total accounting manually:
    size_t save = c.total;
    Update(c, lenb, 8);
    c.total = save;
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c.h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c.h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c.h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c.h[i];
    }
}

std::vector<uint8_t> Hash(const uint8_t* data, size_t len) {
    Ctx c;
    Init(c);
    Update(c, data, len);
    std::vector<uint8_t> out(32);
    Final(c, out.data());
    return out;
}

// HMAC-SHA256(key, msg).
std::vector<uint8_t> Hmac(const uint8_t* key, size_t klen,
                           const uint8_t* msg, size_t mlen) {
    uint8_t kb[64] = {0};
    if (klen > 64) {
        std::vector<uint8_t> h = Hash(key, klen);
        memcpy(kb, h.data(), 32);
    } else {
        memcpy(kb, key, klen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = kb[i] ^ 0x36;
        opad[i] = kb[i] ^ 0x5C;
    }
    Ctx c;
    Init(c);
    Update(c, ipad, 64);
    Update(c, msg, mlen);
    uint8_t inner[32];
    Final(c, inner);
    Init(c);
    Update(c, opad, 64);
    Update(c, inner, 32);
    std::vector<uint8_t> out(32);
    Final(c, out.data());
    return out;
}

uint32_t Crc32(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static bool built = false;
    if (!built) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        built = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// CTR keystream over a raw 32-byte key (envelope path).
void KeystreamRaw(const uint8_t* key32, uint8_t* out, size_t len) {
    uint32_t ctr = 0;
    size_t pos = 0;
    while (pos < len) {
        Ctx c;
        Init(c);
        Update(c, key32, 32);
        uint8_t cb[4] = {(uint8_t)(ctr >> 24), (uint8_t)(ctr >> 16),
                         (uint8_t)(ctr >> 8), (uint8_t)ctr};
        Update(c, cb, 4);
        uint8_t d[32];
        Final(c, d);
        size_t take = len - pos < 32 ? len - pos : 32;
        memcpy(out + pos, d, take);
        pos += take;
        ctr++;
    }
}

// PBKDF2-HMAC-SHA256 -> dkLen bytes (callers use 64: enc[0..32) + auth[32..64)).
std::vector<uint8_t> Pbkdf2(const uint8_t* pw, size_t pwLen,
                             const uint8_t* salt, size_t saltLen,
                             uint32_t iter, size_t dkLen) {
    std::vector<uint8_t> dk;
    dk.reserve(dkLen);
    uint32_t blocks = (uint32_t)((dkLen + 31) / 32);
    for (uint32_t b = 1; b <= blocks; b++) {
        uint8_t be[4] = {(uint8_t)(b >> 24), (uint8_t)(b >> 16),
                         (uint8_t)(b >> 8), (uint8_t)b};
        std::vector<uint8_t> msg;
        msg.insert(msg.end(), salt, salt + saltLen);
        msg.insert(msg.end(), be, be + 4);
        std::vector<uint8_t> u = Hmac(pw, pwLen, msg.data(), msg.size());
        std::vector<uint8_t> t = u;
        for (uint32_t i = 1; i < iter; i++) {
            u = Hmac(pw, pwLen, u.data(), u.size());
            for (size_t j = 0; j < 32; j++) t[j] ^= u[j];
        }
        dk.insert(dk.end(), t.begin(), t.end());
    }
    dk.resize(dkLen);
    return dk;
}

}  // namespace sha
}  // namespace stego
