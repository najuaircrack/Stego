// api.cpp - Encode / Decode (single salted-envelope format) + C ABI.
#include "stego/stego.h"
#include "stego/stego_c.h"
#include "stego/format.h"
#include <string.h>
#include <random>
#include <cstdlib>

namespace stego {
namespace sha {
std::vector<uint8_t> Hash(const uint8_t* data, size_t len);
void KeystreamRaw(const uint8_t* key32, uint8_t* out, size_t len);
std::vector<uint8_t> Hmac(const uint8_t* key, size_t klen,
                           const uint8_t* msg, size_t mlen);
std::vector<uint8_t> Pbkdf2(const uint8_t* pw, size_t pwLen,
                             const uint8_t* salt, size_t saltLen,
                             uint32_t iter, size_t dkLen);
uint32_t Crc32(const uint8_t* data, size_t len);
}  // namespace sha
namespace argon2 {
bool Derive(const uint8_t* pw, size_t pwLen, const uint8_t* salt,
            size_t saltLen, const uint8_t* secret, size_t secretLen,
            const uint8_t* ad, size_t adLen, uint32_t passes,
            uint32_t mem_kib, uint32_t lanes, uint8_t* out, size_t outLen);
}  // namespace argon2
namespace codec {
void PutU16(std::vector<uint8_t>& b, uint16_t v);
void PutU32(std::vector<uint8_t>& b, uint32_t v);
std::vector<uint32_t> Placement(uint32_t nPx, uint32_t seed);
std::vector<uint32_t> PlacementRange(uint32_t base, uint32_t count,
                                     uint32_t seed);
void PutBit(std::vector<uint8_t>& rgb, uint32_t w,
            const std::vector<uint32_t>& place, size_t k, int bit);
int GetBit(const std::vector<uint8_t>& rgb, uint32_t w,
           const std::vector<uint32_t>& place, size_t k);
// v4 adaptive placement (FORMAT.md §2.4): green costs, R/B slots.
void CostMapGreen(const std::vector<uint8_t>& rgb, uint32_t w, uint32_t h,
                  std::vector<uint32_t>& cost);
uint32_t CostBucket(uint32_t cost, uint32_t q);
std::vector<uint32_t> CandidateOrderV4(const std::vector<uint8_t>& rgb,
                                       uint32_t w, uint32_t h, uint32_t seed,
                                       uint32_t q, bool adaptive);
void OrderCostsV4(const std::vector<uint8_t>& rgb, uint32_t w, uint32_t h,
                  uint32_t seed, uint32_t q, bool adaptive,
                  std::vector<uint32_t>& order, std::vector<uint8_t>& costs);
void StcSubmatrix(uint32_t seed, uint8_t sub[8]);
bool StcEncode(const uint8_t* cover, const uint8_t* costs, size_t n,
               const uint8_t* msg, size_t msgLen, const uint8_t sub[8],
               uint8_t* flips);
void StcExtract(const uint8_t* y, size_t mBits, const uint8_t sub[8],
                uint8_t* msg, size_t msgLen);
void ApplyFlipsV4(std::vector<uint8_t>& rgb, const std::vector<uint32_t>& order,
                   const uint8_t* flips, size_t n, uint64_t seed64,
                   size_t slotBase);
bool EmbedV4(std::vector<uint8_t>& rgb, const std::vector<uint32_t>& order,
             const uint8_t* src, size_t srcLen, uint64_t seed64,
             size_t slotBase);
bool ReadV4(const std::vector<uint8_t>& rgb, const std::vector<uint32_t>& order,
            size_t nBytes, std::vector<uint8_t>& out);
}  // namespace codec
namespace rs {
bool EncodeBlock(const uint8_t data[223], uint8_t cw[255]);
bool DecodeBlock(const uint8_t cw[255], uint8_t data[223]);
}  // namespace rs
namespace aead {
void ChaChaBlock(const uint8_t key[32], const uint8_t nonce[12],
                 uint32_t counter, uint8_t out[64]);
void Poly1305(const uint8_t key[32], const uint8_t* msg, size_t len,
              uint8_t tag[16]);
void AeadEncrypt(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen, const uint8_t* pt,
                 size_t ptLen, uint8_t* ct, uint8_t tag[16]);
bool AeadDecrypt(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen, const uint8_t* ct,
                 size_t ctLen, const uint8_t tag[16], uint8_t* pt);
}  // namespace aead

const char* Version() { return "4.0.0"; }

size_t Capacity(uint32_t w, uint32_t h) {
    // 118 header pixels reserved; body must fit data_crc32 (+tag).
    size_t nPx = (size_t)w * h;
    if (nPx <= STEGO_HEADER_PX) return 0;
    size_t bodyBits = (nPx - STEGO_HEADER_PX) * 3;
    if (bodyBits < 4 * 8) return 0;
    return (bodyBits - 4 * 8) / 8;
}

static uint16_t FlagsOf(const Options& o) {
    uint16_t f = 0;
    if (o.compress) f |= STEGO_F_COMPRESS;
    if (o.scatter || o.seed != 0) f |= STEGO_F_SCATTER;
    if (!o.password.empty()) f |= STEGO_F_ENCRYPT;
    if (o.auth) f |= STEGO_F_AUTH;
    return f;
}

// Bounds-checked bitstream read under an explicit placement.
static bool ReadStream(const Image& img, const std::vector<uint32_t>& place,
                       size_t placeBits, size_t bitOff, uint8_t* dst, size_t len) {
    if (len * 8 > placeBits || bitOff + len * 8 > placeBits) return false;
    memset(dst, 0, len);
    for (size_t i = 0; i < len * 8; i++) {
        if (codec::GetBit(img.rgb, img.w, place, bitOff + i)) {
            dst[i / 8] |= (uint8_t)(1 << (i % 8));
        }
    }
    return true;
}

bool Encode(const Image& cover, const uint8_t* payload, size_t payloadLen,
            const Options& opt, Image& out) {
    if (!payload || payloadLen == 0 || cover.w == 0 || cover.h == 0) return false;
    if (cover.rgb.size() < (size_t)cover.w * cover.h * 3) return false;
    if (opt.compress) return false;  // backend deferred (see FORMAT.md)
    if (opt.auth && opt.password.empty()) return false;
    if (opt.scatter && opt.seed == 0) return false;

    // Salt + KDF: PBKDF2 -> 64B (enc[0..32) + auth[32..64)).
    uint8_t salt[STEGO_SALT_LEN] = {0};
    std::vector<uint8_t> encKey, authKey;
    if (!opt.password.empty()) {
        std::random_device rd;
        for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)rd();
        std::vector<uint8_t> dk = sha::Pbkdf2(
            (const uint8_t*)opt.password.data(), opt.password.size(),
            salt, sizeof(salt), STEGO_PBKDF2_ITER, STEGO_PBKDF2_OUT);
        encKey.assign(dk.begin(), dk.begin() + 32);
        authKey.assign(dk.begin() + 32, dk.end());
    }

    // Stage 1+2: (compress n/a) + encrypt (CTR over enc-key).
    std::vector<uint8_t> body(payload, payload + payloadLen);
    if (!opt.password.empty()) {
        std::vector<uint8_t> ks(body.size());
        sha::KeystreamRaw(encKey.data(), ks.data(), ks.size());
        for (size_t i = 0; i < body.size(); i++) body[i] ^= ks[i];
    }

    // Envelope header (44 bytes).
    std::vector<uint8_t> hdr;
    hdr.push_back(STEGO_MAGIC_0);
    hdr.push_back(STEGO_MAGIC_1);
    hdr.push_back(STEGO_MAGIC_2);
    hdr.push_back(STEGO_MAGIC_3);
    codec::PutU16(hdr, STEGO_FORMAT_V3);
    codec::PutU16(hdr, FlagsOf(opt));
    codec::PutU32(hdr, opt.seed);
    codec::PutU32(hdr, (uint32_t)payloadLen);
    codec::PutU32(hdr, (uint32_t)body.size());
    codec::PutU32(hdr, 0);
    hdr.insert(hdr.end(), salt, salt + sizeof(salt));
    uint32_t hcrc = sha::Crc32(hdr.data(), 40);
    codec::PutU32(hdr, hcrc);

    // Bit source: header + body + data_crc32 [+ hmac over header+ciphertext].
    std::vector<uint8_t> src = hdr;
    src.insert(src.end(), body.begin(), body.end());
    uint32_t dcrc = sha::Crc32(payload, payloadLen);
    size_t dcrcPos = src.size();
    for (int i = 0; i < 4; i++) src.push_back(0);
    src[dcrcPos] = (uint8_t)dcrc;
    src[dcrcPos + 1] = (uint8_t)(dcrc >> 8);
    src[dcrcPos + 2] = (uint8_t)(dcrc >> 16);
    src[dcrcPos + 3] = (uint8_t)(dcrc >> 24);
    if (opt.auth) {
        // NOTE: tag covers header[0..44) + ciphertext ONLY (not data_crc32);
        // decode verifies the identical span. Order matters.
        std::vector<uint8_t> m = sha::Hmac(authKey.data(), authKey.size(),
                                           src.data(), 44 + body.size());
        src.insert(src.end(), m.begin(), m.end());
    }

    size_t needBits = src.size() * 8;
    const size_t kHeaderBits = STEGO_HEADER_LEN * 8;
    const uint32_t kHeaderPx = STEGO_HEADER_PX;
    uint32_t nPx = cover.w * cover.h;
    if (nPx <= kHeaderPx) return false;
    if (needBits < kHeaderBits || needBits - kHeaderBits > ((size_t)nPx - kHeaderPx) * 3) {
        return false;
    }

    out.w = cover.w;
    out.h = cover.h;
    out.rgb = cover.rgb;
    {
        std::vector<uint32_t> seq = codec::Placement(nPx, 0);
        for (size_t k = 0; k < kHeaderBits; k++) {
            int bit = (src[k / 8] >> (k % 8)) & 1;
            codec::PutBit(out.rgb, cover.w, seq, k, bit);
        }
    }
    {
        std::vector<uint32_t> bodyPlace = codec::PlacementRange(
            kHeaderPx, nPx - kHeaderPx, opt.seed);
        for (size_t k = kHeaderBits; k < needBits; k++) {
            int bit = (src[k / 8] >> (k % 8)) & 1;
            codec::PutBit(out.rgb, cover.w, bodyPlace, k - kHeaderBits, bit);
        }
    }
    return true;
}

// --- envelope decode (44B header, PBKDF2 envelope) ---
static bool DecodeEnvelope(const Image& img, const uint8_t* hdr,
                           const std::string& password, std::vector<uint8_t>& out) {
    uint16_t flags = (uint16_t)(hdr[6] | (hdr[7] << 8));
    uint32_t seed = (uint32_t)hdr[8] | ((uint32_t)hdr[9] << 8) |
                    ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
    uint32_t orig = (uint32_t)hdr[12] | ((uint32_t)hdr[13] << 8) |
                    ((uint32_t)hdr[14] << 16) | ((uint32_t)hdr[15] << 24);
    uint32_t comp = (uint32_t)hdr[16] | ((uint32_t)hdr[17] << 8) |
                    ((uint32_t)hdr[18] << 16) | ((uint32_t)hdr[19] << 24);
    const uint8_t* salt = hdr + 24;  // salt field (bytes [24..40))
    uint32_t hcrc = (uint32_t)hdr[40] | ((uint32_t)hdr[41] << 8) |
                    ((uint32_t)hdr[42] << 16) | ((uint32_t)hdr[43] << 24);
    if (stego::sha::Crc32(hdr, 40) != hcrc) return false;
    if (flags & STEGO_F_COMPRESS) return false;
    bool enc = (flags & STEGO_F_ENCRYPT) != 0;
    bool auth = (flags & STEGO_F_AUTH) != 0;
    if ((enc || auth) && password.empty()) return false;
    if (auth && !enc) return false;
    if (comp == 0) return false;

    std::vector<uint8_t> encKey, authKey;
    if (enc) {
        std::vector<uint8_t> dk = stego::sha::Pbkdf2(
            (const uint8_t*)password.data(), password.size(),
            salt, STEGO_SALT_LEN, STEGO_PBKDF2_ITER, STEGO_PBKDF2_OUT);
        encKey.assign(dk.begin(), dk.begin() + 32);
        authKey.assign(dk.begin() + 32, dk.end());
    }

    uint32_t nPx = img.w * img.h;
    if (nPx <= STEGO_HEADER_PX) return false;
    size_t bodyBits = ((size_t)nPx - STEGO_HEADER_PX) * 3;
    std::vector<uint32_t> place =
        stego::codec::PlacementRange(STEGO_HEADER_PX, nPx - STEGO_HEADER_PX, seed);

    std::vector<uint8_t> body(comp);
    auto readBody = [&](size_t bitOff, uint8_t* dst, size_t len) -> bool {
        return ReadStream(img, place, bodyBits, bitOff, dst, len);
    };
    if (!readBody(0, body.data(), comp)) return false;

    const size_t kCrcBit = (size_t)comp * 8;
    const size_t kTagBit = ((size_t)comp + 4) * 8;
    std::vector<uint8_t> stored;
    stored.reserve(44 + comp);
    stored.insert(stored.end(), hdr, hdr + 44);
    stored.insert(stored.end(), body.begin(), body.end());
    if (auth) {
        uint8_t tag[32];
        if (!readBody(kTagBit, tag, 32)) return false;
        std::vector<uint8_t> m = stego::sha::Hmac(
            authKey.data(), authKey.size(), stored.data(), stored.size());
        if (memcmp(m.data(), tag, 32) != 0) return false;
    }
    if (enc) {
        std::vector<uint8_t> ks(comp);
        stego::sha::KeystreamRaw(encKey.data(), ks.data(), ks.size());
        for (size_t i = 0; i < comp; i++) body[i] ^= ks[i];
    }
    uint8_t cb[4];
    if (!readBody(kCrcBit, cb, 4)) return false;
    uint32_t dcrc = (uint32_t)cb[0] | ((uint32_t)cb[1] << 8) |
                    ((uint32_t)cb[2] << 16) | ((uint32_t)cb[3] << 24);
    if (orig != comp) return false;
    if (stego::sha::Crc32(body.data(), body.size()) != dcrc) return false;
    out.swap(body);
    return true;
}

// RS framing (FORMAT.md §2.6): pad to 223B blocks, encode, interleave.
// comp_size = nblocks*255. Inverse fails closed on any undecodable block.
static bool RsProtect(const std::vector<uint8_t>& data,
                      std::vector<uint8_t>& stream, size_t& nblocks) {
    if (data.empty()) return false;
    nblocks = (data.size() + 222) / 223;
    std::vector<std::vector<uint8_t>> cws(nblocks,
                                          std::vector<uint8_t>(255));
    for (size_t b = 0; b < nblocks; b++) {
        uint8_t blk[223] = {0};
        size_t base = b * 223;
        size_t take = data.size() - base < 223 ? data.size() - base : 223;
        memcpy(blk, data.data() + base, take);
        if (!rs::EncodeBlock(blk, cws[b].data())) return false;
    }
    stream.assign(nblocks * 255, 0);
    for (size_t s = 0; s < nblocks * 255; s++)
        stream[s] = cws[s % nblocks][s / nblocks];
    return true;
}

static bool RsUnprotect(const std::vector<uint8_t>& stream, size_t nblocks,
                        std::vector<uint8_t>& data) {
    if (nblocks == 0 || stream.size() != nblocks * 255) return false;
    data.assign(nblocks * 223, 0);
    std::vector<uint8_t> cw(255), part(223);
    for (size_t b = 0; b < nblocks; b++) {
        for (size_t k = 0; k < 255; k++) cw[k] = stream[b + k * nblocks];
        if (!rs::DecodeBlock(cw.data(), part.data())) return false;
        memcpy(data.data() + b * 223, part.data(), 223);
    }
    return true;
}

// --- v4 envelope decode (64B header, AEAD, adaptive placement) ---
static bool DecodeEnvelopeV4(const Image& img, const uint8_t* hdr,
                             const std::string& password,
                             std::vector<uint8_t>& out) {
    uint16_t flags = (uint16_t)(hdr[6] | (hdr[7] << 8));
    uint32_t seed = (uint32_t)hdr[8] | ((uint32_t)hdr[9] << 8) |
                    ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
    uint32_t orig = (uint32_t)hdr[12] | ((uint32_t)hdr[13] << 8) |
                    ((uint32_t)hdr[14] << 16) | ((uint32_t)hdr[15] << 24);
    uint32_t comp = (uint32_t)hdr[16] | ((uint32_t)hdr[17] << 8) |
                    ((uint32_t)hdr[18] << 16) | ((uint32_t)hdr[19] << 24);
    uint32_t costq = (uint32_t)hdr[20] | ((uint32_t)hdr[21] << 8) |
                     ((uint32_t)hdr[22] << 16) | ((uint32_t)hdr[23] << 24);
    const uint8_t* salt = hdr + 24;  // salt field (bytes [24..40))
    uint32_t kdfId = (uint32_t)hdr[40] | ((uint32_t)hdr[41] << 8) |
                     ((uint32_t)hdr[42] << 16) | ((uint32_t)hdr[43] << 24);
    uint32_t hcrc = (uint32_t)hdr[44] | ((uint32_t)hdr[45] << 8) |
                    ((uint32_t)hdr[46] << 16) | ((uint32_t)hdr[47] << 24);
    uint32_t kdfM = (uint32_t)hdr[48] | ((uint32_t)hdr[49] << 8) |
                    ((uint32_t)hdr[50] << 16) | ((uint32_t)hdr[51] << 24);
    uint32_t kdfT = (uint32_t)hdr[52] | ((uint32_t)hdr[53] << 8) |
                    ((uint32_t)hdr[54] << 16) | ((uint32_t)hdr[55] << 24);
    uint32_t kdfLanes = (uint32_t)hdr[56] | ((uint32_t)hdr[57] << 8) |
                        ((uint32_t)hdr[58] << 16) | ((uint32_t)hdr[59] << 24);
    if (stego::sha::Crc32(hdr, 44) != hcrc) return false;
    if (flags & STEGO_F_COMPRESS) return false;
    if (!(flags & STEGO_F_ENCRYPT) || !(flags & STEGO_F_AUTH)) return false;
    if (kdfId == 0) {
        if (kdfM != 0 || kdfT != 0 || kdfLanes != 0) return false;
    } else if (kdfId == 1) {
        // Bounds cap decoder memory/time on hostile headers (DoS gate).
        if (kdfM < 8 || kdfM > 1048576 || kdfT < 1 || kdfT > 16 ||
            kdfLanes != 1)
            return false;
    } else {
        return false;
    }
    if (costq < 1 || costq > 16) return false;
    if (orig < 1) return false;
    bool adaptive = (flags & STEGO_F_ADAPTIVE) != 0;
    bool robust = (flags & STEGO_F_ROBUST) != 0;
    if (robust) {
        size_t expect = ((size_t)orig + 20 + 222) / 223 * 255;
        if (comp != expect) return false;
    } else if (comp != orig + 4 + STEGO_V4_TAG_LEN) {
        return false;
    }

    std::vector<uint8_t> dk;
    if (kdfId == 0) {
        dk = stego::sha::Pbkdf2(
            (const uint8_t*)password.data(), password.size(),
            salt, STEGO_V4_SALT_LEN, STEGO_V4_PBKDF2_ITER, STEGO_V4_KDF_OUT);
    } else {
        dk.resize(STEGO_V4_KDF_OUT);
        if (!stego::argon2::Derive(
                (const uint8_t*)password.data(), password.size(),
                salt, STEGO_V4_SALT_LEN, NULL, 0, NULL, 0, kdfT, kdfM,
                kdfLanes, dk.data(), dk.size()))
            return false;
    }

    uint32_t nPx = img.w * img.h;
    if (nPx <= STEGO_V4_HEADER_PX) return false;
    bool stc = (flags & STEGO_F_STC) != 0;
    size_t needSlots = (size_t)comp * 8 + (stc ? STEGO_STC_H : 0);
    if (needSlots > ((size_t)nPx - STEGO_V4_HEADER_PX) * 2) return false;
    std::vector<uint32_t> order = stego::codec::CandidateOrderV4(
        img.rgb, img.w, img.h, seed, costq, adaptive);
    std::vector<uint8_t> body;
    if (stc) {
        size_t n = (size_t)comp * 8 + STEGO_STC_H;
        std::vector<uint8_t> y(n);
        for (size_t s = 0; s < n; s++) {
            uint32_t ch = order[s / 2] * 3 + (s % 2 == 0 ? 0 : 2);
            y[s] = img.rgb[ch] & 1;
        }
        uint8_t sub[8];
        stego::codec::StcSubmatrix(seed, sub);
        body.assign(comp, 0);
        stego::codec::StcExtract(y.data(), (size_t)comp * 8, sub,
                                 body.data(), comp);
    } else if (!stego::codec::ReadV4(img.rgb, order, comp, body)) {
        return false;
    }
    if (robust) {
        if (comp % 255 != 0) return false;
        size_t nblocks = comp / 255;
        std::vector<uint8_t> cat;
        if (!RsUnprotect(body, nblocks, cat)) return false;
        if (cat.size() < (size_t)orig + 20) return false;
        body.assign(cat.begin(), cat.begin() + orig + 20);  // strip padding
    }
    // From here body.size() is the AEAD length (orig+20); comp was the
    // wire length (equal for non-robust, codeword length for robust).
    size_t cLen = body.size();
    if (cLen != (size_t)orig + 4 + STEGO_V4_TAG_LEN) return false;
    std::vector<uint8_t> pt(cLen - STEGO_V4_TAG_LEN);
    if (!stego::aead::AeadDecrypt(dk.data(), dk.data() + 32, hdr,
                                  STEGO_V4_HEADER_LEN, body.data(),
                                  cLen - STEGO_V4_TAG_LEN,
                                  body.data() + cLen - STEGO_V4_TAG_LEN,
                                  pt.data()))
        return false;
    uint32_t dcrc = (uint32_t)pt[0] | ((uint32_t)pt[1] << 8) |
                    ((uint32_t)pt[2] << 16) | ((uint32_t)pt[3] << 24);
    if (pt.size() != (size_t)orig + 4) return false;
    if (stego::sha::Crc32(pt.data() + 4, orig) != dcrc) return false;
    out.assign(pt.begin() + 4, pt.end());
    return true;
}

bool Decode(const Image& img, const std::string& password,
            std::vector<uint8_t>& out) {
    out.clear();
    if (img.w == 0 || img.h == 0) return false;
    if (img.rgb.size() < (size_t)img.w * img.h * 3) return false;
    size_t totalBits = (size_t)img.w * img.h * 3;

    // v3 probe first (deployed majority, exact legacy path): 44 bytes over
    // the 3-channel sequential map. v4 probe second (64 bytes over R/B
    // slots — v4's magic lives there, so a v3-map read of a v4 image is
    // garbage by construction). Magic + version + CRC decide; both probes
    // fail closed.
    uint8_t hdr[STEGO_V4_HEADER_LEN];
    std::vector<uint32_t> seq = codec::Placement(img.w * img.h, 0);
    if (ReadStream(img, seq, totalBits, 0, hdr, STEGO_HEADER_LEN) &&
        hdr[0] == STEGO_MAGIC_0 && hdr[1] == STEGO_MAGIC_1 &&
        hdr[2] == STEGO_MAGIC_2 && hdr[3] == STEGO_MAGIC_3 &&
        (uint16_t)(hdr[4] | (hdr[5] << 8)) == STEGO_FORMAT_V3)
        return DecodeEnvelope(img, hdr, password, out);
    std::vector<uint32_t> hdrOrder;
    for (uint32_t i = 0; i < STEGO_V4_HEADER_PX; i++) hdrOrder.push_back(i);
    std::vector<uint8_t> hdr64;
    if (!stego::codec::ReadV4(img.rgb, hdrOrder, STEGO_V4_HEADER_LEN,
                              hdr64))
        return false;
    memcpy(hdr, hdr64.data(), STEGO_V4_HEADER_LEN);
    if (hdr[0] != STEGO_MAGIC_0 || hdr[1] != STEGO_MAGIC_1 ||
        hdr[2] != STEGO_MAGIC_2 || hdr[3] != STEGO_MAGIC_3) return false;
    uint16_t ver = (uint16_t)(hdr[4] | (hdr[5] << 8));
    if (ver != STEGO_FORMAT_V4) return false;
    return DecodeEnvelopeV4(img, hdr, password, out);
}

size_t CapacityV4(uint32_t w, uint32_t h, bool robust) {
    // 256 header pixels reserved (R/B slots); body carries 2 bits/px.
    // Robust pays RS(255,223) framing on the wire (AEAD overhead inside).
    size_t nPx = (size_t)w * h;
    if (nPx <= STEGO_V4_HEADER_PX) return 0;
    size_t cwBytes = ((nPx - STEGO_V4_HEADER_PX) * 2) / 8;
    if (!robust) {
        if (cwBytes < 4 + STEGO_V4_TAG_LEN) return 0;
        return cwBytes - (4 + STEGO_V4_TAG_LEN);
    }
    size_t nblocks = cwBytes / 255;
    if (nblocks == 0) return 0;
    size_t data = nblocks * 223;
    return data > 4 + STEGO_V4_TAG_LEN ? data - (4 + STEGO_V4_TAG_LEN) : 0;
}

bool EncodeV4(const Image& cover, const uint8_t* payload, size_t payloadLen,
              const OptionsV4& opt, Image& out) {
    if (!payload || payloadLen == 0 || cover.w == 0 || cover.h == 0)
        return false;
    if (cover.rgb.size() < (size_t)cover.w * cover.h * 3) return false;
    if (opt.password.empty()) return false;  // v4 always encrypted+authed
    if (opt.costq < 1 || opt.costq > 16) return false;
    uint32_t kdfId = (uint32_t)opt.kdf;
    uint32_t kdfM = opt.kdf_m_kib, kdfT = opt.kdf_time, kdfLanes = opt.kdf_lanes;
    if (kdfId == 0) {
        kdfM = kdfT = kdfLanes = 0;
    } else if (kdfId == 1) {
        if (kdfM < 8 || kdfM > 1048576 || kdfT < 1 || kdfT > 16 ||
            kdfLanes != 1)
            return false;
    } else {
        return false;
    }
    uint32_t nPx = cover.w * cover.h;
    if (nPx <= STEGO_V4_HEADER_PX) return false;
    uint32_t seed = opt.seed;
    if (seed == 0 && opt.adaptive) {
        // 0 is forbidden on the wire for ADAPTIVE: pick nonzero random
        // (same rule as the Python port — 0 is never written).
        std::random_device rd;
        do {
            seed = (uint32_t)rd();
        } while (seed == 0);
    }

    uint8_t salt[STEGO_V4_SALT_LEN];
    {
        std::random_device rd;
        for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)rd();
    }
    std::vector<uint8_t> dk;
    if (kdfId == 0) {
        dk = sha::Pbkdf2(
            (const uint8_t*)opt.password.data(), opt.password.size(),
            salt, sizeof(salt), STEGO_V4_PBKDF2_ITER, STEGO_V4_KDF_OUT);
    } else {
        dk.resize(STEGO_V4_KDF_OUT);
        if (!argon2::Derive(
                (const uint8_t*)opt.password.data(), opt.password.size(),
                salt, sizeof(salt), NULL, 0, NULL, 0, kdfT, kdfM, kdfLanes,
                dk.data(), dk.size()))
            return false;
    }

    uint32_t cLen = (uint32_t)payloadLen + 4 + STEGO_V4_TAG_LEN;  // AEAD bytes
    uint32_t comp = cLen;
    size_t nblocks = 0;
    if (opt.robust) {
        nblocks = (cLen + 222) / 223;
        comp = (uint32_t)(nblocks * 255);  // RS codeword bytes on wire
    }
    std::vector<uint8_t> hdr;
    hdr.push_back(STEGO_MAGIC_0);
    hdr.push_back(STEGO_MAGIC_1);
    hdr.push_back(STEGO_MAGIC_2);
    hdr.push_back(STEGO_MAGIC_3);
    codec::PutU16(hdr, STEGO_FORMAT_V4);
    uint16_t flags = STEGO_F_ENCRYPT | STEGO_F_AUTH;
    if (opt.scatter) flags |= STEGO_F_SCATTER;
    if (opt.adaptive) flags |= STEGO_F_ADAPTIVE;
    if (opt.robust) flags |= STEGO_F_ROBUST;
    if (opt.stc) flags |= STEGO_F_STC;
    codec::PutU16(hdr, flags);
    codec::PutU32(hdr, seed);
    codec::PutU32(hdr, (uint32_t)payloadLen);
    codec::PutU32(hdr, comp);
    codec::PutU32(hdr, opt.costq);
    hdr.insert(hdr.end(), salt, salt + sizeof(salt));
    codec::PutU32(hdr, kdfId);
    uint32_t hcrc = sha::Crc32(hdr.data(), 44);
    codec::PutU32(hdr, hcrc);
    codec::PutU32(hdr, kdfM);
    codec::PutU32(hdr, kdfT);
    codec::PutU32(hdr, kdfLanes);
    codec::PutU32(hdr, 0);

    std::vector<uint8_t> pt(4 + payloadLen);
    uint32_t dcrc = sha::Crc32(payload, payloadLen);
    pt[0] = (uint8_t)dcrc;
    pt[1] = (uint8_t)(dcrc >> 8);
    pt[2] = (uint8_t)(dcrc >> 16);
    pt[3] = (uint8_t)(dcrc >> 24);
    memcpy(pt.data() + 4, payload, payloadLen);
    std::vector<uint8_t> ciph(cLen);
    uint8_t tag[STEGO_V4_TAG_LEN];
    aead::AeadEncrypt(dk.data(), dk.data() + 32, hdr.data(), hdr.size(),
                      pt.data(), pt.size(), ciph.data(), tag);
    memcpy(ciph.data() + cLen - STEGO_V4_TAG_LEN, tag, STEGO_V4_TAG_LEN);
    std::vector<uint8_t> body;
    if (opt.robust) {
        if (!RsProtect(ciph, body, nblocks)) return false;
    } else {
        body.swap(ciph);
    }

    std::vector<uint32_t> order;
    std::vector<uint8_t> ocosts;
    codec::OrderCostsV4(cover.rgb, cover.w, cover.h, seed, opt.costq,
                        opt.adaptive, order, ocosts);
    size_t needSlots = (size_t)comp * 8 + (opt.stc ? STEGO_STC_H : 0);
    if (needSlots > order.size() * 2) return false;
    uint64_t seed64 = (uint64_t)seed ^
                      ((uint64_t)salt[0] | ((uint64_t)salt[1] << 8) |
                       ((uint64_t)salt[2] << 16) | ((uint64_t)salt[3] << 24));
    std::vector<uint32_t> hdrOrder;
    for (uint32_t i = 0; i < STEGO_V4_HEADER_PX; i++) hdrOrder.push_back(i);
    out.w = cover.w;
    out.h = cover.h;
    out.rgb = cover.rgb;
    if (!codec::EmbedV4(out.rgb, hdrOrder, hdr.data(), hdr.size(),
                        seed64, 0))
        return false;
    if (opt.stc) {
        uint8_t sub[8];
        codec::StcSubmatrix(seed, sub);
        size_t n = (size_t)comp * 8 + STEGO_STC_H;
        std::vector<uint8_t> coverBits(n), slotCosts(n), flips(n);
        for (size_t s = 0; s < n; s++) {
            uint32_t ch = order[s / 2] * 3 + (s % 2 == 0 ? 0 : 2);
            coverBits[s] = cover.rgb[ch] & 1;
            slotCosts[s] = ocosts[s / 2];
        }
        if (!codec::StcEncode(coverBits.data(), slotCosts.data(), n,
                              body.data(), body.size(), sub, flips.data()))
            return false;
        codec::ApplyFlipsV4(out.rgb, order, flips.data(), n, seed64,
                            (size_t)STEGO_V4_HEADER_LEN * 8);
    } else if (!codec::EmbedV4(out.rgb, order, body.data(), body.size(),
                               seed64, (size_t)STEGO_V4_HEADER_LEN * 8)) {
        return false;
    }
    return true;
}

}  // namespace stego

// --- C ABI ---
extern "C" {

int stego_encode(const stego_image_t* cover, const uint8_t* payload,
                 size_t payload_len, const stego_options_t* opt,
                 uint8_t* out_rgb) {
    if (!cover || !payload || !opt || !out_rgb) return STEGO_C_ERR_PARAM;
    stego::Image c;
    c.w = cover->w;
    c.h = cover->h;
    c.rgb.assign(cover->rgb, cover->rgb + (size_t)cover->w * cover->h * 3);
    stego::Options o;
    o.compress = opt->compress != 0;
    o.scatter = opt->scatter != 0;
    o.seed = opt->seed;
    if (opt->password) o.password = opt->password;
    o.auth = opt->auth != 0;
    stego::Image res;
    if (!stego::Encode(c, payload, payload_len, o, res)) {
        return (o.compress || (o.auth && o.password.empty())) ? STEGO_C_ERR_UNSUPPORTED
                                                              : STEGO_C_ERR_CAPACITY;
    }
    memcpy(out_rgb, res.rgb.data(), res.rgb.size());
    return STEGO_C_OK;
}

int stego_encode_v4(const stego_image_t* cover, const uint8_t* payload,
                     size_t payload_len, const stego_options_v4_t* opt,
                     uint8_t* out_rgb) {
    if (!cover || !payload || !opt || !out_rgb) return STEGO_C_ERR_PARAM;
    stego::Image c;
    c.w = cover->w;
    c.h = cover->h;
    c.rgb.assign(cover->rgb, cover->rgb + (size_t)cover->w * cover->h * 3);
    stego::OptionsV4 o;
    o.seed = opt->seed;
    if (opt->password) o.password = opt->password;
    o.scatter = opt->scatter != 0;
    o.adaptive = opt->adaptive != 0;
    o.robust = opt->robust != 0;
    o.costq = opt->costq ? opt->costq : 8;
    o.stc = opt->stc != 0;
    o.kdf = opt->kdf;
    o.kdf_m_kib = opt->kdf_m_kib ? opt->kdf_m_kib : 65536;
    o.kdf_time = opt->kdf_time ? opt->kdf_time : 3;
    o.kdf_lanes = opt->kdf_lanes ? opt->kdf_lanes : 1;
    stego::Image res;
    if (!stego::EncodeV4(c, payload, payload_len, o, res)) {
        return o.password.empty() ? STEGO_C_ERR_PARAM : STEGO_C_ERR_CAPACITY;
    }
    memcpy(out_rgb, res.rgb.data(), res.rgb.size());
    return STEGO_C_OK;
}

int stego_decode(const stego_image_t* img, const char* password,
                 uint8_t** out, size_t* out_len) {
    if (!img || !out || !out_len) return STEGO_C_ERR_PARAM;
    stego::Image c;
    c.w = img->w;
    c.h = img->h;
    c.rgb.assign(img->rgb, img->rgb + (size_t)img->w * img->h * 3);
    std::vector<uint8_t> res;
    if (!stego::Decode(c, password ? password : "", res)) return STEGO_C_ERR_FORMAT;
    *out = (uint8_t*)malloc(res.size() ? res.size() : 1);
    if (!*out) return STEGO_C_ERR_PARAM;
    memcpy(*out, res.data(), res.size());
    *out_len = res.size();
    return STEGO_C_OK;
}

void stego_free(void* p) { free(p); }
const char* stego_version(void) { return stego::Version(); }

}  // extern "C"
