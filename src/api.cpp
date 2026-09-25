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
}  // namespace codec

const char* Version() { return "3.0.0"; }

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
    codec::PutU16(hdr, STEGO_FORMAT_VERSION);
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

bool Decode(const Image& img, const std::string& password,
            std::vector<uint8_t>& out) {
    out.clear();
    if (img.w == 0 || img.h == 0) return false;
    if (img.rgb.size() < (size_t)img.w * img.h * 3) return false;
    size_t totalBits = (size_t)img.w * img.h * 3;

    // Single envelope header (44 bytes, sequential pixels [0,118)).
    // Anything else - wrong magic, wrong version, CRC/auth failure -
    // is rejected. No fallbacks.
    uint8_t hdr[STEGO_HEADER_LEN];
    std::vector<uint32_t> seq = codec::Placement(img.w * img.h, 0);
    if (!ReadStream(img, seq, totalBits, 0, hdr, sizeof(hdr))) return false;
    if (hdr[0] != STEGO_MAGIC_0 || hdr[1] != STEGO_MAGIC_1 ||
        hdr[2] != STEGO_MAGIC_2 || hdr[3] != STEGO_MAGIC_3) return false;
    uint16_t ver = (uint16_t)(hdr[4] | (hdr[5] << 8));
    if (ver != STEGO_FORMAT_VERSION) return false;
    return DecodeEnvelope(img, hdr, password, out);
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
