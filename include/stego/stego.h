// stego.h - public C++ API. Operates on raw RGB buffers (no file IO;
// products convert PNG<->RGB with GDI+/PIL - see examples/gdiplus_glue.h).
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

namespace stego {

struct Image {
    uint32_t w = 0, h = 0;
    std::vector<uint8_t> rgb;  // w*h*3 bytes, R,G,B order
};

struct Options {
    bool compress = false;   // reserved: currently rejected (no backend)
    bool scatter = false;    // PRNG placement (seed required if true)
    uint32_t seed = 0;       // 0 = sequential layout
    std::string password;    // empty = no encryption/auth
    bool auth = false;       // HMAC (requires non-empty password)
};

// Encode payload into cover (cover pixels preserved except LSBs).
// Returns false on capacity/parameter errors. Payload plus header/CRC/HMAC
// overhead must fit in w*h*3 bits. On success `out` is a full RGB image.
// Writes the v3 envelope (frozen).
bool Encode(const Image& cover, const uint8_t* payload, size_t payloadLen,
            const Options& opt, Image& out);

// v4 options (FORMAT.md §2): always encrypted + authenticated (password
// REQUIRED); adaptive ternary placement over R/B slots (green untouched).
struct OptionsV4 {
    uint32_t seed = 0;        // 0 = random nonzero when adaptive,
                              // sequential when non-adaptive
    std::string password;     // REQUIRED, non-empty
    bool scatter = true;      // policy signal (keyed order always applies)
    bool adaptive = true;     // cost-ordered placement (green-invariant)
    bool robust = false;      // RS-ECC framing (§2.6)
    uint32_t costq = 8;       // cost buckets 1..16
    bool stc = true;          // syndrome-trellis coding (§2.4b)
    int kdf = 1;              // 0 = PBKDF2-210k (fast), 1 = Argon2id
    uint32_t kdf_m_kib = 65536;  // Argon2id memory (KiB)
    uint32_t kdf_time = 3;       // Argon2id passes
    uint32_t kdf_lanes = 1;      // Argon2id lanes (1 supported)
};

// Encode with the v4 envelope. Returns false on capacity/parameter
// errors. New function (additive): v3 Encode behavior is unchanged.
bool EncodeV4(const Image& cover, const uint8_t* payload, size_t payloadLen,
              const OptionsV4& opt, Image& out);

// Decode: dispatches on the header version (v3 and v4 accepted).
// Strict: CRC/AEAD failures return false. No legacy fallbacks.
bool Decode(const Image& img, const std::string& password,
            std::vector<uint8_t>& out);

// Capacity in payload bytes for given dims + options overhead estimate.
size_t Capacity(uint32_t w, uint32_t h);

// v4 capacity (2 bits/px body over R/B slots, minus AEAD overhead).
size_t CapacityV4(uint32_t w, uint32_t h, bool robust);

// Library version string ("4.0.0").
const char* Version();

}  // namespace stego
