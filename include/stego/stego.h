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
bool Encode(const Image& cover, const uint8_t* payload, size_t payloadLen,
            const Options& opt, Image& out);

// Decode: single envelope format (magic + version + header CRC).
// Strict: CRC/HMAC failures return false. No legacy fallbacks.
bool Decode(const Image& img, const std::string& password,
            std::vector<uint8_t>& out);

// Capacity in payload bytes for given dims + options overhead estimate.
size_t Capacity(uint32_t w, uint32_t h);

// Library version string ("3.0.0").
const char* Version();

}  // namespace stego
