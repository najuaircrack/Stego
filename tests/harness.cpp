// harness.cpp - argv-driven cross-implementation test helper.
//   harness enc <w> <h> <seed> <pw|-> <auth01> <in.bin> <out.rgb>
//   harness enc4 <w> <h> <seed> <pw> <adaptive01> <robust01> <costq> <stc01> <kdf> <m> <t> <in.bin> <out.rgb>
//   harness dec <w> <h> <pw|-> <in.rgb> <out.bin>   (dispatches v3/v4)
//   harness kdf <t> <m_kib> <lanes> <outlen> <pwhex> <salthex> <out.bin>
// RGB files are raw triplets (no PNG container); pytest drives both sides.
#include "stego/stego.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

namespace stego {
namespace argon2 {
bool Derive(const uint8_t* pw, size_t pwLen, const uint8_t* salt,
            size_t saltLen, const uint8_t* secret, size_t secretLen,
            const uint8_t* ad, size_t adLen, uint32_t passes,
            uint32_t mem_kib, uint32_t lanes, uint8_t* out, size_t outLen);
}  // namespace argon2
}  // namespace stego

static std::vector<uint8_t> Slurp(const char* path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: harness enc|dec ...\n";
        return 2;
    }
    std::string mode = argv[1];
    if (mode == "enc") {
        if (argc != 9) return 2;
        uint32_t w = (uint32_t)atoi(argv[2]);
        uint32_t h = (uint32_t)atoi(argv[3]);
        uint32_t seed = (uint32_t)atoi(argv[4]);
        std::string pw = argv[5];
        if (pw == "-") pw.clear();
        int auth = atoi(argv[6]);
        std::vector<uint8_t> cover((size_t)w * h * 3, 0);
        std::vector<uint8_t> payload = Slurp(argv[7]);
        stego::Image c;
        c.w = w;
        c.h = h;
        c.rgb = cover;
        stego::Options o;
        o.scatter = seed != 0;
        o.seed = seed;
        o.password = pw;
        o.auth = auth != 0;
        stego::Image e;
        if (!stego::Encode(c, payload.data(), payload.size(), o, e)) {
            std::cerr << "encode failed\n";
            return 1;
        }
        std::ofstream f(argv[8], std::ios::binary);
        f.write((const char*)e.rgb.data(), e.rgb.size());
        return 0;
    }
    if (mode == "enc4") {
        if (argc != 15) return 2;
        uint32_t w = (uint32_t)atoi(argv[2]);
        uint32_t h = (uint32_t)atoi(argv[3]);
        uint32_t seed = (uint32_t)atoi(argv[4]);
        std::string pw = argv[5];
        int adaptive = atoi(argv[6]);
        int robust = atoi(argv[7]);
        uint32_t costq = (uint32_t)atoi(argv[8]);
        int stc = atoi(argv[9]);
        int kdf = atoi(argv[10]);
        uint32_t kdf_m = (uint32_t)atoi(argv[11]);
        uint32_t kdf_t = (uint32_t)atoi(argv[12]);
        std::vector<uint8_t> cover((size_t)w * h * 3, 0);
        std::vector<uint8_t> payload = Slurp(argv[13]);
        stego::Image c;
        c.w = w;
        c.h = h;
        c.rgb = cover;
        stego::OptionsV4 o;
        o.seed = seed;
        o.password = pw;
        o.adaptive = adaptive != 0;
        o.robust = robust != 0;
        o.costq = costq;
        o.stc = stc != 0;
        o.kdf = kdf;
        o.kdf_m_kib = kdf_m;
        o.kdf_time = kdf_t;
        o.kdf_lanes = 1;
        stego::Image e;
        if (!stego::EncodeV4(c, payload.data(), payload.size(), o, e)) {
            std::cerr << "encode4 failed\n";
            return 1;
        }
        std::ofstream f(argv[14], std::ios::binary);
        f.write((const char*)e.rgb.data(), e.rgb.size());
        return 0;
    }
    if (mode == "kdf") {        // argon2::Derive cross-check vs python (hex in, raw tag out).
        if (argc != 9) return 2;
        uint32_t t = (uint32_t)atoi(argv[2]);
        uint32_t m = (uint32_t)atoi(argv[3]);
        uint32_t p = (uint32_t)atoi(argv[4]);
        size_t outLen = (size_t)atoi(argv[5]);
        auto unhex = [](const char* s) {
            std::vector<uint8_t> v;
            for (; s[0] && s[1]; s += 2)
                v.push_back((uint8_t)strtoul(std::string(s, 2).c_str(),
                                             NULL, 16));
            return v;
        };
        std::vector<uint8_t> pw = unhex(argv[6]);
        std::vector<uint8_t> salt = unhex(argv[7]);
        std::vector<uint8_t> tag(outLen ? outLen : 1, 0);
        if (!stego::argon2::Derive(pw.data(), pw.size(), salt.data(),
                                   salt.size(), NULL, 0, NULL, 0, t, m, p,
                                   tag.data(), outLen)) {
            std::cerr << "kdf failed\n";
            return 1;
        }
        std::ofstream f(argv[8], std::ios::binary);
        f.write((const char*)tag.data(), outLen);
        return 0;
    }
    if (mode == "dec") {        if (argc != 7) return 2;
        uint32_t w = (uint32_t)atoi(argv[2]);
        uint32_t h = (uint32_t)atoi(argv[3]);
        std::string pw = argv[4];
        if (pw == "-") pw.clear();
        std::vector<uint8_t> rgb = Slurp(argv[5]);
        stego::Image c;
        c.w = w;
        c.h = h;
        c.rgb = rgb;
        std::vector<uint8_t> out;
        if (!stego::Decode(c, pw, out)) {
            std::cerr << "decode failed\n";
            return 1;
        }
        std::ofstream f(argv[6], std::ios::binary);
        f.write((const char*)out.data(), out.size());
        return 0;
    }
    return 2;
}
