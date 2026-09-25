// harness.cpp - argv-driven cross-implementation test helper.
//   harness enc <w> <h> <seed> <pw|-> <auth01> <in.bin> <out.rgb>
//   harness dec <w> <h> <pw|-> <in.rgb> <out.bin>
// RGB files are raw triplets (no PNG container); pytest drives both sides.
#include "stego/stego.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

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
    if (mode == "dec") {
        if (argc != 7) return 2;
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
