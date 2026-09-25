// amalgam_check.cpp — identity proof: same vectors through single_include.
// Usage: amalgam_check <w> <h> <seed> <pw|-> <auth01> <payload.bin> <out.rgb>
#define STEGO_IMPLEMENTATION
#include "stego_all.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 9) {
        std::cerr << "usage: amalgam_check enc w h seed pw auth src dst\n";
        return 2;
    }
    if (std::string(argv[1]) != "enc") return 2;
    uint32_t w = (uint32_t)atoi(argv[2]);
    uint32_t h = (uint32_t)atoi(argv[3]);
    uint32_t seed = (uint32_t)atoi(argv[4]);
    std::string pw = argv[5];
    if (pw == "-") pw.clear();
    int auth = atoi(argv[6]);
    std::ifstream f(argv[7], std::ios::binary);
    std::vector<uint8_t> payload((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
    std::vector<uint8_t> cover((size_t)w * h * 3, 0);
    stego_image_t c;
    c.w = w;
    c.h = h;
    c.rgb = cover.data();
    stego_options_t o;
    o.compress = 0;
    o.scatter = seed != 0;
    o.seed = seed;
    o.password = pw.empty() ? NULL : pw.c_str();
    o.auth = auth;
    std::vector<uint8_t> out((size_t)w * h * 3, 0);
    int rc = stego_encode(&c, payload.data(), payload.size(), &o, out.data());
    if (rc != STEGO_C_OK) {
        std::cerr << "encode failed\n";
        return 1;
    }
    std::ofstream o2(argv[8], std::ios::binary);
    o2.write((const char*)out.data(), out.size());
    return 0;
}
