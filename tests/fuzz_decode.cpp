// fuzz_decode.cpp - libFuzzer entry: Decode must never crash/hang on
// arbitrary bytes (fail-closed boolean only). Built with STEGO_FUZZ=ON
// (Clang only; not part of default builds). Corpus: any .rgb plus the
// committed tests/vectors/*.rgb files.
#include "stego/stego.h"
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) return 0;
    // Small dims keep every iteration fast; the codec must still fail
    // clean (never OOB) on all of them.
    uint32_t w = 32 + (uint32_t)(data[0] % 4) * 32;  // 32..128
    uint32_t h = 32 + (uint32_t)(data[1] % 4) * 32;
    size_t need = (size_t)w * h * 3;
    if (size - 2 < need) return 0;  // harness feeds exact-size inputs
    if (need > 128 * 128 * 3) return 0;
    stego::Image img;
    img.w = w;
    img.h = h;
    img.rgb.assign(data + 2, data + 2 + need);
    std::vector<uint8_t> out;
    static const char* pws[] = {"", "pw", "correct horse battery staple",
                                "v4-test-pw-1"};
    for (int i = 0; i < 4; i++) {
        out.clear();
        (void)stego::Decode(img, pws[i], out);
    }
    return 0;
}
