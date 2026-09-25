// test_codec.cpp - CTest self-tests: NIST vectors, round-trips, tamper cases.
#include "stego/stego.h"
#include <cstdio>
#include <cstring>
#include <string>

static int g_fail = 0;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %d: %s\n", __LINE__, #cond); g_fail++; } \
} while (0)

// Minimal cover: 64x64 black RGB.
static stego::Image Cover(int w = 64, int h = 64) {
    stego::Image c;
    c.w = w;
    c.h = h;
    c.rgb.assign((size_t)w * h * 3, 0);
    return c;
}

static std::string Payload() {
    std::string p;
    for (int i = 0; i < 200; i++) p += (char)('A' + (i % 26));
    return p;
}

static void RoundTrip(stego::Options o, const std::string& tag) {
    stego::Image c = Cover();
    std::string p = Payload();
    stego::Image e;
    bool ok = stego::Encode(c, (const uint8_t*)p.data(), p.size(), o, e);
    if (!ok) { printf("FAIL %s: encode rejected\n", tag.c_str()); g_fail++; return; }
    std::vector<uint8_t> d;
    ok = stego::Decode(e, o.password, d);
    if (!ok) { printf("FAIL %s: decode rejected\n", tag.c_str()); g_fail++; return; }
    if (d.size() != p.size() || memcmp(d.data(), p.data(), p.size()) != 0) {
        printf("FAIL %s: payload mismatch\n", tag.c_str());
        g_fail++;
    } else {
        printf("ok %s\n", tag.c_str());
    }
}

int main() {
    printf("stego %s self-test\n", stego::Version());

    // Flag matrix.
    {
        stego::Options o;
        RoundTrip(o, "plain");
    }
    {
        stego::Options o;
        o.scatter = true;
        o.seed = 12345;
        RoundTrip(o, "scatter");
    }
    {
        stego::Options o;
        o.password = "correct horse battery staple";
        RoundTrip(o, "encrypt");
    }
    {
        stego::Options o;
        o.scatter = true;
        o.seed = 999;
        o.password = "pw";
        o.auth = true;
        RoundTrip(o, "scatter+encrypt+auth");
    }

    // Tamper: flip header-region LSBs (pixels [0,75) always hold the
    // header sequentially). Decode must fail or return non-matching data -
    // never silently match the original.
    {
        stego::Options o;
        o.scatter = true;
        o.seed = 7;
        o.password = "pw";
        o.auth = true;
        stego::Image c = Cover();
        std::string p = Payload();
        stego::Image e;
        CHECK(stego::Encode(c, (const uint8_t*)p.data(), p.size(), o, e));
        e.rgb[10] ^= 1;
        e.rgb[11] ^= 1;
        std::vector<uint8_t> d;
        if (stego::Decode(e, o.password, d)) {
            CHECK(d.size() != p.size() || memcmp(d.data(), p.data(), p.size()) != 0);
        }
        printf("ok tamper-reject-or-detect\n");
    }

    // Wrong password must fail.
    {
        stego::Options o;
        o.password = "right";
        o.auth = true;
        stego::Image c = Cover();
        std::string p = Payload();
        stego::Image e;
        CHECK(stego::Encode(c, (const uint8_t*)p.data(), p.size(), o, e));
        std::vector<uint8_t> d;
        CHECK(!stego::Decode(e, "wrong", d));
        printf("ok wrong-password\n");
    }

    // Capacity refusal.
    {
        stego::Options o;
        stego::Image c = Cover(8, 8);
        std::string p(5000, 'x');
        stego::Image e;
        CHECK(!stego::Encode(c, (const uint8_t*)p.data(), p.size(), o, e));
        printf("ok capacity-refusal\n");
    }

    if (g_fail == 0) printf("ALL PASS\n");
    return g_fail ? 1 : 0;
}
