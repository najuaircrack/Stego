// extract.cpp - template: decode a PNG file to a payload file. Windows.
// PNG loading via ../gdiplus_glue.h (the only platform piece; the decode
// itself is pure stego API). Decode only. What you DO with the bytes
// afterwards is your responsibility.
#include "stego/stego.h"
#include "gdiplus_glue.h"
#include <cstdio>
#include <vector>

#pragma comment(lib, "gdiplus.lib")

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        printf("usage: extract.exe <image.png> <out.bin> [password]\n");
        return 2;
    }
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR token = 0;
    Gdiplus::GdiplusStartup(&token, &gsi, NULL);

    stego::Image img;
    bool ok = StegoLoadPng(argv[1], img.w, img.h, img.rgb);
    std::vector<uint8_t> out;
    std::string pw;
    if (ok) {
        char narrow[512] = {0};
        if (argc > 3) {
            WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, narrow,
                                sizeof(narrow), NULL, NULL);
            pw = narrow;
        }
        ok = stego::Decode(img, pw, out);
    }
    if (ok) {
        FILE* f = nullptr;
        _wfopen_s(&f, argv[2], L"wb");
        if (f) {
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        } else {
            ok = false;
        }
    }
    Gdiplus::GdiplusShutdown(token);
    printf(ok ? "decoded %zu bytes\n" : "decode failed\n", out.size());
    return ok ? 0 : 1;
}
