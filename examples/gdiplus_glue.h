// examples/gdiplus_glue.h — optional Windows glue: PNG file <-> RGB buffer.
// Header-only; products include it (not part of lib link). Requires GDI+
// initialized by the caller (GdiplusStartup/Shutdown around usage).
#pragma once
#include <windows.h>
#include <gdiplus.h>
#include <vector>
#include <string>
inline bool StegoLoadPng(const wchar_t* path, uint32_t& w, uint32_t& h,
                         std::vector<uint8_t>& rgb) {    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromFile(path, FALSE);
    if (!bmp || bmp->GetLastStatus() != Gdiplus::Ok) {
        delete bmp;
        return false;
    }
    w = bmp->GetWidth();
    h = bmp->GetHeight();
    Gdiplus::BitmapData bd;
    Gdiplus::Rect rc(0, 0, (INT)w, (INT)h);
    bool ok = false;
    // 32bppARGB (0x0026200A): the production-proven lock path. Numeric
    // literal: avoids header version quirks with the enum name. Strip
    // alpha into RGB triplets (BGRA bytes: B=0 G=1 R=2, alpha ignored).
    if (bmp->LockBits(&rc, Gdiplus::ImageLockModeRead,
                      (Gdiplus::PixelFormat)0x0026200A, &bd) == Gdiplus::Ok) {
        rgb.resize((size_t)w * h * 3);
        for (UINT y = 0; y < h; y++) {
            const uint8_t* row = (const uint8_t*)bd.Scan0 + (size_t)y * bd.Stride;
            for (UINT x = 0; x < w; x++) {
                rgb[((size_t)y * w + x) * 3 + 0] = row[x * 4 + 2];
                rgb[((size_t)y * w + x) * 3 + 1] = row[x * 4 + 1];
                rgb[((size_t)y * w + x) * 3 + 2] = row[x * 4 + 0];
            }
        }
        bmp->UnlockBits(&bd);
        ok = true;
    }
    delete bmp;
    return ok;
}

inline bool StegoSavePng(const wchar_t* path, uint32_t w, uint32_t h,
                         const std::vector<uint8_t>& rgb) {
    if (rgb.size() < (size_t)w * h * 3) return false;
    Gdiplus::Bitmap bmp((INT)w, (INT)h, (Gdiplus::PixelFormat)0x0021808);
    Gdiplus::BitmapData bd;
    Gdiplus::Rect rc(0, 0, (INT)w, (INT)h);
    if (bmp.LockBits(&rc, Gdiplus::ImageLockModeWrite,
                     (Gdiplus::PixelFormat)0x0021808, &bd) != Gdiplus::Ok) {
        return false;
    }
    for (UINT y = 0; y < h; y++) {
        memcpy((uint8_t*)bd.Scan0 + (size_t)y * bd.Stride,
               &rgb[(size_t)y * w * 3], (size_t)w * 3);
    }
    bmp.UnlockBits(&bd);
    CLSID pngClsid;
    UINT n = 0, sz = 0;
    Gdiplus::GetImageEncodersSize(&n, &sz);
    std::vector<uint8_t> buf(sz);
    Gdiplus::ImageCodecInfo* info = (Gdiplus::ImageCodecInfo*)buf.data();
    Gdiplus::GetImageEncoders(n, sz, info);
    bool found = false;
    for (UINT i = 0; i < n; i++) {
        if (wcscmp(info[i].MimeType, L"image/png") == 0) {
            pngClsid = info[i].Clsid;
            found = true;
            break;
        }
    }
    if (!found) return false;
    return bmp.Save(path, &pngClsid, NULL) == Gdiplus::Ok;
}

// C-friendly loader: malloc'd RGB triplets (caller frees with free()).
// Exists so pure-C templates need no STL. Not part of the library ABI.
inline int StegoLoadPngInto(const wchar_t* path, uint32_t* w, uint32_t* h,
                            uint8_t** outRgb) {
    std::vector<uint8_t> rgb;
    uint32_t tw = 0, th = 0;
    if (!StegoLoadPng(path, tw, th, rgb)) return 0;
    uint8_t* buf = (uint8_t*)malloc(rgb.size() ? rgb.size() : 1);
    if (!buf) return 0;
    memcpy(buf, rgb.data(), rgb.size());
    *w = tw;
    *h = th;
    *outRgb = buf;
    return 1;
}
