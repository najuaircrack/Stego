/* extract.c — template: decode raw RGB triplets to a payload file.
   Portable C99 + stego C ABI only (no platform code, no image codecs).
   Usage: extract <image.rgb> <width> <height> <out.bin> [password]
   (Produce .rgb with: python -c "from PIL import Image; ..." or any dumper.)
   Decode only. What you DO with the bytes afterwards is your responsibility. */
#define STEGO_IMPLEMENTATION
#include "stego_all.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 5) {
        printf("usage: extract <image.rgb> <width> <height> <out.bin> [password]\n");
        return 2;
    }
    uint32_t w = (uint32_t)atoi(argv[2]);
    uint32_t h = (uint32_t)atoi(argv[3]);
    if (w == 0 || h == 0) {
        printf("invalid dimensions\n");
        return 2;
    }
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        printf("cannot open input\n");
        return 2;
    }
    size_t need = (size_t)w * h * 3;
    uint8_t* rgb = (uint8_t*)malloc(need);
    size_t got = rgb ? fread(rgb, 1, need, f) : 0;
    fclose(f);
    if (!rgb || got != need) {
        printf("short read\n");
        free(rgb);
        return 2;
    }
    stego_image_t img;
    img.w = w;
    img.h = h;
    img.rgb = rgb;
    uint8_t* out = NULL;
    size_t outLen = 0;
    int rc = stego_decode(&img, argc > 5 ? argv[5] : NULL, &out, &outLen);
    int ok = (rc == STEGO_C_OK);
    if (ok) {
        FILE* o = fopen(argv[4], "wb");
        if (o) {
            ok = (fwrite(out, 1, outLen, o) == outLen);
            fclose(o);
        } else {
            ok = 0;
        }
        stego_free(out);
    }
    free(rgb);
    printf(ok ? "decoded %zu bytes\n" : "decode failed (code %d)\n", outLen, rc);
    return ok ? 0 : 1;
}
