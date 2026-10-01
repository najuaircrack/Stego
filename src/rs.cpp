// rs.cpp - Reed-Solomon RS(255,223) over GF(2^8), primitive poly 0x11D
// (FORMAT.md section 2.6). Systematic data||parity blocks for the ROBUST
// framing. Mirrors python/stegolib.py rs_* bit-for-bit (same generator
// roots, same data||parity layout, same division direction).
#include <stdint.h>
#include <string.h>
#include <vector>

namespace stego {
namespace rs {

namespace {
struct Tables {
    uint8_t exp_[512];
    uint8_t log_[256];
    uint8_t gen_[33];
    Tables() {        unsigned x = 1;
        for (int i = 0; i < 255; i++) {
            exp_[i] = (uint8_t)x;
            log_[x] = (uint8_t)i;
            x <<= 1;
            if (x & 0x100) x ^= 0x11D;
        }
        for (int i = 255; i < 512; i++) exp_[i] = exp_[i - 255];
        // g(x) = PRODUCT_{i=0}^{31} (x + alpha^i), low-to-high coeffs.
        uint8_t g[64] = {1};
        size_t deg = 0;
        for (int i = 0; i < 32; i++) {
            uint8_t ng[64] = {0};
            for (size_t a = 0; a <= deg; a++) {
                if (!g[a]) continue;
                ng[a] ^= Mul(g[a], exp_[i]);
                ng[a + 1] ^= g[a];
            }
            deg++;
            memcpy(g, ng, sizeof(g));
        }
        memcpy(gen_, g, 33);
    }
    static uint8_t Mul(uint8_t a, uint8_t b, const uint8_t* exp_,
                       const uint8_t* log_) {
        if (!a || !b) return 0;
        return exp_[log_[a] + log_[b]];
    }
    uint8_t Mul(uint8_t a, uint8_t b) const { return Mul(a, b, exp_, log_); }
    uint8_t Div(uint8_t a, uint8_t b) const {
        if (!a) return 0;
        int d = (int)log_[a] - (int)log_[b];
        if (d < 0) d += 255;
        return exp_[d];
    }
};
const Tables& T() {
    static Tables t;
    return t;
}
}  // namespace

// Systematic encode: 223B data -> 255B codeword (data || parity).
// Long division eliminates from the high-degree end, so it consumes
// the generator high-to-low (gen[32] = 1 zeroes each leading term).
bool EncodeBlock(const uint8_t data[223], uint8_t cw[255]) {
    const Tables& t = T();
    uint8_t w[255];
    memcpy(w, data, 223);
    memset(w + 223, 0, 32);
    for (int i = 0; i < 223; i++) {
        uint8_t coef = w[i];
        if (!coef) continue;
        for (int j = 0; j < 33; j++) w[i + j] ^= t.Mul(t.gen_[32 - j], coef);
    }
    for (int i = 0; i < 223; i++)
        if (w[i]) return false;  // not fully reduced (cannot happen)
    memcpy(cw, data, 223);
    memcpy(cw + 223, w + 223, 32);
    return true;
}

static void Syndromes(const uint8_t* cw, uint8_t syn[32]) {
    const Tables& t = T();
    for (int i = 0; i < 32; i++) {
        uint8_t a = t.exp_[i], s = 0, p = 1;
        // Highest-first: R(x) = c_0 x^254 + ... (c[254-k] carries x^k).
        for (int k = 0; k < 255; k++) {
            s ^= t.Mul(cw[254 - k], p);
            p = t.Mul(p, a);
        }
        syn[i] = s;
    }
}

// Decode 255B codeword -> 223B data. False on uncorrectable input
// (fail closed; miscorrections rechecked and rejected).
bool DecodeBlock(const uint8_t cw[255], uint8_t data[223]) {
    const Tables& t = T();
    uint8_t syn[32];
    Syndromes(cw, syn);
    bool clean = true;
    for (int i = 0; i < 32; i++)
        if (syn[i]) {
            clean = false;
            break;
        }
    if (clean) {
        memcpy(data, cw, 223);
        return true;
    }
    // Berlekamp-Massey: error-locator Lambda (degree <= 16).
    uint8_t lam[33] = {1}, prev[33] = {1};
    size_t lamLen = 1, prevLen = 1;
    size_t L = 0, m = 1;
    uint8_t b = 1;
    for (int n = 0; n < 32; n++) {
        uint8_t d = syn[n];
        for (size_t i = 1; i <= L && i < lamLen; i++)
            d ^= t.Mul(lam[i], syn[n - i]);
        if (d == 0) {
            m++;
            continue;
        }
        uint8_t nxt[64] = {0};
        size_t nxtLen = lamLen + m;
        if (nxtLen < prevLen + m) nxtLen = prevLen + m;
        for (size_t i = 0; i < lamLen && i < sizeof(nxt); i++) nxt[i] = lam[i];
        uint8_t coef = t.Div(d, b);
        for (size_t i = 0; i < prevLen; i++) nxt[i + m] ^= t.Mul(coef, prev[i]);
        if (2 * L <= (size_t)n) {
            memcpy(prev, lam, lamLen);
            prevLen = lamLen;
            L = (size_t)n + 1 - L;
            b = d;
            m = 1;
        } else {
            m++;
        }
        if (L > 16) return false;  // beyond t: uncorrectable, fail fast
        memcpy(lam, nxt, nxtLen < sizeof(lam) ? nxtLen : sizeof(lam));
        lamLen = nxtLen < 33 ? nxtLen : 33;
    }
    if (L == 0 || L > 16) return false;
    // Chien: test x = alpha^{-t}; hit means error at codeword 254-t.
    int errs[16];
    size_t nErrs = 0;
    for (int tt = 0; tt < 255; tt++) {
        uint8_t x = t.exp_[(255 - tt) % 255];
        uint8_t y = 0, p = 1;
        for (size_t i = 0; i <= L; i++) {
            y ^= t.Mul(lam[i], p);
            p = t.Mul(p, x);
        }
        if (y == 0) {
            if (nErrs >= 16) return false;
            errs[nErrs++] = 254 - tt;
        }
    }
    if (nErrs != L) return false;
    // Omega = (S*Lambda) mod x^32.
    uint8_t omega[32] = {0};
    for (int i = 0; i < 32; i++) {
        uint8_t s = 0;
        for (int j = 0; j <= i && j <= (int)L; j++)
            s ^= t.Mul(lam[j], syn[i - j]);
        omega[i] = s;
    }
    uint8_t out[255];
    memcpy(out, cw, 255);
    for (size_t e = 0; e < nErrs; e++) {
        int j = errs[e];
        uint8_t x = t.exp_[(254 - j + 255) % 255];  // X_k = alpha^{254-j}
        uint8_t xi = t.Div(1, x);
        uint8_t den = 0, xp = 1;  // Lambda'(x^{-1}), odd terms
        for (size_t i = 1; i <= L; i += 2) {
            den ^= t.Mul(lam[i], xp);
            xp = t.Mul(t.Mul(xp, xi), xi);
        }
        if (den == 0) return false;
        uint8_t num = 0, p = 1;  // Omega(x^{-1})
        for (int i = 0; i < 32; i++) {
            num ^= t.Mul(omega[i], p);
            p = t.Mul(p, xi);
        }
        out[j] ^= t.Mul(num, t.Div(x, den));  // Forney, narrow-sense
    }
    uint8_t chk[32];
    Syndromes(out, chk);
    for (int i = 0; i < 32; i++)
        if (chk[i]) return false;  // miscorrection guard
    memcpy(data, out, 223);
    return true;
}

}  // namespace rs
}  // namespace stego
