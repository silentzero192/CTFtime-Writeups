// Decrypt the "D" challenge: Dickson-polynomial S-box cipher over GF(2^128).
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

typedef unsigned __int128 u128;

static inline u128 clmul64(uint64_t a, uint64_t b) {
    __m128i r = _mm_clmulepi64_si128(_mm_cvtsi64_si128((long long)a),
                                     _mm_cvtsi64_si128((long long)b), 0x00);
    return ((u128)(uint64_t)_mm_extract_epi64(r, 1) << 64) | (uint64_t)_mm_cvtsi128_si64(r);
}

// GF(2^128) with modulus x^128 + x^7 + x^2 + x + 1  (low part 0x87)
static inline u128 gfmul(u128 a, u128 b) {
    uint64_t a0 = (uint64_t)a, a1 = (uint64_t)(a >> 64);
    uint64_t b0 = (uint64_t)b, b1 = (uint64_t)(b >> 64);
    u128 z0 = clmul64(a0, b0);
    u128 z2 = clmul64(a1, b1);
    u128 z1 = clmul64(a0 ^ a1, b0 ^ b1) ^ z0 ^ z2;
    u128 lo = z0 ^ (z1 << 64);
    u128 hi = z2 ^ (z1 >> 64);
    uint64_t h0 = (uint64_t)hi, h1 = (uint64_t)(hi >> 64);
    u128 p0 = clmul64(h0, 0x87);
    u128 p1 = clmul64(h1, 0x87);
    lo ^= p0 ^ (p1 << 64);
    lo ^= clmul64((uint64_t)(p1 >> 64), 0x87);
    return lo;
}

static u128 gfpow(u128 a, u128 e) {
    u128 r = 1;
    while (e) { if (e & 1) r = gfmul(r, a); a = gfmul(a, a); e >>= 1; }
    return r;
}

#define AA ((u128)19)   // F.from_integer(19) = x^4 + x + 1

// Dickson D_13(z, a) evaluated at z
static inline u128 dickson13(u128 z) {
    u128 d0 = 0, d1 = z;
    for (int k = 2; k <= 13; k++) {
        u128 d = gfmul(z, d1) ^ gfmul(AA, d0);
        d0 = d1; d1 = d;
    }
    return d1;
}

// m = 13^{-1} mod (2^256 - 1), 256-bit, little-endian words
static const uint64_t MEXP[4] = {
    0x7627627627627627ULL, 0x2762762762762762ULL,
    0x6276276276276276ULL, 0x7627627627627627ULL
};

static u128 B13;  // a^13

// Inverse of D_13(.,a): D_m(c, a^13) computed in F[T]/(T^2 + cT + B13);
// if T^m = A + B*T then D_m(c,B13) = B*c.
static u128 dickson13_inv(u128 c) {
    if (c == 0) return 0;
    u128 r0 = 0, r1 = 1;        // r = T
    int started = 0;
    for (int i = 255; i >= 0; i--) {
        int bit = (MEXP[i >> 6] >> (i & 63)) & 1;
        if (!started) { if (!bit) continue; started = 1; continue; }
        // square: (r0 + r1 T)^2 = (r0^2 + r1^2*B13) + (r1^2 * c) T
        u128 s0 = gfmul(r0, r0), s1 = gfmul(r1, r1);
        r0 = s0 ^ gfmul(s1, B13);
        r1 = gfmul(s1, c);
        if (bit) { // multiply by T: (r0 + r1 T)*T = r1*B13 + (r0 + r1*c) T
            u128 t0 = gfmul(r1, B13);
            u128 t1 = r0 ^ gfmul(r1, c);
            r0 = t0; r1 = t1;
        }
    }
    return gfmul(r1, c);
}

static inline u128 be_load(const unsigned char *p) {
    u128 v = 0;
    for (int i = 0; i < 16; i++) v = (v << 8) | p[i];
    return v;
}
static inline void be_store(u128 v, unsigned char *p) {
    for (int i = 15; i >= 0; i--) { p[i] = (unsigned char)v; v >>= 8; }
}

static int PBOX[16];  // dst -> src

int main(int argc, char **argv) {
    B13 = gfpow(AA, 13);

    // self-test: D_13 inverse
    for (u128 t = 1; t < 50; t++) {
        u128 z = gfmul(t, (u128)0x123456789abcdefULL) ^ t;
        if (dickson13_inv(dickson13(z)) != z) { fprintf(stderr, "SELFTEST FAIL\n"); return 1; }
    }
    fprintf(stderr, "selftest ok\n");

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            PBOX[j * 4 + i] = i + 4 * ((j + i) % 4);

    // keystream
    FILE *fk = fopen(argv[1], "rb");
    unsigned char key[128];
    if (fread(key, 1, 128, fk) != 128) { fprintf(stderr, "key read\n"); return 1; }
    fclose(fk);
    u128 ks[128];
    for (int i = 0; i < 8; i++) {
        u128 l = be_load(key + i);
        for (int j = 0; j < 16; j++) { ks[i * 16 + j] = l; l = dickson13(l); }
    }

    // ciphertext
    FILE *fc = fopen(argv[2], "rb");
    fseek(fc, 0, SEEK_END); long n = ftell(fc); fseek(fc, 0, SEEK_SET);
    unsigned char *ct = malloc(n);
    if (fread(ct, 1, n, fc) != (size_t)n) return 1; fclose(fc);
    unsigned char *pt = malloc(n);

    unsigned char prev[16]; memset(prev, 0, 16);
    for (long blk = 0; blk < n / 16; blk++) {
        unsigned char *cur = ct + blk * 16;
        u128 b = be_load(cur);
        for (int r = 15; r >= 0; r--) {
            unsigned char cbytes[16], ebytes[16];
            be_store(b, cbytes);
            for (int d = 0; d < 16; d++) ebytes[PBOX[d]] = cbytes[d];
            u128 e = be_load(ebytes);
            u128 z = dickson13_inv(e);
            b = z ^ ks[(blk * 16 + r) % 128];
        }
        unsigned char dec[16]; be_store(b, dec);
        for (int k = 0; k < 16; k++) pt[blk * 16 + k] = dec[k] ^ prev[k];
        memcpy(prev, cur, 16);
    }
    FILE *fo = fopen(argv[3], "wb");
    fwrite(pt, 1, n, fo); fclose(fo);
    fprintf(stderr, "wrote %ld bytes\n", n);
    return 0;
}
