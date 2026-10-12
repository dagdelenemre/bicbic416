/*
 * BicBic-Hash testleri (SPEC.md §12).
 *  - sabit test vektörleri: bağımsız Python referansıyla (ref/bicbic416_ref.py) doğrulandı
 *  - IV'nin E_0(0) olduğu
 *  - parça parça (akışlı) hesaplamanın tek seferlikle aynı olduğu
 *  - çığ etkisi: girdide 1 bit → çıktıda ~208 bit (416'nın yarısı)
 *  - 100 000 yapılı girdide çakışma olmadığı
 */
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"
#include "test_util.h"

static int hex_eq(const uint8_t *p, const char *hex)
{
    if (strlen(hex) != 2 * BB416_HASH_BYTES) return 0;
    for (int i = 0; i < BB416_HASH_BYTES; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || v != p[i]) return 0;
    }
    return 1;
}

static const struct { const char *msg; size_t len; const char *hex; } named_vec[] = {
    { "", 0,
      "3d1cae2f4726603f99386cabec329671268fc1b5e5a6500acecd"
      "1bbdbda1192a168dcc359a44ed7e5fb4e9a004b554388989b7b8" },
    { "abc", 3,
      "67a30eca090354246f2832416cf494bc1873e4a8d9ab1dd99819"
      "774f7c38d3e4b0c48d556cadbb5a27d1c12e856f879f8fe1a19f" },
    { "BicBic416", 9,
      "ac25b7e9084596b04227b2e57980e958d92907448438367435be"
      "db8503f9ac60859ab42f910f74cfa786b8fb1d836ce132dd09da" },
    { "Merhaba dünya, ğüşıöç İĞÜŞÖÇ", sizeof("Merhaba dünya, ğüşıöç İĞÜŞÖÇ") - 1,
      "9244e0712ca19905322cf00450ed5bbb6087ef1f5f1bd682ae20"
      "5d24fa01e89b330645c916bddb77b6f6519f3265563fe615e136" },
};

/* Desen: msg[i] = (7*i + 3) mod 256. Uzunluklar blok sınırlarını (52) ve dolgu
 * sınırını (52 - 9 = 43) kapsar. */
static const struct { size_t len; const char *hex; } pattern_vec[] = {
    { 1, "a77e82cb3a7c3efba1619a900101b7f92bf146bef8f34487135e"
            "c97a2f3dd5dd34924c33efa1dcd964b5167585db1ab3df4a41ac" },
    { 43, "4ad6b3737a4457465565d5485662679d54c4785a5ad845d252c5"
            "f4ff0a8e807d3e944702af1fec2adaa13fcbe1b79b23be1682ea" },
    { 44, "11103f65c70ec28ad1906c053437d6b2e9f08ff607d3f83fe52f"
            "d7f3e41f1e2450f931e679e764932c51f4e6eddf1a332aeed905" },
    { 51, "4a748fc3486ed12591c5e0a0a806e7cd4e6dda591fba83882fe6"
            "015d0b5b47d23fabb3208da7866f901dc87702aa486de746f50d" },
    { 52, "c6387b9d104c811df06caa396889cb4a3dcb687cfd6003140919"
            "937ffa4d9986a1de7196e89e317611f09c237ad5631cb7575f3d" },
    { 53, "99ce1180a2cd781c705c0af16cbee8ed2655fbec039c17c5389a"
            "996a998714a1592c6d53dacd29213ffac1cf83f8202b7ee9f57c" },
    { 95, "eaf0cadbbf9b60855a3b42b172f7cdec04add4597bac2e5c0020"
            "6414c20e02c933c42be50f3913f1caaac1e38929f1a4ca6ade06" },
    { 96, "faa2dde3e20367610bcb98aacc182b675e1b2506260c373d5bc4"
            "104f928b9fc4dfa6f46e29920ab933e5965775813cad2db0f3af" },
    { 103, "a1ab0eabb9ba3d70bdff199111b0055e212e04e10a7a3f6a80dd"
            "83833d60f8438cc963dd027274b2d555af9654d1088ab46642e6" },
    { 104, "4d3a981cef078f3db67c7e53ae6c00d6a95b8812a35c70cf0007"
            "6fe596880c7600967e75e8c573d8b0018c1756c836b4df20e657" },
    { 105, "21a8b5b50c4e441e08dc10a9604eae6e8530b3cea1556eeecc3b"
            "c75db5b0077e0053613e6a08e24f368d94124ed332adabde5632" },
    { 1000, "b015723e53e87d00e35097a40768dcc4e1b02f847001ece67a3a"
            "af1295f9b5367ea33be7bedaa67f66c0b8d0240091d93fa4b97a" },
};

static void test_kat(void)
{
    uint8_t out[BB416_HASH_BYTES], msg[1000];
    for (size_t i = 0; i < sizeof named_vec / sizeof named_vec[0]; i++) {
        bb416_hash(named_vec[i].msg, named_vec[i].len, out);
        CHECK(hex_eq(out, named_vec[i].hex));
    }
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 7 + 3);
    for (size_t i = 0; i < sizeof pattern_vec / sizeof pattern_vec[0]; i++) {
        bb416_hash(msg, pattern_vec[i].len, out);
        CHECK(hex_eq(out, pattern_vec[i].hex));
    }
}

/* IV, sıfır anahtarla sıfır bloğun şifresi olmalı (keyfi bir sabit değil). */
static void test_iv(void)
{
    static bb416_ctx ctx;
    uint8_t zero[BB416_KEY_BYTES] = { 0 }, e[BB416_BLOCK_BYTES];
    bb416_hash_ctx h;
    CHECK(bb416_init(&ctx, zero, 16) == BB416_OK);
    bb416_encrypt_block(&ctx, zero, e);
    bb416_hash_init(&h);
    CHECK(memcmp(h.h, e, sizeof e) == 0);
}

static void test_streaming(void)
{
    static uint8_t msg[5000];
    uint8_t a[BB416_HASH_BYTES], b[BB416_HASH_BYTES];
    for (int k = 0; k < 300; k++) {
        size_t len = tu_rand32() % (sizeof msg + 1);
        tu_randbytes(msg, len);
        bb416_hash(msg, len, a);
        bb416_hash_ctx c;
        bb416_hash_init(&c);
        for (size_t off = 0; off < len;) {
            size_t take = tu_rand32() % 120u;
            if (take > len - off) take = len - off;
            bb416_hash_update(&c, msg + off, take);
            off += take;
        }
        bb416_hash_final(&c, b);
        CHECK(memcmp(a, b, sizeof a) == 0);
    }
}

static int hamming(const uint8_t *a, const uint8_t *b)
{
    int d = 0;
    for (int i = 0; i < BB416_HASH_BYTES; i++)
        for (uint8_t x = a[i] ^ b[i]; x; x &= (uint8_t)(x - 1)) d++;
    return d;
}

static void test_avalanche(void)
{
    const int N = 5000;
    uint8_t msg[120], a[BB416_HASH_BYTES], b[BB416_HASH_BYTES];
    double sum = 0, sq = 0;
    int mn = 416;
    for (int k = 0; k < N; k++) {
        size_t len = 1 + tu_rand32() % sizeof msg;
        tu_randbytes(msg, len);
        bb416_hash(msg, len, a);
        unsigned bit = tu_rand32() % (unsigned)(8 * len);
        msg[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
        bb416_hash(msg, len, b);
        int d = hamming(a, b);
        sum += d; sq += (double)d * d;
        if (d < mn) mn = d;
    }
    double m = sum / N, sd = sqrt(sq / N - m * m);
    printf("  çığ etkisi: 1 bit değişince ortalama %.2f bit (ideal 208), std. sapma %.2f (ideal 10.2), min %d\n",
           m, sd, mn);
    CHECK(fabs(m - 208) < 1.0);
    CHECK(fabs(sd - 10.2) < 0.6);
}

/* 100 000 ardışık sayaç girdisi: hepsi farklı çıktı vermeli (ilk 8 baytla karşılaştır). */
static int cmp_u64(const void *x, const void *y)
{
    uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;
    return (a > b) - (a < b);
}

static void test_no_collisions(void)
{
    const int N = 100000;
    uint64_t *v = malloc((size_t)N * sizeof *v);
    uint8_t out[BB416_HASH_BYTES];
    for (int i = 0; i < N; i++) {
        uint32_t x = (uint32_t)i;
        bb416_hash(&x, sizeof x, out);
        memcpy(&v[i], out, 8);
    }
    qsort(v, (size_t)N, sizeof *v, cmp_u64);
    int dup = 0;
    for (int i = 1; i < N; i++) dup += v[i] == v[i - 1];
    CHECK(dup == 0);
    free(v);
}

int main(int argc, char **argv)
{
    tu_init("test_hash", argc, argv);
    test_kat();
    test_iv();
    test_streaming();
    test_avalanche();
    test_no_collisions();
    return tu_finish("test_hash");
}
