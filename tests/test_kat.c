/*
 * Aşama 8: bilinen cevap testleri (KAT).
 *
 * Bu değerler 2026-10-12'de bu uygulamanın kendisinden üretildi (GCC ve Clang aynı
 * sonucu verdi). Bağımsız bir referans uygulama olmadığı için kodun "doğru"
 * olduğunu kanıtlamazlar; amaçları, sonraki değişikliklerin (ör. hız
 * optimizasyonları) şifrenin çıktısını fark edilmeden değiştirmesini yakalamaktır.
 *
 * Desenler: 0 = sıfır anahtar / sıfır blok
 *           1 = anahtar[i] = i, blok[i] = 0x80 + i
 *           2 = anahtar 0xFF..., blok 0x80...
 */
#include <string.h>

#include "bicbic416.h"
#include "test_util.h"

static void make_pattern(int pat, uint8_t key[BB416_KEY_BYTES], uint8_t pt[BB416_BLOCK_BYTES])
{
    for (int i = 0; i < 52; i++) {
        key[i] = pat == 0 ? 0 : pat == 1 ? (uint8_t)i : 0xFF;
        pt[i]  = pat == 0 ? 0 : pat == 1 ? (uint8_t)(0x80 + i) : 0x80;
    }
}

static int hex_eq(const uint8_t *p, size_t n, const char *hex)
{
    if (strlen(hex) != 2 * n)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || v != p[i])
            return 0;
    }
    return 1;
}

static const struct { int pat, rounds; const char *ct; } block_kat[] = {
    { 0,  1, "b1ab10fabd2565721ead92790ffbd0b9ec81d059de95f3600293c16001bb1ea800ddc6b337d33c104e44fcccf59f9feddb1a9d5d" },
    { 0,  2, "928e52e0f65705d1c7c31a6e46a16c18c7eec2055915ad47cf7a514590152c318aa542e9dcd136736a4ef9df90fe6081d765458b" },
    { 0,  8, "235cac14119e1f64f147642ffb761563d6bb811ae2fdacb700a679600d01737782fe90e91f24dfb56279b7e4f56915f944c183a4" },
    { 0, 16, "09ef2ca3c1ec50f70328542984b6c60518b612718593ba4563a694d4e4450532f2e2ca640fc3545c3d356b0e6ed20c27da7b9704" },
    { 0, 32, "f6ece3e6604b25e5c8749af19795dcff5e9d32b7167fe6a0f50d7c7861c842fda16bf2a7f85c4d66bd7d55b7b3be1e852942988d" },
    { 1,  1, "50b4fed1840a1652fe875b8309825bd63e3997d3e7c192920d0e1b9c089e1e774bed8bf9208d7919536d24d2405ebe5befe0473c" },
    { 1,  2, "a9e3994aaed5beec3862689f3a3dc4509487f63c7a6f8e598b3a0e6f04c73119891bcecec21d2b73aef476a7d403c029527f0076" },
    { 1,  8, "ba530b660fcc2ef62f98ddf61c8fc3b4167fb79a1c2f10c093832ac876d07f43537fb8445856dc66443395ded9091092132fe639" },
    { 1, 16, "89a7d44980ed105404d2cadd947388f741f07ca474263b8ef55dd1cc43e3279fc310d50fc7142a145a774c80b6a20f92d723c475" },
    { 1, 32, "f146326de39fe84605967d8746ea52bc564ec1f85bb4f6e68137579593de72743dab66b5d2e4825308103420e2ed0a4bce106b8b" },
    { 2,  1, "736d9e7b08c50f9263aeefcd6a39c05c2753b596fe99e98ebae75df4a45748592378042d91b979de59f86d07896f74dcc60aea0f" },
    { 2,  2, "2b40c3c0ce04d8bb7c06741baddea4c553729617dce66313be54793296afb1ea7b9aa3b7ff18fb95f68b3c63035fc3fff1866394" },
    { 2,  8, "8ab6b7c994ab744fac45e9ffbe17bc975432882131efd0311c0f75727f9c3eaf90c0357ce9e8e8f4b0f76ffdfd623e15731704a6" },
    { 2, 16, "cbe333e530f07bac339faec04e159b141aaa37634dc599de2d3721d12ba1c7f4e0e95e959265c4fd20537c3d9cf3e44a80173a1d" },
    { 2, 32, "e07325ded72bd2be1117980b018131466bbde348a9aa1e4ff39f11b3f33c232d5d5ae55289d655eff00b4ea24c5aa6c47a703c79" },
};

static void test_blocks(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], pt[BB416_BLOCK_BYTES], ct[BB416_BLOCK_BYTES], back[BB416_BLOCK_BYTES];

    for (size_t i = 0; i < sizeof block_kat / sizeof block_kat[0]; i++) {
        make_pattern(block_kat[i].pat, key, pt);
        CHECK(bb416_init(&ctx, key, block_kat[i].rounds) == BB416_OK);
        bb416_encrypt_block(&ctx, pt, ct);
        CHECK(hex_eq(ct, sizeof ct, block_kat[i].ct));
        bb416_decrypt_block(&ctx, ct, back);
        CHECK(memcmp(back, pt, sizeof pt) == 0);
    }
}

/* Sıfır anahtar, R = 16: sıfır bloğu kendi çıktısıyla 10.000 kez şifrele. */
static void test_chain(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES] = { 0 }, b[BB416_BLOCK_BYTES] = { 0 };

    CHECK(bb416_init(&ctx, key, 16) == BB416_OK);
    for (int i = 0; i < 10000; i++)
        bb416_encrypt_block(&ctx, b, b);
    CHECK(hex_eq(b, sizeof b,
        "ada3b2d9b9fa6004c5b268e6aa0a5afae5fc0ad91b85e47ad8befd6dc8e80b1f"
        "adc9fa7043488d978a4785612d5badd6ae7ee430"));
    for (int i = 0; i < 10000; i++)
        bb416_decrypt_block(&ctx, b, b);
    for (int i = 0; i < BB416_BLOCK_BYTES; i++)
        CHECK(b[i] == 0);
}

/* CTR: anahtar[i] = i, nonce[i] = 0xA0 + i, sayaç 1, mesaj[i] = i (100 bayt), R = 16. */
static void test_ctr(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], nonce[BB416_NONCE_BYTES], msg[100], out[100];

    for (int i = 0; i < BB416_KEY_BYTES; i++)   key[i] = (uint8_t)i;
    for (int i = 0; i < BB416_NONCE_BYTES; i++) nonce[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 100; i++)              msg[i] = (uint8_t)i;

    CHECK(bb416_init(&ctx, key, 16) == BB416_OK);
    CHECK(bb416_ctr_xor(&ctx, nonce, 1, msg, out, sizeof msg) == BB416_OK);
    CHECK(hex_eq(out, sizeof out,
        "104b9b965a3dcaf760293e1bb95d938815fdc8cdd63845a1f56a0098688025db"
        "b3e51f1abf952fba9c19f93abfc1ec5290cc4a4de863b6291eba1a4438187f6c"
        "64c93e5f24a62448a10e4ec97f838f344b3ee5fd309dc0b8806621a169348649"
        "19094e0c"));
}

int main(int argc, char **argv)
{
    tu_init("test_kat", argc, argv);
    test_blocks();
    test_chain();
    test_ctr();
    return tu_finish("test_kat");
}
