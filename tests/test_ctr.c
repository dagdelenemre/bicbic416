/*
 * Aşama 6: CTR modu (SPEC.md §7.3).
 *  - gidiş-dönüş: 0, 1, 51, 52, 53, 1000 bayt ve rastgele uzunluklar
 *  - çıktının bb416_encrypt_block ile elle kurulan anahtar akışıyla aynı olması
 *  - sayaç bloğunun bayt düzeni (nonce || sayaç LE)
 *  - yerinde çalışma, parça parça şifreleme = tek seferlik
 *  - sayaç taşma sınırı, parametre hataları
 */
#include <string.h>

#include "bicbic416.h"
#include "test_util.h"

#define MAXLEN 2048

static bb416_ctx ctx;
static uint8_t nonce[BB416_NONCE_BYTES];

/* Referans: anahtar akışını blok şifreyle elle kur. */
static void ref_ctr(uint64_t counter, const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t blk[BB416_BLOCK_BYTES], ks[BB416_BLOCK_BYTES];
    for (size_t off = 0; off < len; off += BB416_BLOCK_BYTES, counter++) {
        memcpy(blk, nonce, BB416_NONCE_BYTES);
        for (int b = 0; b < 8; b++)
            blk[BB416_NONCE_BYTES + b] = (uint8_t)(counter >> (8 * b));
        bb416_encrypt_block(&ctx, blk, ks);
        for (size_t i = 0; i < BB416_BLOCK_BYTES && off + i < len; i++)
            out[off + i] = in[off + i] ^ ks[i];
    }
}

static void check_len(size_t len, uint64_t counter)
{
    static uint8_t m[MAXLEN], c[MAXLEN], r[MAXLEN], d[MAXLEN], io[MAXLEN];
    tu_randbytes(m, len);

    CHECK(bb416_ctr_xor(&ctx, nonce, counter, m, c, len) == BB416_OK);
    ref_ctr(counter, m, r, len);
    CHECK(memcmp(c, r, len) == 0);

    CHECK(bb416_ctr_xor(&ctx, nonce, counter, c, d, len) == BB416_OK);
    CHECK(memcmp(d, m, len) == 0);
    if (len >= 16)
        CHECK(memcmp(c, m, len) != 0);

    memcpy(io, m, len);
    CHECK(bb416_ctr_xor(&ctx, nonce, counter, io, io, len) == BB416_OK);
    CHECK(memcmp(io, c, len) == 0);
    CHECK(bb416_ctr_xor(&ctx, nonce, counter, io, io, len) == BB416_OK);
    CHECK(memcmp(io, m, len) == 0);
}

static void test_lengths(void)
{
    static const size_t lens[] = { 0, 1, 51, 52, 53, 103, 104, 105, 1000 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        check_len(lens[i], 0);
        check_len(lens[i], tu_rand64());
    }
    for (int k = 0; k < 2000; k++)
        check_len((size_t)(tu_rand32() % (MAXLEN + 1u)), tu_rand64() >> 1);
}

/* Sıfır mesaj → çıktı doğrudan anahtar akışı = E(nonce || sayaç LE). */
static void test_counter_block_layout(void)
{
    uint8_t zero[BB416_BLOCK_BYTES] = { 0 }, ks[BB416_BLOCK_BYTES], blk[BB416_BLOCK_BYTES], e[BB416_BLOCK_BYTES];
    const uint64_t counter = 0x0102030405060708ULL;

    CHECK(bb416_ctr_xor(&ctx, nonce, counter, zero, ks, sizeof zero) == BB416_OK);
    memcpy(blk, nonce, BB416_NONCE_BYTES);
    const uint8_t le[8] = { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
    memcpy(blk + BB416_NONCE_BYTES, le, 8);
    bb416_encrypt_block(&ctx, blk, e);
    CHECK(memcmp(ks, e, sizeof e) == 0);

    /* Farklı nonce → farklı anahtar akışı. */
    uint8_t n2[BB416_NONCE_BYTES], ks2[BB416_BLOCK_BYTES];
    memcpy(n2, nonce, sizeof n2);
    n2[0] ^= 1;
    CHECK(bb416_ctr_xor(&ctx, n2, counter, zero, ks2, sizeof zero) == BB416_OK);
    CHECK(memcmp(ks, ks2, sizeof ks) != 0);
}

/* 52'nin katı parçalar + sayacı blok sayısı kadar ilerletmek = tek seferlik. */
static void test_piecewise(void)
{
    static uint8_t m[MAXLEN], whole[MAXLEN], parts[MAXLEN];

    for (int k = 0; k < 500; k++) {
        size_t len = (size_t)(tu_rand32() % (MAXLEN + 1u));
        uint64_t counter = tu_rand64() >> 1;
        tu_randbytes(m, len);
        CHECK(bb416_ctr_xor(&ctx, nonce, counter, m, whole, len) == BB416_OK);

        size_t off = 0;
        uint64_t ctr = counter;
        while (off < len) {
            size_t blocks = 1 + tu_rand32() % 8u;
            size_t take = blocks * BB416_BLOCK_BYTES;
            if (take > len - off) take = len - off; /* son parça herhangi uzunlukta */
            CHECK(bb416_ctr_xor(&ctx, nonce, ctr, m + off, parts + off, take) == BB416_OK);
            off += take;
            ctr += blocks;
        }
        CHECK(memcmp(whole, parts, len) == 0);
    }
}

static void test_counter_overflow(void)
{
    static uint8_t m[256], out[256], sentinel[256];
    tu_randbytes(m, sizeof m);
    memset(sentinel, 0xAA, sizeof sentinel);

    static const struct { uint64_t counter; size_t len; int expect; } cases[] = {
        { UINT64_MAX,      0,   BB416_OK },
        { UINT64_MAX,      1,   BB416_OK },
        { UINT64_MAX,      52,  BB416_OK },
        { UINT64_MAX,      53,  BB416_ERR_COUNTER },
        { UINT64_MAX,      256, BB416_ERR_COUNTER },
        { UINT64_MAX - 1,  104, BB416_OK },
        { UINT64_MAX - 1,  105, BB416_ERR_COUNTER },
        { UINT64_MAX - 4,  256, BB416_OK },          /* 5 blok: son sayaç UINT64_MAX */
        { UINT64_MAX - 3,  256, BB416_ERR_COUNTER },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        memcpy(out, sentinel, sizeof out);
        int rc = bb416_ctr_xor(&ctx, nonce, cases[i].counter, m, out, cases[i].len);
        CHECK(rc == cases[i].expect);
        if (rc != BB416_OK)
            CHECK(memcmp(out, sentinel, sizeof out) == 0); /* hiçbir bayt yazılmadı */
    }

    /* Sınırdaki son blok gerçekten sayaç = UINT64_MAX ile şifrelenmeli. */
    static uint8_t r[256];
    CHECK(bb416_ctr_xor(&ctx, nonce, UINT64_MAX - 4, m, out, 256) == BB416_OK);
    ref_ctr(UINT64_MAX - 4, m, r, 256);
    CHECK(memcmp(out, r, 256) == 0);
}

static void test_params(void)
{
    uint8_t m[8] = { 0 }, out[8];
    CHECK(bb416_ctr_xor(NULL, nonce, 0, m, out, 8) == BB416_ERR_PARAM);
    CHECK(bb416_ctr_xor(&ctx, NULL, 0, m, out, 8) == BB416_ERR_PARAM);
    CHECK(bb416_ctr_xor(&ctx, nonce, 0, NULL, out, 8) == BB416_ERR_PARAM);
    CHECK(bb416_ctr_xor(&ctx, nonce, 0, m, NULL, 8) == BB416_ERR_PARAM);
    CHECK(bb416_ctr_xor(&ctx, nonce, 0, NULL, NULL, 0) == BB416_OK);
    CHECK(bb416_ctr_xor(NULL, nonce, 0, NULL, NULL, 0) == BB416_ERR_PARAM);
    CHECK(bb416_ctr_xor(&ctx, NULL, 0, NULL, NULL, 0) == BB416_ERR_PARAM);
}

int main(int argc, char **argv)
{
    uint8_t key[BB416_KEY_BYTES];
    tu_init("test_ctr", argc, argv);

    for (int R = 1; R <= BB416_MAX_ROUNDS; R += (R < 4 ? 1 : 6)) {
        tu_randbytes(key, sizeof key);
        tu_randbytes(nonce, sizeof nonce);
        CHECK(bb416_init(&ctx, key, R) == BB416_OK);
        test_lengths();
        test_counter_block_layout();
        test_piecewise();
        test_counter_overflow();
        test_params();
    }
    return tu_finish("test_ctr");
}
