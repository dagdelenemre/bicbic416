/*
 * Aşama 4: blok şifreleme/çözme.
 *  - 1..32 arası her tur sayısı için 100.000 rastgele anahtar+blok: çöz(şifrele(P)) == P
 *  - yerinde çalışma (in == out)
 *  - şifreli metin düz metinden ve farklı tur sayılarında birbirinden farklı
 *  - farklı anahtar yanlış düz metin verir
 */
#include <string.h>

#include "bb416_internal.h"
#include "bicbic416.h"
#include "test_util.h"

#define TRIALS_PER_R 100000

static void test_roundtrip_all_rounds(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], c[BB416_BLOCK_BYTES],
            d[BB416_BLOCK_BYTES], io[BB416_BLOCK_BYTES];
    unsigned long unchanged = 0;

    for (int R = 1; R <= BB416_MAX_ROUNDS; R++) {
        for (int k = 0; k < TRIALS_PER_R; k++) {
            tu_randbytes(key, sizeof key);
            tu_randbytes(p, sizeof p);
            CHECK(bb416_init(&ctx, key, R) == BB416_OK);

            bb416_encrypt_block(&ctx, p, c);
            bb416_decrypt_block(&ctx, c, d);
            CHECK(memcmp(d, p, sizeof p) == 0);
            unchanged += memcmp(c, p, sizeof p) == 0;

            /* Yerinde: aynı sonuçlar. Her 16 denemede bir yeterli. */
            if ((k & 15) == 0) {
                memcpy(io, p, sizeof io);
                bb416_encrypt_block(&ctx, io, io);
                CHECK(memcmp(io, c, sizeof c) == 0);
                bb416_decrypt_block(&ctx, io, io);
                CHECK(memcmp(io, p, sizeof p) == 0);
            }
        }
    }
    CHECK(unchanged == 0);
    printf("  %d tur sayısı × %d anahtar+blok gidiş-dönüş tamam\n",
           BB416_MAX_ROUNDS, TRIALS_PER_R);
}

/* Sıfır anahtar / sıfır blok gibi yapılı girdiler de çalışmalı. */
static void test_structured_inputs(void)
{
    static bb416_ctx ctx;
    static const uint8_t fills[] = { 0x00, 0xFF, 0x80, 0x01 };
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], c[BB416_BLOCK_BYTES], d[BB416_BLOCK_BYTES];

    for (size_t a = 0; a < sizeof fills; a++) {
        for (size_t b = 0; b < sizeof fills; b++) {
            memset(key, fills[a], sizeof key);
            memset(p, fills[b], sizeof p);
            for (int R = 1; R <= BB416_MAX_ROUNDS; R++) {
                CHECK(bb416_init(&ctx, key, R) == BB416_OK);
                bb416_encrypt_block(&ctx, p, c);
                bb416_decrypt_block(&ctx, c, d);
                CHECK(memcmp(d, p, sizeof p) == 0);
                CHECK(memcmp(c, p, sizeof p) != 0);
            }
        }
    }
}

/* Aynı anahtar ve blok, farklı tur sayısı → farklı şifreli metin. */
static void test_rounds_differ(void)
{
    static bb416_ctx ctx;
    static uint8_t c[BB416_MAX_ROUNDS + 1][BB416_BLOCK_BYTES];
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES];

    tu_randbytes(key, sizeof key);
    tu_randbytes(p, sizeof p);
    for (int R = 1; R <= BB416_MAX_ROUNDS; R++) {
        CHECK(bb416_init(&ctx, key, R) == BB416_OK);
        bb416_encrypt_block(&ctx, p, c[R]);
        for (int Q = 1; Q < R; Q++)
            CHECK(memcmp(c[R], c[Q], BB416_BLOCK_BYTES) != 0);
    }
}

/* Yanlış anahtarla çözme düz metni vermemeli (tek bitlik anahtar farkıyla bile). */
static void test_wrong_key(void)
{
    static bb416_ctx a, b;
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], c[BB416_BLOCK_BYTES], d[BB416_BLOCK_BYTES];

    for (int k = 0; k < 10000; k++) {
        tu_randbytes(key, sizeof key);
        tu_randbytes(p, sizeof p);
        CHECK(bb416_init(&a, key, 16) == BB416_OK);
        unsigned bit = tu_rand32() % 416u;
        key[bit >> 3] ^= (uint8_t)(1u << (bit & 7u));
        CHECK(bb416_init(&b, key, 16) == BB416_OK);

        bb416_encrypt_block(&a, p, c);
        bb416_decrypt_block(&b, c, d);
        CHECK(memcmp(d, p, sizeof p) != 0);
    }
}

/* Hızlı (açılmış) yol, spesifikasyonun adım adım okunur hâliyle birebir aynı olmalı. */
static void ref_encrypt(const bb416_ctx *ctx, const uint8_t in[52], uint8_t out[52])
{
    uint32_t S[13];
    for (int i = 0; i < 13; i++) S[i] = load32_le(in + 4 * i);
    for (int r = 0; r < ctx->rounds; r++) {
        bb416_step1(S, ctx->rk[r]);
        bb416_step2(S, ctx->mk[r]);
        bb416_step3(S);
        bb416_step4(S);
        bb416_step5(S);
        bb416_step6(S);
    }
    bb416_step1(S, ctx->rk[ctx->rounds]);
    for (int i = 0; i < 13; i++) store32_le(out + 4 * i, S[i]);
}

static void ref_decrypt(const bb416_ctx *ctx, const uint8_t in[52], uint8_t out[52])
{
    uint32_t S[13];
    for (int i = 0; i < 13; i++) S[i] = load32_le(in + 4 * i);
    bb416_step1_inv(S, ctx->rk[ctx->rounds]);
    for (int r = ctx->rounds - 1; r >= 0; r--) {
        bb416_step6_inv(S);
        bb416_step5_inv(S);
        bb416_step4_inv(S);
        bb416_step3_inv(S);
        bb416_step2_inv(S, ctx->mkinv[r]);
        bb416_step1_inv(S, ctx->rk[r]);
    }
    for (int i = 0; i < 13; i++) store32_le(out + 4 * i, S[i]);
}

static void test_fast_path_matches_spec(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], a[BB416_BLOCK_BYTES], b[BB416_BLOCK_BYTES];

    for (int R = 1; R <= BB416_MAX_ROUNDS; R++) {
        for (int k = 0; k < 2000; k++) {
            tu_randbytes(key, sizeof key);
            tu_randbytes(p, sizeof p);
            CHECK(bb416_init(&ctx, key, R) == BB416_OK);
            bb416_encrypt_block(&ctx, p, a);
            ref_encrypt(&ctx, p, b);
            CHECK(memcmp(a, b, sizeof a) == 0);
            bb416_decrypt_block(&ctx, p, a);
            ref_decrypt(&ctx, p, b);
            CHECK(memcmp(a, b, sizeof a) == 0);
        }
    }
}

int main(int argc, char **argv)
{
    tu_init("test_roundtrip", argc, argv);
    test_fast_path_matches_spec();
    test_roundtrip_all_rounds();
    test_structured_inputs();
    test_rounds_differ();
    test_wrong_key();
    return tu_finish("test_roundtrip");
}
