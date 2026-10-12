/*
 * Aşama 3: anahtar planı.
 *  - bb416_init hata kodları ve ctx'in sıfırlanması (SPEC.md §7.1)
 *  - SPEC.md §6 sözde kodunun bu dosyada bağımsız yeniden yazımıyla karşılaştırma
 *  - MK tek sayı, MKINV gerçekten ters, tur anahtarları birbirinden farklı
 *  - anahtar planının çığ etkisi
 *  - §6'da kabul edilen zayıflığın gösterimi: RK[0]'dan ana anahtar geri bulunur
 */
#include <string.h>

#include "bb416_internal.h"
#include "bicbic416.h"
#include "test_util.h"

#define REF_KS_MUL  0x2545F491u
#define REF_KS_GOLD 0x9E3779B9u

/* ---- Referans: SPEC.md §6 satır satır -------------------------------------- */

static void ref_mix(uint32_t K[13])
{
    for (int i = 0; i < 13; i++) {
        K[i] = K[i] * REF_KS_MUL;
        K[i] ^= K[i] >> 16;
        K[i] = rotl32(K[i], (13u * (unsigned)i + 3u) & 31u);
    }
    bb416_step4(K);
    bb416_step5(K);
    bb416_step6(K);
}

static void ref_mix_inv(uint32_t K[13])
{
    const uint32_t inv = mulinv32(REF_KS_MUL);
    bb416_step6_inv(K);
    bb416_step5_inv(K);
    bb416_step4_inv(K);
    for (int i = 0; i < 13; i++) {
        K[i] = rotr32(K[i], (13u * (unsigned)i + 3u) & 31u);
        K[i] ^= K[i] >> 16;
        K[i] *= inv;
    }
}

static void ref_schedule(const uint8_t key[52], int R,
                         uint32_t rk[][13], uint32_t mk[][13])
{
    uint32_t K[13];
    uint32_t n = 0;
    for (int i = 0; i < 13; i++)
        K[i] = load32_le(key + 4 * i);

#define URET(dst)                                   \
    do {                                            \
        K[0] ^= (n + 1u) * REF_KS_GOLD;             \
        ref_mix(K); ref_mix(K);                     \
        n++;                                        \
        memcpy((dst), K, sizeof K);                 \
    } while (0)

    for (int r = 0; r < R; r++) {
        URET(rk[r]);
        URET(mk[r]);
        for (int i = 0; i < 13; i++)
            mk[r][i] |= 1u;
    }
    URET(rk[R]);
#undef URET
}

/* ---- Yardımcılar ------------------------------------------------------------ */

static int all_bytes(const void *p, size_t n, uint8_t v)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        if (b[i] != v)
            return 0;
    return 1;
}

static int popcount32(uint32_t x)
{
    int c = 0;
    for (; x; x &= x - 1)
        c++;
    return c;
}

static int hamming13(const uint32_t a[13], const uint32_t b[13])
{
    int d = 0;
    for (int i = 0; i < 13; i++)
        d += popcount32(a[i] ^ b[i]);
    return d;
}

/* ---- Testler ---------------------------------------------------------------- */

static void test_init_errors(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES] = { 0 };
    static const int bad_rounds[] = { 0, -1, 33, 1000, -2147483647 - 1 };

    CHECK(bb416_init(NULL, key, 16) == BB416_ERR_PARAM);

    memset(&ctx, 0xAA, sizeof ctx);
    CHECK(bb416_init(&ctx, NULL, 16) == BB416_ERR_PARAM);
    CHECK(all_bytes(&ctx, sizeof ctx, 0));

    for (size_t i = 0; i < sizeof bad_rounds / sizeof bad_rounds[0]; i++) {
        memset(&ctx, 0xAA, sizeof ctx);
        CHECK(bb416_init(&ctx, key, bad_rounds[i]) == BB416_ERR_PARAM);
        CHECK(all_bytes(&ctx, sizeof ctx, 0));
    }

    for (int R = 1; R <= BB416_MAX_ROUNDS; R++) {
        memset(&ctx, 0xAA, sizeof ctx);
        CHECK(bb416_init(&ctx, key, R) == BB416_OK);
        CHECK(ctx.rounds == R);
        /* Kullanılmayan tur dilimleri eski çöpü taşımamalı. */
        for (int r = R + 1; r <= BB416_MAX_ROUNDS; r++)
            CHECK(all_bytes(ctx.rk[r], sizeof ctx.rk[r], 0));
        for (int r = R; r < BB416_MAX_ROUNDS; r++) {
            CHECK(all_bytes(ctx.mk[r], sizeof ctx.mk[r], 0));
            CHECK(all_bytes(ctx.mkinv[r], sizeof ctx.mkinv[r], 0));
        }
    }

    bb416_wipe(&ctx);
    CHECK(all_bytes(&ctx, sizeof ctx, 0));
    bb416_wipe(NULL); /* çökmemeli */
}

static void test_against_reference(void)
{
    static bb416_ctx ctx;
    static uint32_t rk[BB416_MAX_ROUNDS + 1][13], mk[BB416_MAX_ROUNDS][13];
    uint8_t key[BB416_KEY_BYTES];

    for (int k = 0; k < 2000; k++) {
        int R = 1 + (int)(tu_rand32() & 31u);
        if (k == 0) memset(key, 0, sizeof key);
        else tu_randbytes(key, sizeof key);

        CHECK(bb416_init(&ctx, key, R) == BB416_OK);
        ref_schedule(key, R, rk, mk);
        for (int r = 0; r <= R; r++)
            CHECK(memcmp(ctx.rk[r], rk[r], sizeof rk[r]) == 0);
        for (int r = 0; r < R; r++) {
            CHECK(memcmp(ctx.mk[r], mk[r], sizeof mk[r]) == 0);
            for (int i = 0; i < 13; i++) {
                CHECK(ctx.mk[r][i] & 1u);
                CHECK(ctx.mk[r][i] * ctx.mkinv[r][i] == 1u);
            }
        }
    }
}

/* Aynı anahtar + aynı R → aynı ctx; farklı R'ler ortak öneki paylaşır
 * (üret() sırası R'den bağımsızdır), bu SPEC.md §6'nın doğal sonucudur. */
static void test_determinism_and_prefix(void)
{
    static bb416_ctx a, b, c;
    uint8_t key[BB416_KEY_BYTES];
    tu_randbytes(key, sizeof key);

    CHECK(bb416_init(&a, key, 16) == BB416_OK);
    CHECK(bb416_init(&b, key, 16) == BB416_OK);
    CHECK(memcmp(&a, &b, sizeof a) == 0);

    CHECK(bb416_init(&c, key, 32) == BB416_OK);
    CHECK(memcmp(a.rk, c.rk, 17 * sizeof a.rk[0]) == 0);
    CHECK(memcmp(a.mk, c.mk, 16 * sizeof a.mk[0]) == 0);
}

/* Bir plan içindeki tüm 13 kelimelik değerler (RK ve MK) birbirinden farklı olmalı;
 * sıfır anahtar da simetrik/tekrarlı tur anahtarı üretmemeli. */
static void test_distinct_round_keys(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES];

    for (int k = 0; k < 200; k++) {
        if (k == 0) memset(key, 0, sizeof key);
        else if (k == 1) memset(key, 0xFF, sizeof key);
        else tu_randbytes(key, sizeof key);
        CHECK(bb416_init(&ctx, key, BB416_MAX_ROUNDS) == BB416_OK);

        const uint32_t *v[2 * BB416_MAX_ROUNDS + 1];
        int nv = 0;
        for (int r = 0; r <= BB416_MAX_ROUNDS; r++) v[nv++] = ctx.rk[r];
        for (int r = 0; r < BB416_MAX_ROUNDS; r++)  v[nv++] = ctx.mk[r];

        for (int x = 0; x < nv; x++) {
            /* Rastgele 416 bitlik değerlerin ağırlığı ~208 ± 10. */
            int w = hamming13(v[x], (const uint32_t[13]){ 0 });
            CHECK(w > 140 && w < 276);
            for (int y = 0; y < x; y++)
                CHECK(hamming13(v[x], v[y]) > 140);
        }
    }
}

/* Ana anahtarda 1 bit → her RK/MK'da ortalama ~208 bit değişmeli. */
static void test_schedule_avalanche(void)
{
    static bb416_ctx a, b;
    uint8_t key[BB416_KEY_BYTES];
    const int N = 2000;
    double sum_rk0 = 0, sum_all = 0;
    int min_rk0 = 416;

    for (int k = 0; k < N; k++) {
        tu_randbytes(key, sizeof key);
        CHECK(bb416_init(&a, key, 16) == BB416_OK);
        unsigned bit = tu_rand32() % 416u;
        key[bit >> 3] ^= (uint8_t)(1u << (bit & 7u));
        CHECK(bb416_init(&b, key, 16) == BB416_OK);

        int d0 = hamming13(a.rk[0], b.rk[0]);
        sum_rk0 += d0;
        if (d0 < min_rk0) min_rk0 = d0;
        for (int r = 0; r <= 16; r++) sum_all += hamming13(a.rk[r], b.rk[r]);
        for (int r = 0; r < 16; r++)  sum_all += hamming13(a.mk[r], b.mk[r]);
    }
    double mean_rk0 = sum_rk0 / N, mean_all = sum_all / (N * 33.0);
    /* MK'da her kelimenin 0. biti | 1 ile sabit → MK için ideal (416-13)/2 = 201.5;
     * 17 RK + 16 MK ortalaması (17*208 + 16*201.5)/33 ≈ 204.85. */
    printf("  anahtar planı çığ etkisi: RK[0] ort. %.2f bit (min %d, ideal 208), "
           "tüm RK/MK ort. %.2f bit (ideal 204.85)\n", mean_rk0, min_rk0, mean_all);
    CHECK(mean_rk0 > 206 && mean_rk0 < 210);
    CHECK(mean_all > 203.5 && mean_all < 206.2);
}

/* SPEC.md §6 "bilinen zayıflık": plan tersine çevrilebilir. RK[0] sızarsa
 * iki ters karıştırma + tur sabiti XOR'u ana anahtarı verir. */
static void test_known_weakness_invertible(void)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], rec[BB416_KEY_BYTES];

    for (int k = 0; k < 1000; k++) {
        tu_randbytes(key, sizeof key);
        CHECK(bb416_init(&ctx, key, 16) == BB416_OK);

        uint32_t K[13];
        memcpy(K, ctx.rk[0], sizeof K);
        ref_mix_inv(K);
        ref_mix_inv(K);
        K[0] ^= 1u * REF_KS_GOLD;
        for (int i = 0; i < 13; i++)
            store32_le(rec + 4 * i, K[i]);
        CHECK(memcmp(rec, key, sizeof key) == 0);
    }
}

int main(int argc, char **argv)
{
    tu_init("test_keysched", argc, argv);
    test_init_errors();
    test_against_reference();
    test_determinism_and_prefix();
    test_distinct_round_keys();
    test_schedule_avalanche();
    test_known_weakness_invertible();
    return tu_finish("test_keysched");
}
