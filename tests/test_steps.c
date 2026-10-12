/*
 * Aşama 2: her tur adımı için ters(adım(S)) == S, elle hesaplanmış birkaç
 * bilinen sonuç ve Adım 4/5'in yayılma özellikleri.
 */
#include <string.h>

#include "bb416_internal.h"
#include "test_util.h"

#define TRIALS 100000

static void rand_state(uint32_t S[13])
{
    for (int i = 0; i < 13; i++)
        S[i] = tu_rand32();
}

static int state_eq(const uint32_t a[13], const uint32_t b[13])
{
    return memcmp(a, b, 13 * sizeof a[0]) == 0;
}

static int words_changed(const uint32_t a[13], const uint32_t b[13])
{
    int n = 0;
    for (int i = 0; i < 13; i++)
        n += a[i] != b[i];
    return n;
}

/* ---- ters(adım(S)) == S ------------------------------------------------ */

static void test_inverses(void)
{
    uint32_t S[13], orig[13], key[13], mk[13], mkinv[13];
    unsigned long identity[7] = { 0 }; /* adım S'yi hiç değiştirmediyse */

    for (int k = 0; k < TRIALS; k++) {
        rand_state(orig);
        rand_state(key);
        for (int i = 0; i < 13; i++) {
            mk[i] = tu_rand32() | 1u;
            mkinv[i] = mulinv32(mk[i]);
        }

#define ROUNDTRIP(n, fwd, inv)                 \
        memcpy(S, orig, sizeof S);             \
        fwd;                                   \
        identity[n] += state_eq(S, orig);      \
        inv;                                   \
        CHECK(state_eq(S, orig));

        ROUNDTRIP(1, bb416_step1(S, key), bb416_step1_inv(S, key))
        ROUNDTRIP(2, bb416_step2(S, mk), bb416_step2_inv(S, mkinv))
        ROUNDTRIP(3, bb416_step3(S), bb416_step3_inv(S))
        ROUNDTRIP(4, bb416_step4(S), bb416_step4_inv(S))
        ROUNDTRIP(5, bb416_step5(S), bb416_step5_inv(S))
        ROUNDTRIP(6, bb416_step6(S), bb416_step6_inv(S))
#undef ROUNDTRIP
    }

    /* Rastgele durumda hiçbir adım birim dönüşüm gibi davranmamalı. */
    for (int n = 1; n <= 6; n++)
        CHECK(identity[n] == 0);
}

/* Uç durumlar: tümü 0 / tümü 1 bitli durumlar, mk = 1 ve mk = -1. */
static void test_edge_states(void)
{
    static const uint32_t fills[] = { 0u, 0xFFFFFFFFu, 0x80000000u, 1u };
    uint32_t S[13], orig[13], mk[13], mkinv[13];

    for (size_t f = 0; f < sizeof fills / sizeof fills[0]; f++) {
        for (int i = 0; i < 13; i++) {
            orig[i] = fills[f];
            mk[i] = (i & 1) ? 1u : 0xFFFFFFFFu;
            mkinv[i] = mulinv32(mk[i]);
        }
        memcpy(S, orig, sizeof S); bb416_step2(S, mk); bb416_step2_inv(S, mkinv);
        CHECK(state_eq(S, orig));
        memcpy(S, orig, sizeof S); bb416_step4(S); bb416_step4_inv(S);
        CHECK(state_eq(S, orig));
        memcpy(S, orig, sizeof S); bb416_step5(S); bb416_step5_inv(S);
        CHECK(state_eq(S, orig));
    }
}

/* ---- Elle hesaplanmış bilinen sonuçlar ---------------------------------- */

static void test_known_values(void)
{
    uint32_t S[13], mk[13];

    /* Adım 3: tümü 1 olan durumda S[i] = 1 << ROT[i]. */
    for (int i = 0; i < 13; i++) S[i] = 1u;
    bb416_step3(S);
    for (int i = 0; i < 13; i++)
        CHECK(S[i] == (1u << BB416_ROT[i]));

    /* Adım 6: S[i] = i ise takastan sonra S[i] = 12 - i, merkez bit-ters. */
    for (int i = 0; i < 13; i++) S[i] = (uint32_t)i;
    bb416_step6(S);
    for (int i = 0; i < 13; i++)
        CHECK(S[i] == (i == 6 ? bitrev32(6u) : (uint32_t)(12 - i)));
    CHECK(S[6] == 0x60000000u);

    /* Adım 2: mk = 1 iken yalnızca x ^= x >> 16 kalır. */
    for (int i = 0; i < 13; i++) { S[i] = 0xABCD1234u; mk[i] = 1u; }
    bb416_step2(S, mk);
    for (int i = 0; i < 13; i++)
        CHECK(S[i] == 0xABCDB9F9u); /* 0x1234 ^ 0xABCD = 0xB9F9 */

    /* Adım 2: mk = 3, x = 0x80000001 → x*3 = 0x80000003 → ^ 0x8000 = 0x80008003. */
    for (int i = 0; i < 13; i++) { S[i] = 0x80000001u; mk[i] = 3u; }
    bb416_step2(S, mk);
    CHECK(S[0] == 0x80008003u);

    /* Adım 4: yalnızca S[0] = 1, diğerleri 0 →
     * S[12] = 1, S[0] = 1 ^ rotl(1, 7) = 0x81; diğer çiftler sıfır kalır. */
    memset(S, 0, sizeof S);
    S[0] = 1u;
    bb416_step4(S);
    CHECK(S[12] == 1u);
    CHECK(S[0] == 0x81u);
    for (int i = 1; i < 12; i++)
        CHECK(S[i] == 0u);

    /* Adım 5: S[i] = 1 (i != 6), S[6] = 0 → S[6] = 12, S[i] = 1 ^ rotl(12, i+1). */
    for (int i = 0; i < 13; i++) S[i] = (i == 6) ? 0u : 1u;
    bb416_step5(S);
    CHECK(S[6] == 12u);
    for (int i = 0; i < 13; i++)
        if (i != 6)
            CHECK(S[i] == (1u ^ rotl32(12u, (unsigned)i + 1u)));
}

/* ---- Yayılma: Adım 4 yalnızca çiftleri, Adım 5 tüm durumu karıştırır ----- */

static void test_diffusion(void)
{
    uint32_t A[13], B[13];
    unsigned long step5_full = 0, step5_trials = 0;

    for (int k = 0; k < TRIALS; k++) {
        rand_state(A);
        memcpy(B, A, sizeof A);
        int w = (int)(tu_rand32() & 0xFFu) % 13;   /* test kodu: % serbest */
        B[w] ^= 1u << (tu_rand32() & 31u);

        /* Adım 4: fark yalnızca kendi çiftine (w, 12-w) yayılabilir. */
        uint32_t A4[13], B4[13];
        memcpy(A4, A, sizeof A); memcpy(B4, B, sizeof B);
        bb416_step4(A4); bb416_step4(B4);
        for (int i = 0; i < 13; i++)
            if (i != w && i != 12 - w)
                CHECK(A4[i] == B4[i]);

        /* Adım 5: tek bitlik fark (merkez dışı) S[6]'yı ve neredeyse her zaman
         * diğer tüm kelimeleri değiştirmeli. */
        if (w != 6) {
            bb416_step5(A); bb416_step5(B);
            CHECK(A[6] != B[6]);
            step5_full += words_changed(A, B) == 13;
            step5_trials++;
        }
    }
    /* Çakışma olasılığı kelime başına ~2^-32 düzeyinde; pratikte hep 13 olmalı. */
    CHECK(step5_full * 1000 >= step5_trials * 999);
    printf("  adım 5: tek bit farkı %lu/%lu denemede 13 kelimenin hepsini değiştirdi\n",
           step5_full, step5_trials);
}

int main(int argc, char **argv)
{
    tu_init("test_steps", argc, argv);
    test_inverses();
    test_edge_states();
    test_known_values();
    test_diffusion();
    return tu_finish("test_steps");
}
