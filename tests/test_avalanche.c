/*
 * Aşama 5: çığ etkisi (SPEC.md §9.5, §10).
 *
 * Her tur sayısı R = 1..16 için N deneme:
 *   - düz metin modu: rastgele anahtar+blok, düz metinde rastgele 1 bit çevir
 *   - anahtar modu:   rastgele anahtar+blok, anahtarda rastgele 1 bit çevir
 * Şifreli metinde değişen bit sayısının ortalaması, standart sapması, min/max'ı ve
 * çıktı bitlerinin değişme olasılığının 0.5'ten en büyük sapması yazdırılır.
 *
 * İdeal (rastgele permütasyon): ortalama 208, std. sapma √104 ≈ 10.198.
 * "Ulaştı" eşikleri N'den türetilir (≈5σ), böylece rastgele dalgalanma
 * yanlış alarm vermez ama gerçek sapmalar yakalanır.
 *
 * Kullanım: test_avalanche [tohum] [N]
 */
#include <math.h>
#include <string.h>

#include "bicbic416.h"
#include "test_util.h"

#define MAX_R    16
#define NBITS    416
#define IDEAL_MEAN 208.0

typedef struct {
    double mean, sd, max_bias;
    int min, max;
    int ok;
} stats;

static int popcount8(uint8_t x)
{
    int c = 0;
    for (; x; x &= (uint8_t)(x - 1))
        c++;
    return c;
}

static void flip_bit(uint8_t *buf, unsigned bit)
{
    buf[bit >> 3] ^= (uint8_t)(1u << (bit & 7u));
}

static stats measure(int R, int key_mode, long N)
{
    static bb416_ctx ctx;
    static unsigned long per_bit[NBITS];
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], c1[BB416_BLOCK_BYTES],
            c2[BB416_BLOCK_BYTES];
    double sum = 0, sumsq = 0;
    stats st = { 0, 0, 0, NBITS, 0, 0 };

    memset(per_bit, 0, sizeof per_bit);
    for (long k = 0; k < N; k++) {
        tu_randbytes(key, sizeof key);
        tu_randbytes(p, sizeof p);
        unsigned bit = tu_rand32() % NBITS;

        CHECK(bb416_init(&ctx, key, R) == BB416_OK);
        bb416_encrypt_block(&ctx, p, c1);
        if (key_mode) {
            flip_bit(key, bit);
            CHECK(bb416_init(&ctx, key, R) == BB416_OK);
        } else {
            flip_bit(p, bit);
        }
        bb416_encrypt_block(&ctx, p, c2);

        int d = 0;
        for (int i = 0; i < BB416_BLOCK_BYTES; i++) {
            uint8_t x = c1[i] ^ c2[i];
            d += popcount8(x);
            for (int b = 0; b < 8; b++)
                per_bit[8 * i + b] += (x >> b) & 1u;
        }
        sum += d;
        sumsq += (double)d * d;
        if (d < st.min) st.min = d;
        if (d > st.max) st.max = d;
    }

    st.mean = sum / N;
    st.sd = sqrt(sumsq / N - st.mean * st.mean);
    for (int b = 0; b < NBITS; b++) {
        double dev = fabs((double)per_bit[b] / N - 0.5);
        if (dev > st.max_bias) st.max_bias = dev;
    }

    const double ideal_sd = sqrt(NBITS / 4.0);
    const double mean_tol = 5.0 * ideal_sd / sqrt((double)N);
    const double sd_tol   = 5.0 * ideal_sd / sqrt(2.0 * N);
    const double bias_tol = 4.5 * 0.5 / sqrt((double)N); /* 416 bitin en kötüsü */
    st.ok = fabs(st.mean - IDEAL_MEAN) < mean_tol &&
            fabs(st.sd - ideal_sd) < sd_tol &&
            st.max_bias < bias_tol;
    return st;
}

static int run_mode(int key_mode, long N)
{
    int T = 0;

    printf("\n%s biti çevrildi (N = %ld deneme / tur sayısı)\n",
           key_mode ? "Anahtar" : "Düz metin", N);
    printf("| Tur | Ortalama | Std. sapma | Min | Maks | Maks. bit sapması | İdeal |\n");
    printf("|----:|---------:|-----------:|----:|-----:|------------------:|:-----:|\n");
    for (int R = 1; R <= MAX_R; R++) {
        stats st = measure(R, key_mode, N);
        /* "hayır" UTF-8'de 6 bayt; %-Ns bayt saydığı için sabit metin kullanılır. */
        printf("| %3d | %8.2f | %10.2f | %3d | %4d | %17.4f | %s |\n",
               R, st.mean, st.sd, st.min, st.max, st.max_bias, st.ok ? "evet " : "hayır");
        fflush(stdout);
        if (!st.ok) T = 0;            /* T: bu turdan itibaren hep ideal */
        else if (T == 0) T = R;
        if (R == MAX_R) CHECK(st.ok); /* varsayılan R = 16 ideal olmalı */
    }
    printf("İdeal: ortalama 208.00, std. sapma %.2f, maks. bit sapması < %.4f\n",
           sqrt(NBITS / 4.0), 4.5 * 0.5 / sqrt((double)N));
    return T;
}

int main(int argc, char **argv)
{
    long N = 20000;
    tu_init("test_avalanche", argc, argv);
    if (argc > 2)
        N = strtol(argv[2], NULL, 0);
    if (N < 100)
        N = 100;

    int T_pt  = run_mode(0, N);
    int T_key = run_mode(1, N);
    int T = T_pt > T_key ? T_pt : T_key;

    printf("\nT (çığ etkisinin ideale oturduğu ilk tur): düz metin %d, anahtar %d → T = %d\n",
           T_pt, T_key, T);
    if (T > 0)
        printf("SPEC.md §10 kuralı R ≥ 3T–4T → R = %d–%d önerilir\n", 3 * T, 4 * T);
    CHECK(T > 0);
    return tu_finish("test_avalanche");
}
