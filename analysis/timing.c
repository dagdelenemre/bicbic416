/*
 * Zamanlama yan kanalı testi (dudect yöntemi: Reparaz, Balasch, Verbauwhede 2017).
 *
 * İki girdi sınıfı rastgele sırayla karıştırılarak ölçülür; süre dağılımları
 * Welch t-testiyle karşılaştırılır. |t| < 4.5: sızıntı tespit edilmedi.
 * |t| > 10: kesin sızıntı.
 *
 * Testin gerçekten sızıntı yakalayabildiğini göstermek için bir "pozitif kontrol"
 * de vardır: standart memcmp ilk farklı baytta durur, bu yüzden SIZDIRMALIDIR.
 *
 * Kullanım: timing [ölçüm_sayısı]
 */
#if !defined(_WIN32)
#  define _POSIX_C_SOURCE 200809L /* clock_gettime: katı C11 modunda görünür olsun */
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"
#include "sha256.h"
#include "test_util.h"

#if defined(__x86_64__) || defined(__i386__)
#  include <x86intrin.h>
static inline uint64_t ticks(void) { _mm_lfence(); uint64_t t = __rdtsc(); _mm_lfence(); return t; }
#else
#  include <time.h>
static inline uint64_t ticks(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}
#endif
#if defined(_WIN32)
#  include <windows.h>
#endif

typedef struct { double n, mean, m2; } welford;

static void wpush(welford *w, double x)
{
    w->n++;
    double d = x - w->mean;
    w->mean += d / w->n;
    w->m2 += d * (x - w->mean);
}

static double welch_t(const welford *a, const welford *b)
{
    double va = a->m2 / (a->n - 1), vb = b->m2 / (b->n - 1);
    return (a->mean - b->mean) / sqrt(va / a->n + vb / b->n);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Ölçülecek işlem: sınıf (0/1) ve hazırlanmış girdi alır. */
typedef void (*op_fn)(int cls, const uint8_t *in);

static bb416_ctx g_ctx;
static uint8_t g_out[4096];
static volatile int g_sink;

static void op_encrypt(int cls, const uint8_t *in) { (void)cls; bb416_encrypt_block(&g_ctx, in, g_out); }
static void op_decrypt(int cls, const uint8_t *in) { (void)cls; bb416_decrypt_block(&g_ctx, in, g_out); }
static void op_keysetup(int cls, const uint8_t *in)
{
    (void)cls;
    static bb416_ctx c;
    bb416_init(&c, in, 16);
    bb416_encrypt_block(&c, in, g_out);
}
static void op_ctr(int cls, const uint8_t *in)
{
    (void)cls;
    static const uint8_t nonce[BB416_NONCE_BYTES] = { 1 };
    bb416_ctr_xor(&g_ctx, nonce, 0, in, g_out, 520);
}
static uint8_t g_ref[4096];
static void op_ct_memcmp(int cls, const uint8_t *in) { (void)cls; g_sink += ct_memcmp(in, g_ref, 4096); }
static void op_memcmp(int cls, const uint8_t *in) { (void)cls; g_sink += memcmp(in, g_ref, 4096) != 0; }

/* Sınıf 0: sabit girdi (hep aynı); sınıf 1: rastgele girdi. memcmp testlerinde:
 * sınıf 0 = referansla eşit, sınıf 1 = ilk baytta farklı. */
static double run(const char *name, op_fn op, size_t in_len, int cmp_mode, long M)
{
    uint8_t *inputs = malloc((size_t)M * in_len);
    uint8_t *cls = malloc((size_t)M);
    uint64_t *t = malloc((size_t)M * sizeof *t);
    for (long i = 0; i < M; i++) {
        cls[i] = (uint8_t)(tu_rand32() & 1u);
        uint8_t *x = inputs + (size_t)i * in_len;
        if (cmp_mode) {
            memcpy(x, g_ref, in_len);
            if (cls[i]) x[0] ^= 1;
        } else if (cls[i]) {
            tu_randbytes(x, in_len);
        } else {
            memset(x, 0, in_len);
        }
    }
    for (long i = 0; i < M; i++) {
        uint64_t a = ticks();
        op(cls[i], inputs + (size_t)i * in_len);
        t[i] = ticks() - a;
    }

    /* Kesinti/gürültü kaynaklı uç değerleri at: birkaç eşikte ayrı ayrı test et,
     * en büyük |t|'yi raporla (dudect'in yaptığı gibi). */
    uint64_t *sorted = malloc((size_t)M * sizeof *sorted);
    memcpy(sorted, t, (size_t)M * sizeof *t);
    qsort(sorted, (size_t)M, sizeof *sorted, cmp_u64);
    static const double pct[] = { 0.50, 0.75, 0.90, 0.95, 0.99 };
    double worst = 0;
    for (size_t p = 0; p < sizeof pct / sizeof pct[0]; p++) {
        uint64_t cut = sorted[(long)(pct[p] * (M - 1))];
        welford w[2] = { { 0, 0, 0 }, { 0, 0, 0 } };
        for (long i = 0; i < M; i++)
            if (t[i] <= cut) wpush(&w[cls[i]], (double)t[i]);
        double tt = fabs(welch_t(&w[0], &w[1]));
        if (tt > worst) worst = tt;
    }
    const char *verdict = worst < 4.5 ? "sızıntı tespit edilmedi" : worst < 10 ? "şüpheli" : "SIZINTI VAR";
    printf("| %s | %.0f | %.2f | %s |\n", name, (double)sorted[M / 2], worst, verdict);
    fflush(stdout);
    free(inputs); free(cls); free(t); free(sorted);
    return worst;
}

int main(int argc, char **argv)
{
    long M = argc > 1 ? atol(argv[1]) : 1000000;
    tu_init("timing", 1, argv);
#if defined(_WIN32)
    SetThreadAffinityMask(GetCurrentThread(), 1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif
    uint8_t key[BB416_KEY_BYTES];
    tu_randbytes(key, sizeof key);
    bb416_init(&g_ctx, key, 16);
    tu_randbytes(g_ref, sizeof g_ref);

    printf("%ld ölçüm / test; sınıf 0 = sabit girdi, sınıf 1 = rastgele girdi\n\n", M);
    printf("| İşlem | Medyan süre (çevrim) | En büyük |t| | Sonuç |\n");
    printf("|---|---:|---:|---|\n");
    double w = 0, x;
    x = run("blok şifreleme (düz metin sınıfları)", op_encrypt, 52, 0, M);   if (x > w) w = x;
    x = run("blok çözme (şifreli metin sınıfları)", op_decrypt, 52, 0, M);   if (x > w) w = x;
    x = run("anahtar hazırlığı + şifreleme (anahtar sınıfları)", op_keysetup, 52, 0, M / 4); if (x > w) w = x;
    x = run("CTR 520 bayt (veri sınıfları)", op_ctr, 520, 0, M / 2);          if (x > w) w = x;
    x = run("etiket karşılaştırma ct_memcmp (eşit / ilk bayt farklı)", op_ct_memcmp, 4096, 1, M / 4); if (x > w) w = x;
    double pos = run("POZİTİF KONTROL: standart memcmp (sızdırmalı)", op_memcmp, 4096, 1, M / 4);
    printf("\nKripto işlemlerinde en büyük |t| = %.2f; pozitif kontrol |t| = %.1f (%s)\n", w, pos,
           pos > 10 ? "test sızıntıyı yakalayabiliyor" : "UYARI: test bu ortamda yeterince hassas değil");
    return 0;
}
