/*
 * Azaltılmış turlarda deneysel diferansiyel kriptanaliz.
 *
 * Soru: Girdide belirli bir fark (XOR) verildiğinde, R tur sonra çıktı farkında
 * rastgeleden ayırt edilebilir bir iz kalıyor mu?
 *
 * Yöntem (iki aşamalı arama):
 *   1. Tarama: 416 tek-bit fark + 78 "iki kelimenin en üst biti" farkı (toplama
 *      altında birbirini götürebilen, bu tasarıma özel aday) için az sayıda çiftle
 *      her çıktı bitinin değişme olasılığını ölç; en şüpheli 8 farkı seç.
 *   2. Doğrulama: Seçilenleri bağımsız, çok daha büyük örneklerle yeniden ölç.
 *      (Aynı veriyle seçip aynı veriyle doğrulamak sahte sonuç üretir.)
 * Ek olarak, tam çıktı farkının tekrar edip etmediğine bakılır (yüksek olasılıklı
 * diferansiyel karakteristik varsa aynı çıktı farkı defalarca görülür).
 *
 * Çıktı: her tur için en büyük sapma ε (değişme olasılığı = 0.5 ± ε), z-skoru ve
 * bu sapmayı ayırt etmek için gereken yaklaşık çift sayısı ≈ 6.25 / ε².
 *
 * Kullanım: differential [en_fazla_tur] [aşama2_çift_log2]
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"
#include "test_util.h"

#define NB 416
#define NCAND (416 + 78)
#define TOP 8

typedef struct { uint8_t d[BB416_BLOCK_BYTES]; char name[48]; } diff_t;

static diff_t cand[NCAND];
static uint32_t flips[NB];

static void build_candidates(void)
{
    int n = 0;
    for (int b = 0; b < NB; b++, n++) {
        memset(cand[n].d, 0, BB416_BLOCK_BYTES);
        cand[n].d[b >> 3] = (uint8_t)(1u << (b & 7));
        snprintf(cand[n].name, sizeof cand[n].name, "kelime %d bit %d", b / 32, b % 32);
    }
    for (int i = 0; i < 13; i++)
        for (int j = i + 1; j < 13; j++, n++) {
            memset(cand[n].d, 0, BB416_BLOCK_BYTES);
            cand[n].d[4 * i + 3] = 0x80;
            cand[n].d[4 * j + 3] = 0x80;
            snprintf(cand[n].name, sizeof cand[n].name, "kelime %d ve %d, bit 31", i, j);
        }
}

/* N çift için her çıktı bitinin değişme sayısını flips[]'e yazar; anahtar her
 * 256 çiftte bir yenilenir (beklenen diferansiyel olasılık, anahtarlar üzerinden). */
static void measure(int R, const uint8_t d[BB416_BLOCK_BYTES], long N, uint32_t *exact_max)
{
    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], q[BB416_BLOCK_BYTES],
            c1[BB416_BLOCK_BYTES], c2[BB416_BLOCK_BYTES];
    memset(flips, 0, sizeof flips);

    /* Tam çıktı farkı tekrarı: 64-bit özetleri küçük bir tabloda say. */
    enum { H = 1 << 16 };
    static uint64_t hk[H];
    static uint32_t hv[H];
    if (exact_max) { memset(hk, 0, sizeof hk); memset(hv, 0, sizeof hv); *exact_max = 0; }

    for (long k = 0; k < N; k++) {
        if ((k & 255) == 0) {
            tu_randbytes(key, sizeof key);
            bb416_init(&ctx, key, R);
        }
        tu_randbytes(p, sizeof p);
        for (int i = 0; i < BB416_BLOCK_BYTES; i++) q[i] = p[i] ^ d[i];
        bb416_encrypt_block(&ctx, p, c1);
        bb416_encrypt_block(&ctx, q, c2);
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < BB416_BLOCK_BYTES; i++) {
            uint8_t x = c1[i] ^ c2[i];
            h = (h ^ x) * 1099511628211ULL;
            for (int b = 0; b < 8; b++) flips[8 * i + b] += (x >> b) & 1u;
        }
        if (exact_max && k < H / 2) {
            uint32_t s = (uint32_t)h & (H - 1);
            while (hk[s] && hk[s] != h) s = (s + 1) & (H - 1);
            hk[s] = h;
            if (++hv[s] > *exact_max) *exact_max = hv[s];
        }
    }
}

/* En büyük |z| ve ilgili bit. */
static double max_z(long N, int *bit, double *eps)
{
    double best = 0;
    for (int b = 0; b < NB; b++) {
        double e = (double)flips[b] / N - 0.5;
        double z = fabs(e) * 2.0 * sqrt((double)N);
        if (z > best) { best = z; *bit = b; *eps = e; }
    }
    return best;
}

int main(int argc, char **argv)
{
    int maxR = argc > 1 ? atoi(argv[1]) : 6;
    int log2N2 = argc > 2 ? atoi(argv[2]) : 21;
    const long N1 = 4096, N2 = 1L << log2N2;
    tu_init("differential", 1, argv);
    build_candidates();

    printf("Aşama 1: %d aday fark × %ld çift; aşama 2: en iyi %d aday × %ld yeni çift\n",
           NCAND, N1, TOP, N2);
    printf("Anlamlılık eşiği: aşama 2'de |z| > 5.5 (416 bit × %d aday çoklu karşılaştırma dahil)\n\n", TOP);
    printf("| Tur | En güçlü girdi farkı | Çıktı biti | Değişme olasılığı | z | Gereken çift | Tam fark tekrarı | Sonuç |\n");
    printf("|---:|---|---:|---:|---:|---:|---:|---|\n");

    for (int R = 1; R <= maxR; R++) {
        double zs[NCAND];
        for (int c = 0; c < NCAND; c++) {
            int b; double e;
            measure(R, cand[c].d, N1, NULL);
            zs[c] = max_z(N1, &b, &e);
        }
        int top[TOP];
        for (int t = 0; t < TOP; t++) {
            int bi = -1;
            for (int c = 0; c < NCAND; c++) {
                int used = 0;
                for (int u = 0; u < t; u++) used |= top[u] == c;
                if (!used && (bi < 0 || zs[c] > zs[bi])) bi = c;
            }
            top[t] = bi;
        }

        double bestz = 0, besteps = 0;
        int bestc = top[0], bestbit = 0;
        uint32_t best_exact = 0;
        for (int t = 0; t < TOP; t++) {
            int b = 0; double e = 0;
            uint32_t ex;
            measure(R, cand[top[t]].d, N2, &ex);
            double z = max_z(N2, &b, &e);
            if (z > bestz) { bestz = z; besteps = e; bestc = top[t]; bestbit = b; }
            if (ex > best_exact) best_exact = ex;
        }
        double need = besteps != 0 ? 6.25 / (besteps * besteps) : 0;
        int sig = bestz > 5.5;
        printf("| %d | %s | %d | %.4f | %.1f | %s%.3g | %u / %ld | %s |\n",
               R, cand[bestc].name, bestbit, 0.5 + besteps, bestz,
               sig ? "≈ " : "> ", sig ? need : (double)N2, best_exact, N2 < (1L << 15) ? N2 : (1L << 15),
               sig ? "AYIRT EDİLEBİLİR" : "rastgeleden ayırt edilemedi");
        fflush(stdout);
    }
    return 0;
}
