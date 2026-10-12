/*
 * Azaltılmış turlarda deneysel lineer kriptanaliz.
 *
 * Soru: Sabit (bilinmeyen) bir anahtarla, düz metnin bir biti ile şifreli metnin
 * bir biti arasında rastgelede olmaması gereken bir ilişki (korelasyon) var mı?
 * Bu tasarıma özel aday: modüler toplamanın ve tek sayıyla çarpmanın en alt biti
 * doğrusaldır (XOR gibi davranır); bu yüzden alt bitler arasında iz kalabilir.
 *
 * Yöntem: Her tur sayısı için 2 rastgele anahtar × N rastgele düz metin; tüm
 * 416 × 416 (girdi biti, çıktı biti) çifti için korelasyon c = 2·P(eşit) − 1.
 * Saf rastgelede |c| ≈ 1/√N; 173 056 çift arasında en büyük gürültü ≈ 4.9/√N.
 * Anlamlılık eşiği |z| = |c|·√N > 6.
 *
 * Kullanım: linear [en_fazla_tur] [N_log2]
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"
#include "test_util.h"

#define NB 416

static uint32_t both[NB][NB]; /* both[o][i] = P_i ve C_o ikisinin de 1 olduğu örnek sayısı */
static uint32_t sp[NB], sc[NB];

int main(int argc, char **argv)
{
    int maxR = argc > 1 ? atoi(argv[1]) : 4;
    int lg = argc > 2 ? atoi(argv[2]) : 18;
    long N = 1L << lg;
    tu_init("linear", 1, argv);

    printf("N = 2^%d düz metin / anahtar, 2 anahtar; eşik |z| > 6 (gürültü beklentisi ≈ 4.9)\n\n", lg);
    printf("| Tur | Anahtar | En güçlü ilişki | Korelasyon | z | Gereken düz metin | Sonuç |\n");
    printf("|---:|---:|---|---:|---:|---:|---|\n");

    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], c[BB416_BLOCK_BYTES];
    uint8_t pb[NB];

    for (int R = 1; R <= maxR; R++) {
        for (int kk = 0; kk < 2; kk++) {
            tu_randbytes(key, sizeof key);
            bb416_init(&ctx, key, R);
            memset(both, 0, sizeof both);
            memset(sp, 0, sizeof sp);
            memset(sc, 0, sizeof sc);

            for (long n = 0; n < N; n++) {
                tu_randbytes(p, sizeof p);
                bb416_encrypt_block(&ctx, p, c);
                for (int i = 0; i < NB; i++) {
                    pb[i] = (p[i >> 3] >> (i & 7)) & 1u;
                    sp[i] += pb[i];
                }
                for (int o = 0; o < NB; o++) {
                    if ((c[o >> 3] >> (o & 7)) & 1u) {
                        sc[o]++;
                        uint32_t *row = both[o];
                        for (int i = 0; i < NB; i++)
                            row[i] += pb[i];
                    }
                }
            }

            double best = 0, bc = 0;
            int bi = 0, bo = 0;
            for (int o = 0; o < NB; o++)
                for (int i = 0; i < NB; i++) {
                    /* eşit sayısı = N − sp − sc + 2·both */
                    double eq = (double)N - sp[i] - sc[o] + 2.0 * both[o][i];
                    double cor = 2.0 * eq / N - 1.0;
                    double z = fabs(cor) * sqrt((double)N);
                    if (z > best) { best = z; bc = cor; bi = i; bo = o; }
                }
            int sig = best > 6;
            printf("| %d | %d | girdi k%d.b%d ↔ çıktı k%d.b%d | %+.4f | %.1f | %s%.3g | %s |\n",
                   R, kk + 1, bi / 32, bi % 32, bo / 32, bo % 32, bc, best,
                   sig ? "≈ " : "> ", sig ? 25.0 / (bc * bc) : (double)N,
                   sig ? "AYIRT EDİLEBİLİR" : "rastgeleden ayırt edilemedi");
            fflush(stdout);
        }
    }
    return 0;
}
