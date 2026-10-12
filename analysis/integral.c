/*
 * Azaltılmış turlarda integral (kare / "toplam") analizi.
 *
 * Soru: Bir kelimenin alt k bitini tüm 2^k değerinden geçirip diğer her şeyi sabit
 * tutarsak, R tur sonra şifreli metinlerin XOR toplamında sıfıra kilitlenmiş
 * ("dengeli") bitler kalıyor mu? Kelime tabanlı şifrelerde (ör. AES'in azaltılmış
 * sürümleri) en güçlü saldırılardan biri budur.
 *
 * Rastgele bir permütasyonda her bitin XOR toplamı 1/2 olasılıkla 0'dır. T = 32
 * bağımsız denemenin hepsinde 0 olan bit "dengeli" sayılır (tüm tablo boyunca
 * yanlış alarm beklentisi 35 satır × 416 bit / 2^32 ≈ 3·10^-6). T = 16 ile ilk
 * çalıştırmada bir yanlış alarm görüldü (beklenti ≈ 0.2), bu yüzden artırıldı.
 *
 * Kullanım: integral [en_fazla_tur]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bb416_internal.h"
#include "bicbic416.h"
#include "test_util.h"

#define T 32

int main(int argc, char **argv)
{
    int maxR = argc > 1 ? atoi(argv[1]) : 5;
    tu_init("integral", 1, argv);
    static const int ks[] = { 8, 16, 20 };
    static const int words[] = { 0, 6, 12 };

    printf("| Tur | Değişen bitler | Dengeli çıktı biti (416'dan) | Sonuç |\n");
    printf("|---:|---|---:|---|\n");

    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], c[BB416_BLOCK_BYTES];

    for (int R = 1; R <= maxR; R++) {
        for (size_t ki = 0; ki < sizeof ks / sizeof ks[0]; ki++) {
            for (size_t wi = 0; wi < sizeof words / sizeof words[0]; wi++) {
                int k = ks[ki], w = words[wi];
                if (k == 20 && w != 6) continue; /* en pahalı durum: yalnızca merkez kelime */
                uint32_t zero_all[13];
                for (int i = 0; i < 13; i++) zero_all[i] = 0xFFFFFFFFu;

                for (int t = 0; t < T; t++) {
                    tu_randbytes(key, sizeof key);
                    bb416_init(&ctx, key, R);
                    tu_randbytes(p, sizeof p);
                    uint32_t base = load32_le(p + 4 * w) & ~((1u << k) - 1u);
                    uint32_t acc[13] = { 0 };
                    for (uint32_t v = 0; v < (1u << k); v++) {
                        store32_le(p + 4 * w, base | v);
                        bb416_encrypt_block(&ctx, p, c);
                        for (int i = 0; i < 13; i++) acc[i] ^= load32_le(c + 4 * i);
                    }
                    /* Bu denemede 0 olmayan bitler artık "dengeli" sayılmaz. */
                    for (int i = 0; i < 13; i++) zero_all[i] &= ~acc[i];
                }
                int balanced = 0;
                for (int i = 0; i < 13; i++)
                    for (uint32_t x = zero_all[i]; x; x &= x - 1) balanced++;
                printf("| %d | kelime %d'nin alt %d biti (2^%d metin) | %d | %s |\n", R, w, k, k,
                       balanced, balanced ? "AYIRT EDİLEBİLİR" : "rastgeleden ayırt edilemedi");
                fflush(stdout);
            }
        }
    }
    return 0;
}
