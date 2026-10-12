/*
 * Yapısal simetri ve özel durum testleri (tam tur sayısında, R = 16).
 *
 * Bir dönüşüm σ için E(σK, σP) = σE(K, P) gibi bir eşitlik (veya ona yakınlık)
 * varsa, anahtar uzayı fiilen küçülür veya şifre ayırt edilebilir olur
 * (ör. DES'in tümleme özelliği). Her σ için şifreli metinler arasındaki
 * Hamming uzaklığı ölçülür: rastgelede ortalama 208, std. sapma ≈ 10.2.
 *
 * Ayrıca: zayıf çarpan anahtarları (MK ≡ 1 mod 2^16: çarpma o kelimenin alt
 * yarısını değiştirmez) ne sıklıkla oluşuyor; sabit noktalar / kısa döngü yok mu.
 */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "bb416_internal.h"
#include "bicbic416.h"
#include "test_util.h"

#define R 16
#define N 20000

typedef void (*sigma_fn)(uint8_t *x, int len);

static void s_complement(uint8_t *x, int len) { for (int i = 0; i < len; i++) x[i] ^= 0xFF; }
static void s_rot1(uint8_t *x, int len)
{
    for (int i = 0; i + 4 <= len; i += 4) store32_le(x + i, rotl32(load32_le(x + i), 1));
}
static void s_rot16(uint8_t *x, int len)
{
    for (int i = 0; i + 4 <= len; i += 4) store32_le(x + i, rotl32(load32_le(x + i), 16));
}
static void s_reverse_words(uint8_t *x, int len)
{
    int n = len / 4;
    for (int i = 0; i < n / 2; i++) {
        uint32_t a = load32_le(x + 4 * i), b = load32_le(x + 4 * (n - 1 - i));
        store32_le(x + 4 * i, b);
        store32_le(x + 4 * (n - 1 - i), a);
    }
}
static void s_bitrev_words(uint8_t *x, int len)
{
    for (int i = 0; i + 4 <= len; i += 4) store32_le(x + i, bitrev32(load32_le(x + i)));
}
static void s_msb(uint8_t *x, int len) { for (int i = 3; i < len; i += 4) x[i] ^= 0x80; }

static int hamming(const uint8_t *a, const uint8_t *b, int n)
{
    int d = 0;
    for (int i = 0; i < n; i++)
        for (uint8_t x = a[i] ^ b[i]; x; x &= (uint8_t)(x - 1)) d++;
    return d;
}

int main(int argc, char **argv)
{
    tu_init("structure", argc, argv);
    static const struct { const char *name; sigma_fn f; } sig[] = {
        { "tümleme (tüm bitleri ters çevir)", s_complement },
        { "her kelimeyi 1 bit döndür", s_rot1 },
        { "her kelimeyi 16 bit döndür", s_rot16 },
        { "kelime sırasını ters çevir (sarmal simetrisi)", s_reverse_words },
        { "her kelimenin bitlerini ters çevir", s_bitrev_words },
        { "her kelimenin üst bitini çevir", s_msb },
    };
    static bb416_ctx a, b;
    uint8_t k[BB416_KEY_BYTES], k2[BB416_KEY_BYTES], p[BB416_BLOCK_BYTES], p2[BB416_BLOCK_BYTES],
            c[BB416_BLOCK_BYTES], c2[BB416_BLOCK_BYTES];

    printf("| Dönüşüm σ | d(E(σK,σP), σE(K,P)) ort. | std. sapma | min | Sonuç |\n");
    printf("|---|---:|---:|---:|---|\n");
    for (size_t s = 0; s < sizeof sig / sizeof sig[0]; s++) {
        double sum = 0, sq = 0;
        int mn = 416;
        for (int n = 0; n < N; n++) {
            tu_randbytes(k, sizeof k);
            tu_randbytes(p, sizeof p);
            memcpy(k2, k, sizeof k);
            memcpy(p2, p, sizeof p);
            sig[s].f(k2, sizeof k2);
            sig[s].f(p2, sizeof p2);
            bb416_init(&a, k, R);
            bb416_init(&b, k2, R);
            bb416_encrypt_block(&a, p, c);
            bb416_encrypt_block(&b, p2, c2);
            sig[s].f(c, sizeof c);
            int d = hamming(c, c2, sizeof c);
            sum += d; sq += (double)d * d;
            if (d < mn) mn = d;
        }
        double m = sum / N, sd = sqrt(sq / N - m * m);
        int ok = fabs(m - 208) < 0.5 && fabs(sd - 10.2) < 0.6 && mn > 140;
        printf("| %s | %.2f | %.2f | %d | %s |\n", sig[s].name, m, sd, mn,
               ok ? "simetri yok (iyi)" : "ŞÜPHELİ");
        fflush(stdout);
    }

    /* Zayıf çarpanlar: MK ≡ 1 (mod 2^16) olan kelimeler. */
    long weak_words = 0, weak_keys = 0;
    const long KEYS = 200000;
    for (long n = 0; n < KEYS; n++) {
        tu_randbytes(k, sizeof k);
        bb416_init(&a, k, R);
        int any = 0;
        for (int r = 0; r < R; r++)
            for (int i = 0; i < 13; i++)
                if ((a.mk[r][i] & 0xFFFFu) == 1u) { weak_words++; any = 1; }
        weak_keys += any;
    }
    printf("\nZayıf çarpan (MK ≡ 1 mod 2^16): %ld anahtarın %ld'inde (%.3f%%) en az bir tur kelimesi "
           "(toplam %ld kelime); beklenen ≈ %.3f%% (208 kelime × 2^-15)\n", KEYS, weak_keys,
           100.0 * weak_keys / KEYS, weak_words, 100.0 * (1 - pow(1 - 1.0 / 32768, 208)));

    /* Sabit nokta / kısa döngü: E(P) = P veya E(E(P)) = P olmamalı. */
    long fixed = 0, cyc2 = 0;
    for (long n = 0; n < 200000; n++) {
        if ((n & 1023) == 0) { tu_randbytes(k, sizeof k); bb416_init(&a, k, R); }
        tu_randbytes(p, sizeof p);
        bb416_encrypt_block(&a, p, c);
        bb416_encrypt_block(&a, c, c2);
        fixed += memcmp(c, p, sizeof p) == 0;
        cyc2 += memcmp(c2, p, sizeof p) == 0;
    }
    printf("Sabit nokta: %ld, 2-döngü: %ld (200 000 denemede; rastgele permütasyonda beklenen 0)\n",
           fixed, cyc2);
    return 0;
}
