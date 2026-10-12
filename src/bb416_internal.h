/*
 * BicBic416 iç yardımcıları (SPEC.md §2–3).
 * Kütüphane ve testler tarafından paylaşılır; genel API'nin parçası değildir.
 */
#ifndef BB416_INTERNAL_H
#define BB416_INTERNAL_H

#include <stdint.h>

/* Satır döndürme sabitleri: ROT[i] = (13*i + 3) mod 32 */
static const unsigned BB416_ROT[13] = {
    3, 16, 29, 10, 23, 4, 17, 30, 11, 24, 5, 18, 31
};

/* r & 31 maskesi sayesinde r == 0 tanımsız davranış üretmez. */
static inline uint32_t rotl32(uint32_t x, unsigned r)
{
    return (x << (r & 31u)) | (x >> ((32u - r) & 31u));
}

static inline uint32_t rotr32(uint32_t x, unsigned r)
{
    return (x >> (r & 31u)) | (x << ((32u - r) & 31u));
}

/* Bit sırasını ters çevirir; dalsız, kendi tersidir. */
static inline uint32_t bitrev32(uint32_t x)
{
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0F0F0F0Fu) | ((x & 0x0F0F0F0Fu) << 4);
    x = ((x >> 8) & 0x00FF00FFu) | ((x & 0x00FF00FFu) << 8);
    return (x >> 16) | (x << 16);
}

/*
 * a tek sayı olmalı; a * inv ≡ 1 (mod 2^32).
 * Newton: inv = a başlangıçta 3 bit doğrudur, her adım doğru bit sayısını ikiye katlar.
 */
static inline uint32_t mulinv32(uint32_t a)
{
    uint32_t inv = a;
    for (int k = 0; k < 5; k++)
        inv *= 2u - a * inv;
    return inv;
}

/* Platform endianness'ından bağımsız little-endian yükleme/saklama. */
static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

/*
 * Tur adımları (SPEC.md §4) ve tersleri (§5). Tanımlar bicbic416.c içindedir;
 * testlerin her adımı ayrı ayrı sınayabilmesi için burada bildirilir.
 * 1 ve 6 kendi tersidir; _inv sürümleri simetri için yine de vardır.
 */
void bb416_step1(uint32_t S[13], const uint32_t rk[13]);
void bb416_step1_inv(uint32_t S[13], const uint32_t rk[13]);
void bb416_step2(uint32_t S[13], const uint32_t mk[13]);
void bb416_step2_inv(uint32_t S[13], const uint32_t mkinv[13]);
void bb416_step3(uint32_t S[13]);
void bb416_step3_inv(uint32_t S[13]);
void bb416_step4(uint32_t S[13]);
void bb416_step4_inv(uint32_t S[13]);
void bb416_step5(uint32_t S[13]);
void bb416_step5_inv(uint32_t S[13]);
void bb416_step6(uint32_t S[13]);
void bb416_step6_inv(uint32_t S[13]);

#endif /* BB416_INTERNAL_H */
