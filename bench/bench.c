/*
 * Aşama 7: hız ölçümü (SPEC.md §9.7).
 * Blok şifreleme, blok çözme, CTR ve anahtar hazırlığı; her biri 3 × süre_sn
 * çalıştırılır, en iyi sonuç yazdırılır.
 *
 * Kullanım: bench [tur sayısı] [süre_sn (varsayılan 0.5)]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bicbic416.h"

#define CTR_BUF (1u << 20) /* 1 MiB */

/* clock(): C89'dan beri standart; MinGW'nin msvcrt'sinde timespec_get yok.
 * Windows'ta duvar saati, Linux'ta CPU zamanı ölçer; tek iş parçacığında ikisi de uygun. */
static double now(void)
{
    return (double)clock() / CLOCKS_PER_SEC;
}

static volatile uint8_t sink; /* volatile: sonuçlar optimize edilip silinmesin */

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(seed + i * 131u);
}

/* fn bir "iş birimi"ni çalıştırır ve işlenen bayt sayısını döndürür. */
typedef size_t (*work_fn)(void);

static bb416_ctx ctx;
static uint8_t blk[BB416_BLOCK_BYTES];
static uint8_t key[BB416_KEY_BYTES];
static uint8_t nonce[BB416_NONCE_BYTES];
static uint8_t *buf;
static uint64_t ctr;
static int rounds;

static size_t w_encrypt(void)
{
    for (int i = 0; i < 1024; i++)
        bb416_encrypt_block(&ctx, blk, blk); /* zincir: sonuç bir sonrakinin girdisi */
    return 1024u * BB416_BLOCK_BYTES;
}

static size_t w_decrypt(void)
{
    for (int i = 0; i < 1024; i++)
        bb416_decrypt_block(&ctx, blk, blk);
    return 1024u * BB416_BLOCK_BYTES;
}

static size_t w_ctr(void)
{
    if (bb416_ctr_xor(&ctx, nonce, ctr, buf, buf, CTR_BUF) != BB416_OK)
        abort();
    ctr += (CTR_BUF + BB416_BLOCK_BYTES - 1) / BB416_BLOCK_BYTES;
    return CTR_BUF;
}

static size_t w_keysetup(void)
{
    static bb416_ctx tmp;
    for (int i = 0; i < 64; i++) {
        key[i % BB416_KEY_BYTES] ^= (uint8_t)i;
        if (bb416_init(&tmp, key, rounds) != BB416_OK)
            abort();
        sink ^= (uint8_t)tmp.rk[0][0];
    }
    return 64; /* burada "bayt" değil, anahtar hazırlığı sayısı */
}

/* 3 deneme yapar, en hızlısını döndürür (arka plan gürültüsünü azaltır). */
static double run(work_fn fn, double seconds)
{
    double best = 0;
    fn(); /* ısınma */
    for (int trial = 0; trial < 3; trial++) {
        size_t total = 0;
        double t0 = now(), t;
        do {
            total += fn();
            t = now();
        } while (t - t0 < seconds);
        double rate = (double)total / (t - t0);
        if (rate > best)
            best = rate;
    }
    return best;
}

int main(int argc, char **argv)
{
    rounds = argc > 1 ? atoi(argv[1]) : 16;
    double seconds = argc > 2 ? atof(argv[2]) : 0.5;

    buf = malloc(CTR_BUF);
    if (!buf)
        return 1;
    fill(key, sizeof key, 1);
    fill(nonce, sizeof nonce, 2);
    fill(blk, sizeof blk, 3);
    fill(buf, CTR_BUF, 4);
    if (bb416_init(&ctx, key, rounds) != BB416_OK) {
        fprintf(stderr, "geçersiz tur sayısı: %d\n", rounds);
        return 1;
    }

    const double MB = 1e6;
    double enc = run(w_encrypt, seconds) / MB;
    double dec = run(w_decrypt, seconds) / MB;
    double ctrm = run(w_ctr, seconds) / MB;
    double ks = run(w_keysetup, seconds);

    printf("R = %2d | şifreleme %7.1f MB/s | çözme %7.1f MB/s | CTR %7.1f MB/s | "
           "anahtar hazırlığı %9.0f /s\n", rounds, enc, dec, ctrm, ks);

    for (size_t i = 0; i < sizeof blk; i++) sink ^= blk[i];
    for (size_t i = 0; i < CTR_BUF; i += 4096) sink ^= buf[i];
    free(buf);
    bb416_wipe(&ctx);
    return 0;
}
