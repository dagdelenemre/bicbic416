/*
 * SOC / log senaryosu hız ölçümü.
 *
 * Her log kaydı ayrı ayrı korunur (bir kayıt bozulsa diğerleri okunabilir kalır):
 *   nonce  = oturum öneki (36 bayt, oturum başında bir kez rastgele) || sıra no (8 bayt)
 *   şifreli = BicBic416-CTR(enc_anahtar, nonce, sayaç 0, kayıt)
 *   etiket = HMAC-SHA256(mac_anahtar, sıra no || şifreli)   → kayıt değiştirilirse/silinirse/
 *                                                              sırası değişirse fark edilir
 * Sıra numarası her kayıtta farklı olduğundan nonce asla tekrarlanmaz ve kayıt başına
 * işletim sisteminden rastgele sayı istemeye gerek kalmaz.
 *
 * Ölçülenler: kayıt/saniye, MB/s, kayıt başına ortalama ve %99 gecikme (mikrosaniye),
 * hem şifreleme+mühürleme hem doğrulama+çözme için.
 *
 * Kullanım: bench_log [tur sayısı] [kayıt sayısı]
 */
#if !defined(_WIN32)
#  define _POSIX_C_SOURCE 200809L /* clock_gettime: katı C11 modunda görünür olsun */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"
#include "sha256.h"

#if defined(_WIN32)
#  include <windows.h>
static double now_us(void)
{
    static LARGE_INTEGER f;
    LARGE_INTEGER c;
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1e6 / (double)f.QuadPart;
}
#else
#  include <time.h>
static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}
#endif

#define MAXREC 2048

/* Gerçekçi görünen log satırları (syslog/JSON benzeri), 80..1500 bayt. */
static size_t make_log(char *out, unsigned long i)
{
    static const char *src[] = { "fw-01", "dc-02", "web-proxy", "edr-agent", "vpn-gw" };
    static const char *msg[] = {
        "kullanici girisi basarili",
        "basarisiz parola denemesi",
        "engellenen baglanti 10.0.%lu.%lu:445",
        "supheli surec: powershell -enc ...",
        "DNS sorgusu: guncelleme.ornek.com.tr",
    };
    int n = snprintf(out, MAXREC,
        "{\"zaman\":\"2026-10-12T21:%02lu:%02lu.%03luZ\",\"kaynak\":\"%s\",\"olay_id\":%lu,"
        "\"seviye\":\"%s\",\"mesaj\":\"",
        (i / 60000) % 60, (i / 1000) % 60, i % 1000, src[i % 5], 4624 + i % 50,
        (i % 7) ? "bilgi" : "uyari");
    n += snprintf(out + n, MAXREC - (size_t)n, msg[i % 5], i % 255, (i * 7) % 255);
    /* Değişken uzunluklu ek alan: ortalama ~400 bayt, bazen 1500'e kadar. */
    size_t extra = (i % 10 == 0) ? 1100 : (i * 2654435761u) % 300;
    out[n++] = ' ';
    for (size_t k = 0; k < extra && (size_t)n < MAXREC - 4; k++)
        out[n++] = (char)('a' + (i + k) % 26);
    n += snprintf(out + n, MAXREC - (size_t)n, "\"}");
    return (size_t)n;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 16;
    long N = argc > 2 ? atol(argv[2]) : 300000;

    static bb416_ctx ctx;
    uint8_t key[BB416_KEY_BYTES], mac_key[32], nonce[BB416_NONCE_BYTES];
    for (int i = 0; i < BB416_KEY_BYTES; i++) key[i] = (uint8_t)(i * 31 + 7);
    for (int i = 0; i < 32; i++) mac_key[i] = (uint8_t)(i * 17 + 5);
    for (int i = 0; i < 36; i++) nonce[i] = (uint8_t)(i * 11 + 3);
    if (bb416_init(&ctx, key, rounds) != BB416_OK) return 1;

    /* Kayıtları önceden üret: ölçüm yalnızca kripto işini içersin. */
    char *logs = malloc((size_t)N * MAXREC);
    size_t *len = malloc((size_t)N * sizeof *len);
    uint8_t *ct = malloc((size_t)N * MAXREC), (*tag)[32] = malloc((size_t)N * 32);
    double *lat = malloc((size_t)N * sizeof *lat);
    if (!logs || !len || !ct || !tag || !lat) return 1;
    double total_bytes = 0;
    for (long i = 0; i < N; i++) {
        len[i] = make_log(logs + (size_t)i * MAXREC, (unsigned long)i);
        total_bytes += (double)len[i];
    }

    hmac_sha256_ctx base, h;
    hmac_sha256_init(&base, mac_key, sizeof mac_key);

    /* --- şifrele + mühürle --- */
    double t0 = now_us();
    for (long i = 0; i < N; i++) {
        double a = now_us();
        uint8_t seq[8];
        for (int b = 0; b < 8; b++) seq[b] = (uint8_t)((uint64_t)i >> (8 * b));
        memcpy(nonce + 36, seq, 8);
        bb416_ctr_xor(&ctx, nonce, 0, (const uint8_t *)logs + (size_t)i * MAXREC,
                     ct + (size_t)i * MAXREC, len[i]);
        h = base;
        hmac_sha256_update(&h, seq, 8);
        hmac_sha256_update(&h, ct + (size_t)i * MAXREC, len[i]);
        hmac_sha256_final(&h, tag[i]);
        lat[i] = now_us() - a;
    }
    double t_enc = now_us() - t0;
    qsort(lat, (size_t)N, sizeof *lat, cmp_double);
    double p50e = lat[N / 2], p99e = lat[N * 99 / 100];

    /* --- doğrula + çöz --- */
    long bad = 0;
    uint8_t out[MAXREC];
    t0 = now_us();
    for (long i = 0; i < N; i++) {
        double a = now_us();
        uint8_t seq[8], t[32];
        for (int b = 0; b < 8; b++) seq[b] = (uint8_t)((uint64_t)i >> (8 * b));
        h = base;
        hmac_sha256_update(&h, seq, 8);
        hmac_sha256_update(&h, ct + (size_t)i * MAXREC, len[i]);
        hmac_sha256_final(&h, t);
        if (ct_memcmp(t, tag[i], 32) != 0) { bad++; continue; }
        memcpy(nonce + 36, seq, 8);
        bb416_ctr_xor(&ctx, nonce, 0, ct + (size_t)i * MAXREC, out, len[i]);
        bad += memcmp(out, logs + (size_t)i * MAXREC, len[i]) != 0;
        lat[i] = now_us() - a;
    }
    double t_dec = now_us() - t0;
    qsort(lat, (size_t)N, sizeof *lat, cmp_double);

    printf("R = %d, %ld kayıt, ortalama kayıt %.0f bayt\n", rounds, N, total_bytes / N);
    printf("  şifrele+mühürle : %8.0f kayıt/s  %6.1f MB/s  gecikme ort. %5.2f µs, medyan %5.2f µs, %%99 %5.2f µs\n",
           N / (t_enc / 1e6), total_bytes / t_enc, t_enc / N, p50e, p99e);
    printf("  doğrula+çöz     : %8.0f kayıt/s  %6.1f MB/s  gecikme ort. %5.2f µs, medyan %5.2f µs, %%99 %5.2f µs\n",
           N / (t_dec / 1e6), total_bytes / t_dec, t_dec / N, lat[N / 2], lat[N * 99 / 100]);
    printf("  hatalı kayıt: %ld\n", bad);

    free(logs); free(len); free(ct); free(tag); free(lat);
    bb416_wipe(&ctx);
    return bad != 0;
}
