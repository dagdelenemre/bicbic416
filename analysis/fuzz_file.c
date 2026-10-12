/*
 * Dosya ayrıştırıcısı için mutasyon tabanlı bulanık test (fuzz).
 * AddressSanitizer + UBSan ile derlenip çalıştırılmak üzere tasarlandı: amaç,
 * kötü niyetli/bozuk bir .bb416 dosyasının programı çökertip çökertemeyeceğini,
 * bellek hatası tetikleyip tetikleyemeyeceğini ve "sahte" bir dosyanın doğru
 * parolayla bile kabul edilip edilmeyeceğini (sahtecilik) görmek.
 *
 * Mutasyonlar: bayt çevirme, rastgele bayt yazma, kesme, uzatma, parça silme/
 * ekleme, başlık alanlarını uç değerlere ayarlama, tamamen rastgele dosyalar.
 * Not: hız için PBKDF2 yineleme alanı 64'ün üstüne çıkan mutasyonlarda eski değere
 * döndürülür (üst sınır kodda BBF_MAX_ITERS ile ayrıca korunur).
 *
 * Kullanım: fuzz_file [deneme_sayısı]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic_file.h"
#include "test_util.h"

#define DIR  "build/tmp_fuzz/"
#define SRC  DIR "kaynak.bin"
#define GOOD DIR "iyi.bb416"
#define MUT  DIR "mutant.bb416"
#define OUT  DIR "cikti.bin"

static uint8_t *read_all(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t cap = 1 << 16, n = 0, r;
    uint8_t *p = malloc(cap);
    while ((r = fread(p + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) p = realloc(p, cap *= 2);
    }
    fclose(f);
    *len = n;
    return p;
}

static void write_all(const char *path, const uint8_t *p, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (len) fwrite(p, 1, len, f);
    fclose(f);
}

int main(int argc, char **argv)
{
    long trials = argc > 1 ? atol(argv[1]) : 20000;
    tu_init("fuzz_file", 1, argv);

    uint8_t plain[3000];
    tu_randbytes(plain, sizeof plain);
    write_all(SRC, plain, sizeof plain);
    if (bbf_encrypt_file(SRC, GOOD, "fuzz-parola", 16, 8, 1) != BBF_OK) {
        printf("kaynak dosya oluşturulamadı (build/tmp_fuzz dizini var mı?)\n");
        return 1;
    }
    size_t glen;
    uint8_t *good = read_all(GOOD, &glen);
    uint8_t *m = malloc(glen * 2 + 4096);

    long accepted_modified = 0, rc_count[8] = { 0 };
    for (long t = 0; t < trials; t++) {
        size_t len = glen;
        memcpy(m, good, glen);
        int kind = (int)(tu_rand32() % 8u);
        int nmut = 1 + (int)(tu_rand32() % 4u);
        for (int k = 0; k < nmut; k++) {
            switch (kind) {
            case 0: m[tu_rand32() % len] ^= (uint8_t)(1u << (tu_rand32() & 7)); break;
            case 1: m[tu_rand32() % len] = (uint8_t)tu_rand32(); break;
            case 2: len = tu_rand32() % (len + 1); break;                          /* kes */
            case 3: { size_t add = tu_rand32() % 200; tu_randbytes(m + len, add); len += add; } break;
            case 4: if (len > 80) { size_t at = 70 + tu_rand32() % (len - 80), del = 1 + tu_rand32() % 10;
                        memmove(m + at, m + at + del, len - at - del); len -= del; } break;
            case 5: m[4 + tu_rand32() % 6] = (uint8_t)tu_rand32(); break;           /* sürüm/tur/yineleme */
            case 6: if (len >= 6) m[5] = (uint8_t)(tu_rand32() % 40); break;       /* tur: 0..39 */
            case 7: len = tu_rand32() % 300; tu_randbytes(m, len);
                    if (len >= 4 && (tu_rand32() & 1)) memcpy(m, "BB41", 4); break; /* çöp dosya */
            }
        }
        /* Yineleme alanını fuzz hızı için sınırla. */
        if (len >= 10) {
            uint32_t it = (uint32_t)m[6] | (uint32_t)m[7] << 8 | (uint32_t)m[8] << 16 | (uint32_t)m[9] << 24;
            if (it > 64 && it <= 10000000u) memcpy(m + 6, good + 6, 4);
        }
        int same = len == glen && memcmp(m, good, glen) == 0;
        write_all(MUT, m, len);

        bbf_info info;
        (void)bbf_read_info(MUT, &info);
        int rc = bbf_decrypt_file(MUT, OUT, "fuzz-parola", 1);
        rc_count[rc >= 0 && rc < 8 ? rc : 7]++;
        if (rc == BBF_OK && !same) {
            accepted_modified++;
            printf("SAHTECİLİK: değiştirilmiş dosya kabul edildi (deneme %ld, tür %d)\n", t, kind);
        }
        if (rc == BBF_OK && same) {
            size_t ol;
            uint8_t *o = read_all(OUT, &ol);
            if (ol != sizeof plain || memcmp(o, plain, ol) != 0)
                printf("HATA: değişmemiş dosya yanlış çözüldü\n"), accepted_modified++;
            free(o);
        }
    }
    printf("%ld mutant dosya: tamam=%ld (değişmemiş), doğrulama hatası=%ld, biçim hatası=%ld, G/Ç=%ld\n",
           trials, rc_count[BBF_OK], rc_count[BBF_ERR_AUTH], rc_count[BBF_ERR_FORMAT], rc_count[BBF_ERR_IO]);
    printf("Kabul edilen değiştirilmiş dosya: %ld → %s\n", accepted_modified,
           accepted_modified ? "BAŞARISIZ" : "TAMAM (çökme/bellek hatası olsaydı ASan programı durdururdu)");
    remove(SRC); remove(GOOD); remove(MUT); remove(OUT);
    free(good); free(m);
    return accepted_modified != 0;
}
