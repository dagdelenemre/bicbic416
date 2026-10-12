/*
 * Dosya ayrıştırıcısı için mutasyon tabanlı bulanık test (fuzz).
 * AddressSanitizer + UBSan ile derlenip çalıştırılmak üzere tasarlandı: amaç,
 * kötü niyetli/bozuk bir .bb416 dosyasının programı çökertip çökertemeyeceğini,
 * bellek hatası tetikleyip tetikleyemeyeceğini ve "sahte" bir dosyanın doğru
 * parolayla bile kabul edilip edilmeyeceğini (sahtecilik) görmek.
 *
 * Mutasyonlar: bayt çevirme, rastgele bayt yazma, kesme, uzatma, parça silme/
 * ekleme, başlık alanlarını uç değerlere ayarlama, tamamen rastgele dosyalar.
 * Üç kaynak dosya mutasyona uğratılır: sürüm 2 tek katman, sürüm 2 iki katman ve
 * sürüm 1 örnek dosyası (tests/data). Not: hız için PBKDF2 yineleme alanı en küçük
 * değerin üstüne çıkan mutasyonlarda en küçük değere çekilir (üst sınır kodda
 * BBF_MAX_ITERS ile ayrıca korunur).
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
#define MUT  DIR "mutant.bb416"
#define OUT  DIR "cikti.bin"

static uint8_t *read_all(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
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

typedef struct {
    const char *name, *password;
    uint8_t *file, *plain;
    size_t file_len, plain_len;
} base;

int main(int argc, char **argv)
{
    long trials = argc > 1 ? atol(argv[1]) : 20000;
    tu_init("fuzz_file", 1, argv);

    static uint8_t plain[3000];
    tu_randbytes(plain, sizeof plain);
    write_all(SRC, plain, sizeof plain);

    /* Kaynak 0: v2 tek katman, 1: v2 iki katman, 2: v1 örnek dosyası. */
    base bases[3] = {
        { "v2 tek katman", "fuzz-parola", NULL, plain, 0, sizeof plain },
        { "v2 iki katman", "fuzz-parola", NULL, plain, 0, sizeof plain },
        { "v1", "v1-ornek-parola", NULL, NULL, 0, 0 },
    };
    for (int layers = 1; layers <= 2; layers++) {
        const char *path = DIR "kaynak.bb416";
        if (bbf_encrypt_file(SRC, path, "fuzz-parola", 16, 1000, layers, 1) != BBF_OK) {
            printf("kaynak dosya oluşturulamadı (build/tmp_fuzz dizini var mı?)\n");
            return 1;
        }
        bases[layers - 1].file = read_all(path, &bases[layers - 1].file_len);
        remove(path);
    }
    bases[2].file = read_all("tests/data/v1_ornek.bb416", &bases[2].file_len);
    bases[2].plain = read_all("tests/data/v1_ornek.txt", &bases[2].plain_len);
    for (int b = 0; b < 3; b++) {
        if (!bases[b].file || !bases[b].plain) {
            printf("kaynak okunamadı: %s (depo kökünden çalıştırın)\n", bases[b].name);
            return 1;
        }
    }

    uint8_t *m = malloc(1 << 16);
    long accepted_modified = 0, rc_count[8] = { 0 }, per_base[3] = { 0 };
    for (long t = 0; t < trials; t++) {
        int bi = (int)(tu_rand32() % 3u);
        const base *B = &bases[bi];
        per_base[bi]++;
        size_t len = B->file_len;
        memcpy(m, B->file, len);
        size_t hdr = m[0] == 0xB2 ? BBF_V2_HEADER_BYTES : BBF_V1_HEADER_BYTES;
        int kind = (int)(tu_rand32() % 8u);
        int nmut = 1 + (int)(tu_rand32() % 4u);
        for (int k = 0; k < nmut; k++) {
            switch (kind) {
            case 0: if (len) m[tu_rand32() % len] ^= (uint8_t)(1u << (tu_rand32() & 7)); break;
            case 1: if (len) m[tu_rand32() % len] = (uint8_t)tu_rand32(); break;
            case 2: len = tu_rand32() % (len + 1); break;                              /* kes */
            case 3: { size_t add = tu_rand32() % 200; tu_randbytes(m + len, add); len += add; } break;
            case 4: if (len > hdr + 10) { size_t at = hdr + tu_rand32() % (len - hdr - 10),
                        del = 1 + tu_rand32() % 10;
                        memmove(m + at, m + at + del, len - at - del); len -= del; } break;
            case 5: if (len > hdr) m[tu_rand32() % hdr] = (uint8_t)tu_rand32(); break; /* başlık */
            case 6: if (len > 1) m[1] = (uint8_t)tu_rand32(); break;                  /* v2: tur/katman */
            case 7: len = tu_rand32() % 300; tu_randbytes(m, len);                   /* çöp dosya */
                    if (len >= 1 && (tu_rand32() & 1)) m[0] = 0xB2;
                    else if (len >= 4 && (tu_rand32() & 1)) memcpy(m, "BB41", 4);
                    break;
            }
        }
        /* Yineleme alanını fuzz hızı için en küçük değere çek. */
        if (len >= 4 && m[0] == 0xB2 && (m[2] | m[3] << 8) > 1) { m[2] = 1; m[3] = 0; }
        if (len >= 10 && m[0] == 'B') {
            uint32_t it = (uint32_t)m[6] | (uint32_t)m[7] << 8 | (uint32_t)m[8] << 16 | (uint32_t)m[9] << 24;
            if (it > 1000 && it <= 10000000u) { m[6] = 0xE8; m[7] = 0x03; m[8] = 0; m[9] = 0; }
        }
        int same = len == B->file_len && memcmp(m, B->file, len) == 0;
        write_all(MUT, m, len);

        bbf_info info;
        (void)bbf_read_info(MUT, &info);
        int rc = bbf_decrypt_file(MUT, OUT, B->password, 1);
        rc_count[rc >= 0 && rc < 8 ? rc : 7]++;
        if (rc == BBF_OK && !same) {
            accepted_modified++;
            printf("SAHTECİLİK: değiştirilmiş dosya kabul edildi (deneme %ld, kaynak %s, tür %d)\n",
                   t, B->name, kind);
        }
        if (rc == BBF_OK && same) {
            size_t ol;
            uint8_t *o = read_all(OUT, &ol);
            if (ol != B->plain_len || memcmp(o, B->plain, ol) != 0)
                printf("HATA: değişmemiş dosya yanlış çözüldü (%s)\n", B->name), accepted_modified++;
            free(o);
        }
    }
    printf("%ld mutant dosya (v2 tek: %ld, v2 iki: %ld, v1: %ld)\n", trials, per_base[0], per_base[1], per_base[2]);
    printf("  tamam=%ld (değişmemiş), doğrulama hatası=%ld, biçim hatası=%ld, G/Ç=%ld\n",
           rc_count[BBF_OK], rc_count[BBF_ERR_AUTH], rc_count[BBF_ERR_FORMAT], rc_count[BBF_ERR_IO]);
    printf("Kabul edilen değiştirilmiş dosya: %ld → %s\n", accepted_modified,
           accepted_modified ? "BAŞARISIZ" : "TAMAM (çökme/bellek hatası olsaydı ASan programı durdururdu)");
    remove(SRC); remove(MUT); remove(OUT);
    for (int b = 0; b < 3; b++) { free(bases[b].file); if (b == 2) free(bases[b].plain); }
    free(m);
    return accepted_modified != 0;
}
