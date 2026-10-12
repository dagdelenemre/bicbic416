/*
 * Dosya aracı (tool/bicbic_file.c) testleri:
 *  - tek ve iki katmanlı modda farklı boyutlarda şifrele → çöz → aynı dosya
 *  - yanlış parola, değiştirilmiş başlık/veri/etiket, kesilmiş/uzatılmış dosya →
 *    reddedilir, çıktı dosyası oluşturulmaz (katman bayrağıyla oynamak dahil)
 *  - dosya iki çözme geçişi arasında değiştirilirse (TOCTOU) çıktı oluşmaz
 *  - aynı parolayla iki şifreleme farklı çıktı verir (rastgele tuz)
 *  - sürüm 1 biçimindeki örnek dosya (tests/data) hâlâ açılır
 *  - üzerine yazma koruması, geçersiz parametreler
 * Hız için düşük PBKDF2 yineleme sayısı kullanılır.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../tool/bicbic_file.h"
#include "test_util.h"

#define DIR   "build/tmp_test_file/"
#define PLAIN DIR "duz.bin"
#define ENC   DIR "sifreli.bb416"
#define DEC   DIR "cozulmus.bin"
#define ITERS 1000u
#define H     BBF_V2_HEADER_BYTES
#define T     BBF_V2_TAG_BYTES

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
    if (len) CHECK(fwrite(p, 1, len, f) == len);
    fclose(f);
}

static int exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f) fclose(f);
    return f != NULL;
}

static void test_roundtrip_sizes(void)
{
    /* Blok (52, 64) ve parça (64 896) sınırlarının çevresi dahil. */
    static const size_t sizes[] = { 0, 1, 51, 52, 53, 63, 64, 65, 1000, 64895, 64896, 64897,
                                    200000, 3000017 };
    for (int layers = 1; layers <= 2; layers++) {
        for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
            size_t n = sizes[k], m = 0, e = 0;
            uint8_t *p = malloc(n ? n : 1);
            tu_randbytes(p, n);
            write_all(PLAIN, p, n);

            int rounds = (k & 1) ? 8 : 16;
            CHECK(bbf_encrypt_file(PLAIN, ENC, "doğru parola ğüşıöç", rounds, ITERS, layers, 1) == BBF_OK);
            uint8_t *c = read_all(ENC, &e);
            CHECK(e == n + H + T); /* ek yük: 36 bayt */
            CHECK(c[0] == BBF_V2_FORMAT);
            if (n >= 16) CHECK(memcmp(c + H, p, 16) != 0);

            bbf_info info;
            CHECK(bbf_read_info(ENC, &info) == BBF_OK);
            CHECK(info.version == 2 && info.layers == layers && info.rounds == rounds &&
                  info.iterations == ITERS && info.data_bytes == n);

            CHECK(bbf_decrypt_file(ENC, DEC, "doğru parola ğüşıöç", 1) == BBF_OK);
            uint8_t *d = read_all(DEC, &m);
            CHECK(m == n && (n == 0 || memcmp(d, p, n) == 0));
            free(p); free(c); free(d);
        }
    }
}

/* Her türlü bozulma reddedilmeli ve çıktı dosyası hiç oluşmamalı. */
static void test_tamper(int layers)
{
    size_t n = 5000, e;
    uint8_t *p = malloc(n);
    tu_randbytes(p, n);
    write_all(PLAIN, p, n);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "parola123", 16, ITERS, layers, 1) == BBF_OK);
    uint8_t *orig = read_all(ENC, &e);

    remove(DEC);
    CHECK(bbf_decrypt_file(ENC, DEC, "parola124", 0) == BBF_ERR_AUTH);
    CHECK(!exists(DEC));

    /* (konum, XOR maskesi): biçim, tur (16 → 8), katman bayrağı, yineleme, tuz, veri, etiket. */
    const struct { size_t at; uint8_t mask; } spots[] = {
        { 0, 0x01 }, { 1, 0x18 }, { 1, 0x40 }, { 1, 0x80 }, { 2, 0x01 }, { 3, 0x01 },
        { 4, 0x01 }, { H - 1, 0x80 }, { H, 0x01 }, { H + 1, 0x01 }, { H + 2500, 0x01 },
        { e - T - 1, 0x01 }, { e - T, 0x01 }, { e - 1, 0x80 },
    };
    for (size_t s = 0; s < sizeof spots / sizeof spots[0]; s++) {
        uint8_t *t = malloc(e);
        memcpy(t, orig, e);
        t[spots[s].at] ^= spots[s].mask;
        write_all(ENC, t, e);
        int rc = bbf_decrypt_file(ENC, DEC, "parola123", 0);
        CHECK(rc == BBF_ERR_AUTH || rc == BBF_ERR_FORMAT);
        CHECK(!exists(DEC));
        free(t);
    }

    /* Kesilmiş dosyalar. */
    const size_t cuts[] = { 0, 1, 3, H - 1, H, H + T - 1, H + T, e - 1 };
    for (size_t s = 0; s < sizeof cuts / sizeof cuts[0]; s++) {
        write_all(ENC, orig, cuts[s]);
        int rc = bbf_decrypt_file(ENC, DEC, "parola123", 0);
        CHECK(rc == BBF_ERR_AUTH || rc == BBF_ERR_FORMAT);
        CHECK(!exists(DEC));
    }

    /* Sona bayt eklenmesi. */
    uint8_t *longer = malloc(e + 1);
    memcpy(longer, orig, e);
    longer[e] = 0;
    write_all(ENC, longer, e + 1);
    CHECK(bbf_decrypt_file(ENC, DEC, "parola123", 0) == BBF_ERR_AUTH);
    CHECK(!exists(DEC));

    free(p); free(orig); free(longer);
}

/* TOCTOU: dosya doğrulandıktan sonra, çözülmeden önce değiştirilirse çıktı oluşmamalı.
 * (Windows'ta açık dosyaya başka tanıtıcıdan yazmak mümkündür; "r+b" ile yapılır.) */
static void flip_ciphertext_byte(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f) return;
    fseek(f, H + 10, SEEK_SET);
    int c = fgetc(f);
    fseek(f, H + 10, SEEK_SET);
    fputc(c ^ 0x01, f);
    fclose(f);
}

static void test_toctou(void)
{
    uint8_t p[1000];
    tu_randbytes(p, sizeof p);
    write_all(PLAIN, p, sizeof p);
    for (int layers = 1; layers <= 2; layers++) {
        CHECK(bbf_encrypt_file(PLAIN, ENC, "parola", 16, ITERS, layers, 1) == BBF_OK);
        remove(DEC);
        bbf_test_between_passes = flip_ciphertext_byte;
        CHECK(bbf_decrypt_file(ENC, DEC, "parola", 0) == BBF_ERR_AUTH);
        bbf_test_between_passes = NULL;
        CHECK(!exists(DEC));
    }
}

static void test_randomized_output(void)
{
    size_t a_len, b_len;
    write_all(PLAIN, (const uint8_t *)"ayni metin", 10);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, ITERS, 1, 1) == BBF_OK);
    uint8_t *a = read_all(ENC, &a_len);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, ITERS, 1, 1) == BBF_OK);
    uint8_t *b = read_all(ENC, &b_len);
    CHECK(a_len == b_len && memcmp(a + 4, b + 4, a_len - 4) != 0);
    free(a); free(b);
}

/* Sürüm 1 biçiminde (v0.1.0 ile) oluşturulmuş örnek dosya açılmaya devam etmeli. */
static void test_v1_compat(void)
{
    const char *v1 = "tests/data/v1_ornek.bb416", *expect = "tests/data/v1_ornek.txt";
    bbf_info info;
    CHECK(bbf_read_info(v1, &info) == BBF_OK);
    CHECK(info.version == 1 && info.layers == 1 && info.rounds == 16 && info.iterations == 1000);

    size_t a_len = 0, b_len = 0, e;
    CHECK(bbf_decrypt_file(v1, DEC, "v1-ornek-parola", 1) == BBF_OK);
    uint8_t *a = read_all(DEC, &a_len), *b = read_all(expect, &b_len);
    CHECK(a && b && a_len == b_len && memcmp(a, b, a_len) == 0);
    free(a); free(b);

    remove(DEC);
    CHECK(bbf_decrypt_file(v1, DEC, "yanlis-parola", 0) == BBF_ERR_AUTH);
    uint8_t *t = read_all(v1, &e);
    t[BBF_V1_HEADER_BYTES + 3] ^= 1;
    write_all(ENC, t, e);
    CHECK(bbf_decrypt_file(ENC, DEC, "v1-ornek-parola", 0) == BBF_ERR_AUTH);
    CHECK(!exists(DEC));
    free(t);
}

static void test_params(void)
{
    write_all(PLAIN, (const uint8_t *)"x", 1);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 0, ITERS, 1, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 33, ITERS, 1, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, 0, 1, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, 999, 1, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, 1500, 1, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, BBF_MAX_ITERS + 1000, 1, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, ITERS, 0, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, ITERS, 3, 1) == BBF_ERR_PARAM);
    CHECK(bbf_encrypt_file(DIR "yok.bin", ENC, "p", 16, ITERS, 1, 1) == BBF_ERR_IO);

    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, ITERS, 1, 1) == BBF_OK);
    CHECK(bbf_encrypt_file(PLAIN, ENC, "p", 16, ITERS, 1, 0) == BBF_ERR_EXISTS);
    write_all(DEC, (const uint8_t *)"eski", 4);
    CHECK(bbf_decrypt_file(ENC, DEC, "p", 0) == BBF_ERR_EXISTS);
    CHECK(bbf_decrypt_file(ENC, DEC, "p", 1) == BBF_OK);

    write_all(ENC, (const uint8_t *)"bu bir BicBic416 dosyasi degil ama yeterince uzun bir metin......."
                                    "..........................................", 100);
    CHECK(bbf_decrypt_file(ENC, DEC, "p", 1) == BBF_ERR_FORMAT);
}

int main(int argc, char **argv)
{
    tu_init("test_file", argc, argv);
    test_roundtrip_sizes();
    test_tamper(1);
    test_tamper(2);
    test_toctou();
    test_randomized_output();
    test_v1_compat();
    test_params();
    remove(PLAIN); remove(ENC); remove(DEC);
    return tu_finish("test_file");
}
