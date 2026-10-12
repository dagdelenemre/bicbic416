/*
 * Kayıt biçimi (SPEC.md §14) ve BicBic-Hash için ortak test vektörlerini üretir:
 *   tests/data/record_vectors.json
 * Python paketi ve JavaScript uygulaması bu dosyadaki her kaydı aynen üretmeli ve
 * açabilmeli; C testi (test_record) de dosyanın bu programın çıktısıyla aynı olduğunu
 * doğrular. Kullanım: make vectors
 */
#include <stdio.h>
#include <string.h>

#include "bicbic_record.h"

static void hex(FILE *f, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", p[i]);
}

typedef struct { int key; uint8_t n0; const char *aad, *msg; size_t pattern_len; } spec;

static const spec SPECS[] = {
    { 0, 0xa0, "", "", 0 },
    { 0, 0xb0, "", "abc", 0 },
    { 0, 0xc0, "2026-10-13T10:00:00Z web-1",
      "{\"olay\":\"giris\",\"kullanici\":\"ayşe@ornek.org\",\"ip\":\"203.0.113.7\"}", 0 },
    { 0, 0xd0, "", NULL, 1000 },
    { 1, 0x00, "alan=e_posta", "ikinci anahtarla şifrelenmiş kayıt", 0 },
};

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "tests/data/record_vectors.json";
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }

    uint8_t masters[2][BBR_KEY_BYTES];
    for (int i = 0; i < BBR_KEY_BYTES; i++) {
        masters[0][i] = (uint8_t)i;
        masters[1][i] = (uint8_t)(0xff - i);
    }
    static uint8_t msg[1000], out[1000 + BBR_OVERHEAD];
    static char text[2000];

    fprintf(f, "{\n  \"aciklama\": \"BicBic416 kayit bicimi v1 test vektorleri (SPEC.md 14). "
               "Uretici: tests/gen_record_vectors.c\",\n  \"kayitlar\": [\n");
    for (size_t v = 0; v < sizeof SPECS / sizeof SPECS[0]; v++) {
        const spec *s = &SPECS[v];
        bbr_key k;
        bbr_key_init(&k, masters[s->key]);
        uint8_t nonce[BBR_NONCE_BYTES];
        for (int i = 0; i < BBR_NONCE_BYTES; i++) nonce[i] = (uint8_t)(s->n0 + i);
        size_t len;
        if (s->msg) {
            len = strlen(s->msg);
            memcpy(msg, s->msg, len);
        } else {
            len = s->pattern_len;
            for (size_t i = 0; i < len; i++) msg[i] = (uint8_t)(i * 7 + 3);
        }
        size_t out_len;
        bbr_encrypt_with_nonce(&k, nonce, msg, len, (const uint8_t *)s->aad, strlen(s->aad), out, &out_len);
        memcpy(text, BBR_TEXT_PREFIX, 8);
        text[8 + bbr_b64url_encode(out, out_len, text + 8)] = 0;
        char ktext[64];
        bbr_key_to_text(masters[s->key], ktext, sizeof ktext);

        fprintf(f, "    {\n      \"anahtar\": \"%s\",\n      \"kimlik\": \"", ktext);
        hex(f, k.kid, BBR_KID_BYTES);
        fprintf(f, "\",\n      \"nonce\": \"");
        hex(f, nonce, sizeof nonce);
        fprintf(f, "\",\n      \"ek_hex\": \"");
        hex(f, (const uint8_t *)s->aad, strlen(s->aad));
        fprintf(f, "\",\n      \"mesaj_hex\": \"");
        hex(f, msg, len);
        fprintf(f, "\",\n      \"kayit\": \"%s\"\n    }%s\n", text,
                v + 1 < sizeof SPECS / sizeof SPECS[0] ? "," : "");
        bbr_key_wipe(&k);
    }
    fprintf(f, "  ],\n  \"hashler\": [\n");
    static const char *hmsgs[] = { "", "abc", "BicBic416", "Merhaba dünya, ğüşıöç İĞÜŞÖÇ", NULL };
    for (int h = 0; h < 5; h++) {
        size_t len;
        if (hmsgs[h]) {
            len = strlen(hmsgs[h]);
            memcpy(msg, hmsgs[h], len);
        } else {
            len = 1000;
            for (size_t i = 0; i < len; i++) msg[i] = (uint8_t)(i * 7 + 3);
        }
        uint8_t d[BB416_HASH_BYTES];
        bb416_hash(msg, len, d);
        fprintf(f, "    { \"mesaj_hex\": \"");
        hex(f, msg, len);
        fprintf(f, "\", \"hash\": \"");
        hex(f, d, sizeof d);
        fprintf(f, "\" }%s\n", h < 4 ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
    printf("yazıldı: %s\n", path);
    return 0;
}
