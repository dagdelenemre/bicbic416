/*
 * Kayıt biçimi (tool/bicbic_record.c, SPEC.md §14) testleri:
 *  - ortak test vektörleri (tests/data/record_vectors.json) bu uygulamanın çıktısıyla aynı
 *  - ikili ve metin biçiminde gidiş-dönüş (0..3000 bayt, ekli/eksiz)
 *  - kaydın her baytı değiştirilince ve ek bilgi değişince reddedilir
 *  - yanlış anahtar BBR_ERR_KEY, kimlik okuma, anahtar metni
 *  - base64url: kanonik olmayan ve geçersiz girdiler reddedilir
 *  - aynı mesaj iki kez şifrelenince farklı kayıt (rastgele N)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../tool/bicbic_record.h"
#include "test_util.h"

static char *read_text(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *s = malloc((size_t)n + 1);
    size_t r = fread(s, 1, (size_t)n, f);
    s[r] = 0;
    fclose(f);
    return s;
}

/* Vektör dosyası bu kodla yeniden üretildiğinde aynı çıkmalı: dosyadaki her kayıt
 * için anahtar/nonce/ek/mesajı okuyup kaydı yeniden üretiriz. */
static size_t unhex(const char *h, uint8_t *out)
{
    size_t n = 0;
    while (h[0] && h[0] != '"' && h[1]) {
        unsigned v;
        sscanf(h, "%2x", &v);
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static const char *field(const char *from, const char *name)
{
    const char *p = strstr(from, name);
    return p ? strchr(p + strlen(name), '"') + 1 : NULL;
}

static void test_vectors(void)
{
    char *json = read_text("tests/data/record_vectors.json");
    CHECK(json != NULL);
    if (!json) return;
    static uint8_t msg[4000], aad[256], nonce[64], bin[5000], dec[5000];
    static char text[8000];
    int count = 0;
    for (const char *p = strstr(json, "\"anahtar\""); p; p = strstr(p + 1, "\"anahtar\"")) {
        const char *kt = field(p, "\"anahtar\":"), *kid = field(p, "\"kimlik\":"),
                   *nh = field(p, "\"nonce\":"), *ah = field(p, "\"ek_hex\":"),
                   *mh = field(p, "\"mesaj_hex\":"), *rec = field(p, "\"kayit\":");
        char keytext[64];
        size_t klen = (size_t)(strchr(kt, '"') - kt);
        memcpy(keytext, kt, klen);
        keytext[klen] = 0;

        uint8_t master[BBR_KEY_BYTES], kidb[4];
        CHECK(bbr_key_from_text(keytext, master) == BBR_OK);
        bbr_key k;
        bbr_key_init(&k, master);
        unhex(kid, kidb);
        CHECK(memcmp(k.kid, kidb, 4) == 0);

        unhex(nh, nonce);
        size_t alen = unhex(ah, aad), mlen = unhex(mh, msg), blen;
        CHECK(bbr_encrypt_with_nonce(&k, nonce, msg, mlen, aad, alen, bin, &blen) == BBR_OK);
        memcpy(text, BBR_TEXT_PREFIX, 8);
        text[8 + bbr_b64url_encode(bin, blen, text + 8)] = 0;
        size_t rlen = (size_t)(strchr(rec, '"') - rec);
        CHECK(rlen == strlen(text) && memcmp(rec, text, rlen) == 0);

        size_t dlen;
        CHECK(bbr_decrypt_text(&k, rec, rlen, aad, alen, dec, sizeof dec, &dlen) == BBR_OK);
        CHECK(dlen == mlen && memcmp(dec, msg, mlen) == 0);
        bbr_key_wipe(&k);
        count++;
    }
    CHECK(count == 5);
    free(json);
}

static void test_roundtrip(void)
{
    static uint8_t msg[3000], aad[100], bin[3000 + BBR_OVERHEAD], dec[3000];
    static char text[5000];
    uint8_t master[BBR_KEY_BYTES];
    for (int t = 0; t < 400; t++) {
        tu_randbytes(master, sizeof master);
        bbr_key k;
        bbr_key_init(&k, master);
        size_t len = (t < 60) ? (size_t)t : tu_rand32() % sizeof msg;
        size_t alen = (t & 1) ? tu_rand32() % sizeof aad : 0;
        tu_randbytes(msg, len);
        tu_randbytes(aad, alen);

        size_t blen, dlen;
        CHECK(bbr_encrypt(&k, msg, len, aad, alen, bin, &blen) == BBR_OK);
        CHECK(blen == len + BBR_OVERHEAD);
        CHECK(bbr_decrypt(&k, bin, blen, aad, alen, dec, &dlen) == BBR_OK);
        CHECK(dlen == len && memcmp(dec, msg, len) == 0);

        CHECK(bbr_encrypt_text(&k, msg, len, aad, alen, text, sizeof text) == BBR_OK);
        CHECK(strlen(text) + 1 == bbr_text_len(len));
        CHECK(bbr_decrypt_text(&k, text, strlen(text), aad, alen, dec, sizeof dec, &dlen) == BBR_OK);
        CHECK(dlen == len && memcmp(dec, msg, len) == 0);

        uint8_t kid[4];
        CHECK(bbr_text_kid(text, strlen(text), kid) == BBR_OK && memcmp(kid, k.kid, 4) == 0);
        bbr_key_wipe(&k);
    }
}

static void test_tamper(void)
{
    uint8_t master[BBR_KEY_BYTES], other[BBR_KEY_BYTES], bin[200], t[200], dec[200];
    const uint8_t msg[] = "kullanici=ayse ip=203.0.113.7", aad[] = "web-1";
    tu_randbytes(master, sizeof master);
    tu_randbytes(other, sizeof other);
    bbr_key k, k2;
    bbr_key_init(&k, master);
    bbr_key_init(&k2, other);
    size_t blen, dlen;
    CHECK(bbr_encrypt(&k, msg, sizeof msg - 1, aad, sizeof aad - 1, bin, &blen) == BBR_OK);

    /* Her baytın her biti: biçim → FORMAT, kimlik → KEY, gerisi → AUTH. */
    for (size_t i = 0; i < blen; i++) {
        for (int b = 0; b < 8; b++) {
            memcpy(t, bin, blen);
            t[i] ^= (uint8_t)(1u << b);
            int rc = bbr_decrypt(&k, t, blen, aad, sizeof aad - 1, dec, &dlen);
            int expect = i == 0 ? BBR_ERR_FORMAT : i < 1 + BBR_KID_BYTES ? BBR_ERR_KEY : BBR_ERR_AUTH;
            CHECK(rc == expect);
        }
    }
    CHECK(bbr_decrypt(&k, bin, blen, (const uint8_t *)"web-2", 5, dec, &dlen) == BBR_ERR_AUTH);
    CHECK(bbr_decrypt(&k, bin, blen, NULL, 0, dec, &dlen) == BBR_ERR_AUTH);
    CHECK(bbr_decrypt(&k2, bin, blen, aad, sizeof aad - 1, dec, &dlen) == BBR_ERR_KEY);
    CHECK(bbr_decrypt(&k, bin, blen - 1, aad, sizeof aad - 1, dec, &dlen) == BBR_ERR_AUTH);
    CHECK(bbr_decrypt(&k, bin, BBR_OVERHEAD - 1, aad, sizeof aad - 1, dec, &dlen) == BBR_ERR_FORMAT);

    /* Aynı mesaj iki kez → farklı kayıt. */
    uint8_t bin2[200];
    size_t blen2;
    CHECK(bbr_encrypt(&k, msg, sizeof msg - 1, aad, sizeof aad - 1, bin2, &blen2) == BBR_OK);
    CHECK(blen2 == blen && memcmp(bin, bin2, blen) != 0);
    bbr_key_wipe(&k);
    bbr_key_wipe(&k2);
}

static void test_text_and_keys(void)
{
    uint8_t master[BBR_KEY_BYTES], back[BBR_KEY_BYTES], dec[64];
    char kt[64], text[200];
    CHECK(bbr_generate_key(master) == BBR_OK);
    CHECK(bbr_key_to_text(master, kt, sizeof kt) == BBR_OK);
    CHECK(strlen(kt) == 8 + 43 && strncmp(kt, "bb416k1:", 8) == 0);
    CHECK(bbr_key_from_text(kt, back) == BBR_OK && memcmp(master, back, sizeof back) == 0);
    kt[20] = '!';
    CHECK(bbr_key_from_text(kt, back) == BBR_ERR_FORMAT);
    CHECK(bbr_key_from_text("bb416k1:kisa", back) == BBR_ERR_FORMAT);

    bbr_key k;
    bbr_key_init(&k, master);
    size_t dlen;
    CHECK(bbr_encrypt_text(&k, (const uint8_t *)"merhaba", 7, NULL, 0, text, sizeof text) == BBR_OK);
    CHECK(strlen(text) == 8 + 59); /* 7 + 37 = 44 bayt → 59 base64url karakteri */
    CHECK(bbr_encrypt_text(&k, (const uint8_t *)"merhaba", 7, NULL, 0, text, 60) == BBR_ERR_PARAM);
    CHECK(bbr_decrypt_text(&k, text, strlen(text), NULL, 0, dec, 6, &dlen) == BBR_ERR_PARAM);
    CHECK(bbr_decrypt_text(&k, text + 1, strlen(text) - 1, NULL, 0, dec, sizeof dec, &dlen) == BBR_ERR_FORMAT);
    char bad[200];
    strcpy(bad, text);
    bad[30] = '+'; /* base64url alfabesinde yok */
    CHECK(bbr_decrypt_text(&k, bad, strlen(bad), NULL, 0, dec, sizeof dec, &dlen) == BBR_ERR_FORMAT);
    bbr_key_wipe(&k);

    /* base64url: kanonik olmayan son karakter ve geçersiz uzunluk reddedilir. */
    uint8_t o[8];
    CHECK(bbr_b64url_decode("QQ", 2, o) == 1 && o[0] == 'A');
    CHECK(bbr_b64url_decode("QR", 2, o) == (size_t)-1);
    CHECK(bbr_b64url_decode("QUJD", 4, o) == 3 && memcmp(o, "ABC", 3) == 0);
    CHECK(bbr_b64url_decode("QUJDR", 5, o) == (size_t)-1);
    char e[8];
    CHECK(bbr_b64url_encode((const uint8_t *)"\xfb\xff", 2, e) == 3 && memcmp(e, "-_8", 3) == 0);
}

int main(int argc, char **argv)
{
    tu_init("test_record", argc, argv);
    test_vectors();
    test_roundtrip();
    test_tamper();
    test_text_and_keys();
    return tu_finish("test_record");
}
