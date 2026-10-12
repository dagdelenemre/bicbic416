/*
 * SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) ve PBKDF2-HMAC-SHA256 (RFC 8018).
 * Dosya aracının parola → anahtar türetmesi ve bütünlük etiketi için kullanılır.
 * Doğruluk: tests/test_sha256.c, Python hashlib/hmac çıktılarıyla karşılaştırır.
 */
#ifndef BICBIC_SHA256_H
#define BICBIC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BYTES 32
#define SHA256_BLOCK 64

typedef struct {
    uint32_t h[8];
    uint64_t total;          /* işlenen toplam bayt */
    uint8_t buf[SHA256_BLOCK];
    size_t used;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_BYTES]);
void sha256(const void *data, size_t len, uint8_t out[SHA256_BYTES]);

typedef struct {
    sha256_ctx inner, outer;
} hmac_sha256_ctx;

void hmac_sha256_init(hmac_sha256_ctx *c, const void *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx *c, const void *data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[SHA256_BYTES]);
void hmac_sha256(const void *key, size_t key_len, const void *data, size_t len,
                 uint8_t out[SHA256_BYTES]);

void pbkdf2_hmac_sha256(const void *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len);

/* Sabit zamanlı karşılaştırma: 0 = eşit. Etiket doğrulamasında zamanlama sızıntısını önler. */
int ct_memcmp(const void *a, const void *b, size_t n);

/* Derleyicinin silemeyeceği şekilde sıfırlar. */
void wipe(void *p, size_t n);

#endif
