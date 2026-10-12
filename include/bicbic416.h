/*
 * BicBic416 — eğitim / araştırma amaçlı oyuncak blok şifre.
 * Kriptanalizden geçmemiştir; gerçek verileri korumak için KULLANMAYIN
 * (gerçek kullanım için AES-GCM veya ChaCha20-Poly1305).
 *
 * Tasarımın tamamı SPEC.md içinde tanımlıdır.
 */
#ifndef BICBIC416_H
#define BICBIC416_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BB416_BLOCK_BYTES 52
#define BB416_KEY_BYTES   52
#define BB416_NONCE_BYTES 44
#define BB416_MAX_ROUNDS  32

#define BB416_OK            0
#define BB416_ERR_PARAM    -1 /* NULL işaretçi veya geçersiz tur sayısı */
#define BB416_ERR_COUNTER  -2 /* CTR sayacı taşacaktı */

typedef struct {
    int rounds;
    uint32_t rk[BB416_MAX_ROUNDS + 1][13];
    uint32_t mk[BB416_MAX_ROUNDS][13];
    uint32_t mkinv[BB416_MAX_ROUNDS][13];
} bb416_ctx;

/* rounds 1..BB416_MAX_ROUNDS olmalı. Hata durumunda ctx sıfırlanır. */
int  bb416_init(bb416_ctx *ctx, const uint8_t key[BB416_KEY_BYTES], int rounds);

/* in == out desteklenir; kısmi örtüşme desteklenmez. */
void bb416_encrypt_block(const bb416_ctx *ctx, const uint8_t in[BB416_BLOCK_BYTES],
                        uint8_t out[BB416_BLOCK_BYTES]);
void bb416_decrypt_block(const bb416_ctx *ctx, const uint8_t in[BB416_BLOCK_BYTES],
                        uint8_t out[BB416_BLOCK_BYTES]);

/*
 * CTR modu: sayaç bloğu = nonce (44 bayt) || counter (8 bayt, little-endian).
 * counter ilk bloğun sayacıdır ve her 52 baytlık blokta 1 artar. Sayaç taşacaksa
 * hiçbir bayt yazılmadan BB416_ERR_COUNTER döner. Aynı anahtarla aynı nonce'u
 * asla tekrar kullanmayın. Kimlik doğrulama sağlamaz.
 */
int  bb416_ctr_xor(const bb416_ctx *ctx, const uint8_t nonce[BB416_NONCE_BYTES],
                  uint64_t counter, const uint8_t *in, uint8_t *out, size_t len);

/* Derleyicinin optimize edip silemeyeceği şekilde sıfırlar. */
void bb416_wipe(bb416_ctx *ctx);

/*
 * BicBic-Hash: 416 bitlik (52 bayt) özet fonksiyonu (SPEC.md §12).
 * BicBic416 blok şifresinden Miyaguchi–Preneel yapısıyla türetilir. Deneyseldir;
 * parola saklama veya imza gibi güvenlik işleri için SHA-256/SHA-3 kullanın.
 */
#define BB416_HASH_BYTES 52

typedef struct {
    uint8_t h[BB416_HASH_BYTES];   /* zincirleme değeri */
    uint8_t buf[BB416_BLOCK_BYTES];
    size_t used;
    uint64_t total;                /* işlenen toplam bayt */
} bb416_hash_ctx;

void bb416_hash_init(bb416_hash_ctx *c);
void bb416_hash_update(bb416_hash_ctx *c, const void *data, size_t len);
void bb416_hash_final(bb416_hash_ctx *c, uint8_t out[BB416_HASH_BYTES]);
void bb416_hash(const void *data, size_t len, uint8_t out[BB416_HASH_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* BICBIC416_H */
