/*
 * BicBic416 kayıt biçimi: log satırı gibi küçük mesajları tek tek, iki katmanlı
 * (BicBic416 + ChaCha20) şifreleyip HMAC-SHA256 ile mühürler (SPEC.md §14).
 *
 * Parola yerine 32 baytlık rastgele bir ana anahtar kullanılır; alt anahtarlar bir kez
 * türetilir, kayıt başına maliyet birkaç mikrosaniyedir.
 *
 *   Ana anahtar M (32 bayt) → HKDF-SHA256(M, "BicBic416 kayit v1", 120)
 *                           → K_bb (52) | K_mac (32) | K_cc (32) | kimlik (4)
 *
 *   Kayıt (ikili):  0xB3 | kimlik (4) | N (16, rastgele) | şifreli (n) | etiket (16)
 *     şifreli = mesaj ⊕ BicBic416-CTR(K_bb, N || 0^28, 0) ⊕ ChaCha20(HMAC(K_cc, N), 0^12, 0)
 *     etiket  = HMAC-SHA256(K_mac, uzunluk(ek) 8 bayt LE || ek || başlık || şifreli)[0..16)
 *
 *   Metin biçimi:   "bb416r1:" + base64url(kayıt), dolgusuz → log satırına doğrudan yazılır.
 *   Anahtar metni:  "bb416k1:" + base64url(M)
 *
 * "ek" (ilişkili veri) şifrelenmez ama mühre girer: tarih, sunucu adı gibi açık kalması
 * gereken bilgilerin değiştirilmesini engeller. Çözerken aynı ek verilmelidir.
 */
#ifndef BICBIC_RECORD_H
#define BICBIC_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "bicbic416.h"

#define BBR_KEY_BYTES      32
#define BBR_KID_BYTES      4
#define BBR_NONCE_BYTES    16
#define BBR_TAG_BYTES      16
#define BBR_HEADER_BYTES   (1 + BBR_KID_BYTES + BBR_NONCE_BYTES)          /* 21 */
#define BBR_OVERHEAD       (BBR_HEADER_BYTES + BBR_TAG_BYTES)             /* 37 */
#define BBR_FORMAT         0xB3
#define BBR_TEXT_PREFIX    "bb416r1:"
#define BBR_KEY_PREFIX     "bb416k1:"
#define BBR_MAX_MESSAGE    ((size_t)1 << 30)                               /* 1 GiB */

enum {
    BBR_OK = 0,
    BBR_ERR_PARAM = 1,    /* geçersiz argüman veya çok büyük mesaj */
    BBR_ERR_FORMAT = 2,   /* kayıt/anahtar biçimi tanınmadı */
    BBR_ERR_KEY = 3,      /* kayıt başka bir anahtarla şifrelenmiş (kimlik tutmuyor) */
    BBR_ERR_AUTH = 4,     /* mühür tutmuyor: kayıt veya ek değiştirilmiş */
    BBR_ERR_RANDOM = 5,   /* işletim sisteminden rastgele bayt alınamadı */
};

typedef struct {
    bb416_ctx bb;
    uint8_t mac_key[32];
    uint8_t chacha_key[32];
    uint8_t kid[BBR_KID_BYTES];
} bbr_key;

/* sizeof(bbr_key): başka dillerden (ör. Python ctypes) bellek ayırmak için. */
size_t bbr_key_size(void);

/* Ana anahtardan alt anahtarları türetir. */
void bbr_key_init(bbr_key *k, const uint8_t master[BBR_KEY_BYTES]);
void bbr_key_wipe(bbr_key *k);

/* Yeni rastgele ana anahtar üretir. */
int bbr_generate_key(uint8_t master[BBR_KEY_BYTES]);

/* İkili kayıt. out en az len + BBR_OVERHEAD bayt olmalı; *out_len'e yazılan uzunluk konur. */
int bbr_encrypt(const bbr_key *k, const uint8_t *msg, size_t len, const uint8_t *aad, size_t aad_len,
                uint8_t *out, size_t *out_len);
/* Testler için: N dışarıdan verilir. Gerçek kullanımda N her kayıtta rastgele OLMALIDIR. */
int bbr_encrypt_with_nonce(const bbr_key *k, const uint8_t nonce[BBR_NONCE_BYTES],
                           const uint8_t *msg, size_t len, const uint8_t *aad, size_t aad_len,
                           uint8_t *out, size_t *out_len);
/* out en az in_len - BBR_OVERHEAD bayt olmalı. Mühür tutmazsa out'a hiçbir şey yazılmaz. */
int bbr_decrypt(const bbr_key *k, const uint8_t *in, size_t in_len, const uint8_t *aad, size_t aad_len,
                uint8_t *out, size_t *out_len);

/* Metin biçimi ("bb416r1:..."). Gerekli tampon boyutları: */
size_t bbr_text_len(size_t msg_len);           /* sonlandırıcı NUL dahil */
int bbr_encrypt_text(const bbr_key *k, const uint8_t *msg, size_t len, const uint8_t *aad, size_t aad_len,
                     char *out, size_t out_cap);
int bbr_decrypt_text(const bbr_key *k, const char *text, size_t text_len, const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/* Metindeki kaydın anahtar kimliğini okur (anahtar halkasından doğru anahtarı seçmek için). */
int bbr_text_kid(const char *text, size_t text_len, uint8_t kid[BBR_KID_BYTES]);

/* Anahtar metni ("bb416k1:...") ↔ 32 bayt. */
int bbr_key_to_text(const uint8_t master[BBR_KEY_BYTES], char *out, size_t out_cap);
int bbr_key_from_text(const char *text, uint8_t master[BBR_KEY_BYTES]);

/* base64url (dolgusuz). Dönüş: yazılan bayt/karakter sayısı, hata için (size_t)-1. */
size_t bbr_b64url_encode(const uint8_t *in, size_t len, char *out);
size_t bbr_b64url_decode(const char *in, size_t len, uint8_t *out);

const char *bbr_strerror(int code);

#endif
