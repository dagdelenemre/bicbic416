/*
 * Parolayla dosya şifreleme: BicBic416-CTR (+ isteğe bağlı ChaCha20 ikinci katmanı),
 * HMAC-SHA256 ile şifrele-sonra-doğrula. Şifreleme her zaman sürüm 2 yazar; çözme
 * sürüm 1 ve 2'yi okur. Tüm sayılar little-endian.
 *
 * Sürüm 2 (ek yük 36 bayt):
 *
 *   ofset  boyut  alan
 *   0      1      biçim = 0xB2
 *   1      1      bit 0–5: tur sayısı (1..32) · bit 6: ChaCha20 katmanı · bit 7: 0
 *   2      2      PBKDF2 yineleme sayısı / 1000 (1..10000)
 *   4      16     tuz (rastgele)
 *   20     n      şifreli veri (düz metinle aynı uzunlukta)
 *   20+n   16     etiket = HMAC-SHA256(mac_anahtarı, başlık || şifreli veri)'nin ilk 16 baytı
 *
 *   ana_sır    = PBKDF2-HMAC-SHA256(parola, tuz, yineleme, 32 bayt)
 *   anahtarlar = HKDF-SHA256(ana_sır, tuz yok, "BicBic416 v2 anahtarlar", 116 bayt)
 *              → BicBic416 anahtarı (52) | HMAC anahtarı (32) | ChaCha20 anahtarı (32)
 *   Her dosyanın tuzu rastgele olduğundan anahtarlar dosyaya özgüdür; bu yüzden
 *   nonce'lar sabittir (BicBic416-CTR: 44 sıfır bayt, ChaCha20: 12 sıfır bayt, sayaçlar 0).
 *   İki katmanda veri = düz metin ⊕ BicBic416 akışı ⊕ ChaCha20 akışı.
 *
 * Sürüm 1 (yalnızca okunur, ek yük 102 bayt):
 *   "BB41" | 1 | tur | yineleme (4) | tuz (16) | nonce (44) | veri | etiket (32)
 *   anahtarlar = PBKDF2(parola, tuz, yineleme, 84) → BicBic416 (52) | HMAC (32)
 *
 * Başlık etikete dahildir: tur, katman veya yineleme alanıyla oynanırsa çözme reddedilir.
 * Çözmede önce etiket doğrulanır; doğrulanmayan dosyadan tek bayt bile yazılmaz.
 */
#ifndef BICBIC_FILE_H
#define BICBIC_FILE_H

#include <stddef.h>
#include <stdint.h>

#define BBF_V1_HEADER_BYTES 70
#define BBF_V1_TAG_BYTES    32
#define BBF_V2_HEADER_BYTES 20
#define BBF_V2_TAG_BYTES    16
#define BBF_V2_FORMAT       0xB2
#define BBF_SALT_BYTES      16
#define BBF_DEFAULT_ROUNDS  16
#define BBF_DEFAULT_ITERS   600000u   /* OWASP 2023 önerisi (PBKDF2-HMAC-SHA256) */
#define BBF_MAX_ITERS       10000000u /* bozuk/kötü niyetli başlıkla saatlerce bekletmeyi önler */
#define BBF_ITER_UNIT       1000u     /* v2'de yineleme sayısı 1000'in katıdır */
#define BBF_MAX_TWO_LAYER   ((uint64_t)1 << 38) /* ChaCha20 32-bit sayacı: 256 GiB */

enum {
    BBF_OK = 0,
    BBF_ERR_IO = 1,       /* dosya açılamadı / okunamadı / yazılamadı */
    BBF_ERR_AUTH = 2,     /* yanlış parola veya dosya değiştirilmiş */
    BBF_ERR_FORMAT = 3,   /* BicBic416 dosyası değil / desteklenmeyen sürüm / kısa dosya */
    BBF_ERR_PARAM = 4,    /* geçersiz tur, katman veya yineleme sayısı */
    BBF_ERR_EXISTS = 5,   /* çıktı dosyası zaten var (overwrite = 0) */
    BBF_ERR_RANDOM = 6,   /* işletim sisteminden rastgele bayt alınamadı */
    BBF_ERR_SIZE = 7,     /* iki katmanlı modda dosya 256 GiB'tan büyük */
};

typedef struct {
    int version;          /* 1 veya 2 */
    int rounds;
    int layers;           /* 1 = BicBic416, 2 = BicBic416 + ChaCha20 */
    uint32_t iterations;
    uint64_t data_bytes;
} bbf_info;

/* layers: 1 veya 2. iterations: 1000'in katı, 1000..10 000 000. */
int bbf_encrypt_file(const char *in_path, const char *out_path, const char *password,
                     int rounds, uint32_t iterations, int layers, int overwrite);
int bbf_decrypt_file(const char *in_path, const char *out_path, const char *password,
                     int overwrite);
int bbf_read_info(const char *path, bbf_info *info);
const char *bbf_strerror(int code);

/* Yalnızca testler için: çözmede doğrulama ile çözme geçişleri arasında çağrılır
 * (iki geçiş arasında dosyanın değiştirilmesi saldırısını sınamak için). */
extern void (*bbf_test_between_passes)(const char *in_path);

#endif
