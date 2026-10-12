/*
 * Parolayla dosya şifreleme (BicBic416-CTR + HMAC-SHA256, şifrele-sonra-doğrula).
 *
 * Dosya biçimi (sürüm 1), tüm sayılar little-endian:
 *
 *   ofset  boyut  alan
 *   0      4      sihirli "BB41"
 *   4      1      sürüm = 1
 *   5      1      tur sayısı (1..32)
 *   6      4      PBKDF2 yineleme sayısı
 *   10     16     tuz (rastgele)
 *   26     44     nonce (rastgele)
 *   70     n      şifreli veri (düz metinle aynı uzunlukta)
 *   70+n   32     etiket = HMAC-SHA256(mac_anahtarı, başlık || şifreli veri)
 *
 * Anahtarlar: PBKDF2-HMAC-SHA256(parola, tuz, yineleme, 84 bayt)
 *             → ilk 52 bayt BicBic416 anahtarı, son 32 bayt HMAC anahtarı.
 * Başlık da etikete dahildir: tur/yineleme sayısıyla oynanırsa çözme reddedilir.
 * Çözmede önce etiket doğrulanır; doğrulanmayan dosyadan tek bayt bile yazılmaz.
 */
#ifndef BICBIC_FILE_H
#define BICBIC_FILE_H

#include <stddef.h>
#include <stdint.h>

#define BBF_HEADER_BYTES   70
#define BBF_TAG_BYTES      32
#define BBF_SALT_BYTES     16
#define BBF_DEFAULT_ROUNDS 16
#define BBF_DEFAULT_ITERS  600000u   /* OWASP 2023 önerisi (PBKDF2-HMAC-SHA256) */
#define BBF_MAX_ITERS      10000000u /* bozuk/kötü niyetli başlıkla saatlerce bekletmeyi önler */

enum {
    BBF_OK = 0,
    BBF_ERR_IO = 1,       /* dosya açılamadı / okunamadı / yazılamadı */
    BBF_ERR_AUTH = 2,     /* yanlış parola veya dosya değiştirilmiş */
    BBF_ERR_FORMAT = 3,   /* BicBic416 dosyası değil / desteklenmeyen sürüm / kısa dosya */
    BBF_ERR_PARAM = 4,    /* geçersiz tur veya yineleme sayısı */
    BBF_ERR_EXISTS = 5,   /* çıktı dosyası zaten var (overwrite = 0) */
    BBF_ERR_RANDOM = 6,   /* işletim sisteminden rastgele bayt alınamadı */
};

typedef struct {
    int rounds;
    uint32_t iterations;
    uint64_t data_bytes;
} bbf_info;

int bbf_encrypt_file(const char *in_path, const char *out_path, const char *password,
                    int rounds, uint32_t iterations, int overwrite);
int bbf_decrypt_file(const char *in_path, const char *out_path, const char *password,
                    int overwrite);
int bbf_read_info(const char *path, bbf_info *info);
const char *bbf_strerror(int code);

/* Yalnızca testler için: çözmede doğrulama ile çözme geçişleri arasında çağrılır
 * (iki geçiş arasında dosyanın değiştirilmesi saldırısını sınamak için). */
extern void (*bbf_test_between_passes)(const char *in_path);

#endif
