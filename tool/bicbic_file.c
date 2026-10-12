#include "bicbic_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "osrand.h"
#include "bicbic416.h"
#include "sha256.h"

#define CHUNK (BB416_BLOCK_BYTES * 1260) /* 65 520 bayt; 52'nin katı → CTR sayacı kesintisiz */
#define DK_BYTES (BB416_KEY_BYTES + SHA256_BYTES)

static const uint8_t MAGIC[4] = { 'B', 'B', '4', '1' };

void (*bbf_test_between_passes)(const char *in_path) = NULL;

static void put32(uint8_t *p, uint32_t x)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(x >> (8 * i));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int file_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f) fclose(f);
    return f != NULL;
}

/* Çıktı önce geçici dosyaya yazılır, ancak her şey başarılıysa yerine taşınır:
 * yarıda kalan işlem eksik/bozuk bir çıktı dosyası bırakmaz. */
static int finish_output(FILE *tmp, const char *tmp_path, const char *out_path, int ok)
{
    if (fclose(tmp) != 0)
        ok = 0;
    if (!ok) {
        remove(tmp_path);
        return BBF_ERR_IO;
    }
    remove(out_path); /* Windows'ta rename hedef varsa başarısız olur */
    if (rename(tmp_path, out_path) != 0) {
        remove(tmp_path);
        return BBF_ERR_IO;
    }
    return BBF_OK;
}

static char *tmp_name(const char *out_path)
{
    static const char suffix[] = ".bb416tmp";
    size_t n = strlen(out_path);
    char *t = malloc(n + sizeof suffix);
    if (t) {
        memcpy(t, out_path, n);
        memcpy(t + n, suffix, sizeof suffix); /* sonlandırıcı NUL dahil */
    }
    return t;
}

static void derive(const char *password, const uint8_t salt[BBF_SALT_BYTES], uint32_t iters,
                   uint8_t dk[DK_BYTES])
{
    pbkdf2_hmac_sha256(password, strlen(password), salt, BBF_SALT_BYTES, iters, dk, DK_BYTES);
}

int bbf_encrypt_file(const char *in_path, const char *out_path, const char *password,
                    int rounds, uint32_t iterations, int overwrite)
{
    if (rounds < 1 || rounds > BB416_MAX_ROUNDS || iterations < 1 || iterations > BBF_MAX_ITERS)
        return BBF_ERR_PARAM;
    if (!overwrite && file_exists(out_path))
        return BBF_ERR_EXISTS;

    uint8_t hdr[BBF_HEADER_BYTES];
    memcpy(hdr, MAGIC, 4);
    hdr[4] = 1;
    hdr[5] = (uint8_t)rounds;
    put32(hdr + 6, iterations);
    if (os_random(hdr + 10, BBF_SALT_BYTES + BB416_NONCE_BYTES) != 0)
        return BBF_ERR_RANDOM;
    const uint8_t *salt = hdr + 10, *nonce = hdr + 26;

    FILE *in = fopen(in_path, "rb");
    if (!in)
        return BBF_ERR_IO;
    char *tmp_path = tmp_name(out_path);
    FILE *out = tmp_path ? fopen(tmp_path, "wb") : NULL;
    if (!out) {
        fclose(in);
        free(tmp_path);
        return BBF_ERR_IO;
    }

    uint8_t dk[DK_BYTES];
    bb416_ctx *ctx = malloc(sizeof *ctx);
    uint8_t *buf = malloc(CHUNK);
    hmac_sha256_ctx mac;
    int ok = ctx && buf;

    if (ok) {
        derive(password, salt, iterations, dk);
        ok = bb416_init(ctx, dk, rounds) == BB416_OK;
        hmac_sha256_init(&mac, dk + BB416_KEY_BYTES, SHA256_BYTES);
        hmac_sha256_update(&mac, hdr, sizeof hdr);
        ok = ok && fwrite(hdr, 1, sizeof hdr, out) == sizeof hdr;
    }

    uint64_t counter = 0;
    while (ok) {
        size_t n = fread(buf, 1, CHUNK, in);
        if (n == 0) {
            ok = !ferror(in);
            break;
        }
        ok = bb416_ctr_xor(ctx, nonce, counter, buf, buf, n) == BB416_OK;
        hmac_sha256_update(&mac, buf, n);
        ok = ok && fwrite(buf, 1, n, out) == n;
        counter += CHUNK / BB416_BLOCK_BYTES;
    }
    if (ok) {
        uint8_t tag[BBF_TAG_BYTES];
        hmac_sha256_final(&mac, tag);
        ok = fwrite(tag, 1, sizeof tag, out) == sizeof tag;
    }

    fclose(in);
    int rc = finish_output(out, tmp_path, out_path, ok);
    wipe(dk, sizeof dk);
    wipe(&mac, sizeof mac);
    if (ctx) { bb416_wipe(ctx); free(ctx); }
    if (buf) { wipe(buf, CHUNK); free(buf); }
    free(tmp_path);
    return rc;
}

/* Başlığı okur ve doğrular (etiket hariç). */
static int read_header(FILE *f, uint8_t hdr[BBF_HEADER_BYTES], int *rounds, uint32_t *iters)
{
    if (fread(hdr, 1, BBF_HEADER_BYTES, f) != BBF_HEADER_BYTES)
        return BBF_ERR_FORMAT;
    if (memcmp(hdr, MAGIC, 4) != 0 || hdr[4] != 1)
        return BBF_ERR_FORMAT;
    *rounds = hdr[5];
    *iters = get32(hdr + 6);
    /* Bu alanlar etiketle korunur ama etiket kontrolü için önce PBKDF2 çalışmalı;
     * aşırı değerler reddedilir ki bozuk bir başlık programı kilitlemesin. */
    if (*rounds < 1 || *rounds > BB416_MAX_ROUNDS || *iters < 1 || *iters > BBF_MAX_ITERS)
        return BBF_ERR_FORMAT;
    return BBF_OK;
}

int bbf_read_info(const char *path, bbf_info *info)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return BBF_ERR_IO;
    uint8_t hdr[BBF_HEADER_BYTES];
    int rc = read_header(f, hdr, &info->rounds, &info->iterations);
    uint64_t total = BBF_HEADER_BYTES;
    uint8_t buf[4096];
    size_t n;
    while (rc == BBF_OK && (n = fread(buf, 1, sizeof buf, f)) > 0)
        total += n;
    if (rc == BBF_OK && total < BBF_HEADER_BYTES + BBF_TAG_BYTES)
        rc = BBF_ERR_FORMAT;
    info->data_bytes = rc == BBF_OK ? total - BBF_HEADER_BYTES - BBF_TAG_BYTES : 0;
    fclose(f);
    return rc;
}

int bbf_decrypt_file(const char *in_path, const char *out_path, const char *password,
                    int overwrite)
{
    if (!overwrite && file_exists(out_path))
        return BBF_ERR_EXISTS;

    FILE *in = fopen(in_path, "rb");
    if (!in)
        return BBF_ERR_IO;

    uint8_t hdr[BBF_HEADER_BYTES], dk[DK_BYTES];
    int rounds;
    uint32_t iters;
    int rc = read_header(in, hdr, &rounds, &iters);
    if (rc != BBF_OK) {
        fclose(in);
        return rc;
    }

    bb416_ctx *ctx = malloc(sizeof *ctx);
    uint8_t *buf = malloc(CHUNK + BBF_TAG_BYTES);
    if (!ctx || !buf) {
        free(ctx);
        free(buf);
        fclose(in);
        return BBF_ERR_IO;
    }
    derive(password, hdr + 10, iters, dk);

    /* 1. geçiş: etiketi doğrula. Son 32 bayt etiket olduğundan her zaman
     * 32 baytı geride tutarak akış hâlinde HMAC hesaplanır. */
    hmac_sha256_ctx mac;
    hmac_sha256_init(&mac, dk + BB416_KEY_BYTES, SHA256_BYTES);
    hmac_sha256_update(&mac, hdr, sizeof hdr);
    size_t held = 0;           /* buf başındaki, henüz HMAC'e verilmemiş bayt sayısı */
    uint64_t data_len = 0;
    for (;;) {
        size_t n = fread(buf + held, 1, CHUNK, in);
        if (n == 0) break;
        held += n;
        if (held > BBF_TAG_BYTES) {
            size_t give = held - BBF_TAG_BYTES;
            hmac_sha256_update(&mac, buf, give);
            data_len += give;
            memmove(buf, buf + give, BBF_TAG_BYTES);
            held = BBF_TAG_BYTES;
        }
    }
    uint8_t tag[BBF_TAG_BYTES], file_tag[BBF_TAG_BYTES];
    if (ferror(in) || held < BBF_TAG_BYTES) {
        rc = ferror(in) ? BBF_ERR_IO : BBF_ERR_FORMAT;
    } else {
        memcpy(file_tag, buf, BBF_TAG_BYTES);
        hmac_sha256_final(&mac, tag);
        if (ct_memcmp(tag, file_tag, BBF_TAG_BYTES) != 0)
            rc = BBF_ERR_AUTH;
    }

    /* 2. geçiş: doğrulanmış veriyi çöz ve geçici dosyaya yaz. Dosya iki geçiş
     * arasında değiştirilmiş olabilir (TOCTOU); bu yüzden okunan şifreli veri için
     * etiket yeniden hesaplanır ve eşleşmezse çıktı silinir, hedefe hiç taşınmaz. */
    if (rc == BBF_OK && bbf_test_between_passes)
        bbf_test_between_passes(in_path);
    if (rc == BBF_OK) {
        char *tmp_path = tmp_name(out_path);
        FILE *out = tmp_path ? fopen(tmp_path, "wb") : NULL;
        if (!out) {
            rc = BBF_ERR_IO;
        } else {
            hmac_sha256_init(&mac, dk + BB416_KEY_BYTES, SHA256_BYTES);
            hmac_sha256_update(&mac, hdr, sizeof hdr);
            int ok = bb416_init(ctx, dk, rounds) == BB416_OK &&
                     fseek(in, BBF_HEADER_BYTES, SEEK_SET) == 0;
            uint64_t left = data_len, counter = 0;
            while (ok && left) {
                size_t want = left < CHUNK ? (size_t)left : CHUNK;
                ok = fread(buf, 1, want, in) == want;
                if (ok) {
                    hmac_sha256_update(&mac, buf, want);
                    ok = bb416_ctr_xor(ctx, hdr + 26, counter, buf, buf, want) == BB416_OK &&
                         fwrite(buf, 1, want, out) == want;
                }
                left -= want;
                counter += CHUNK / BB416_BLOCK_BYTES;
            }
            int same = 0;
            if (ok) {
                hmac_sha256_final(&mac, tag);
                same = ct_memcmp(tag, file_tag, BBF_TAG_BYTES) == 0;
            }
            rc = finish_output(out, tmp_path, out_path, ok && same);
            if (ok && !same)
                rc = BBF_ERR_AUTH;
        }
        free(tmp_path);
    }

    fclose(in);
    wipe(dk, sizeof dk);
    wipe(&mac, sizeof mac);
    bb416_wipe(ctx);
    free(ctx);
    wipe(buf, CHUNK + BBF_TAG_BYTES);
    free(buf);
    return rc;
}

const char *bbf_strerror(int code)
{
    switch (code) {
    case BBF_OK:         return "tamam";
    case BBF_ERR_IO:     return "dosya okunamadı veya yazılamadı";
    case BBF_ERR_AUTH:   return "yanlış parola veya dosya değiştirilmiş/bozulmuş";
    case BBF_ERR_FORMAT: return "BicBic416 dosyası değil, desteklenmeyen sürüm veya eksik dosya";
    case BBF_ERR_PARAM:  return "geçersiz tur veya yineleme sayısı";
    case BBF_ERR_EXISTS: return "çıktı dosyası zaten var (üzerine yazmak için -z kullanın)";
    case BBF_ERR_RANDOM: return "işletim sisteminden rastgele sayı alınamadı";
    default:            return "bilinmeyen hata";
    }
}
