#include "bicbic_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"
#include "chacha20.h"
#include "osrand.h"
#include "sha256.h"

/* Parça boyutu hem 52'nin (BicBic416 bloğu) hem 64'ün (ChaCha20 bloğu) katı olmalı ki
 * her parçada iki akışın sayacı da ofsetten doğrudan hesaplanabilsin: 832 × 78. */
#define CHUNK 64896u
#define MAX_TAG BBF_V1_TAG_BYTES

static const uint8_t V1_MAGIC[4] = { 'B', 'B', '4', '1' };
static const char V2_INFO[] = "BicBic416 v2 anahtarlar";

void (*bbf_test_between_passes)(const char *in_path) = NULL;

/* Ayrıştırılmış başlık. */
typedef struct {
    int version, rounds, layers;
    uint32_t iters;
    size_t hdr_len, tag_len;
    uint8_t hdr[BBF_V1_HEADER_BYTES];
} header;

/* Bir dosyanın türetilmiş anahtarları ve akış durumu. */
typedef struct {
    bb416_ctx bb;
    uint8_t nonce[BB416_NONCE_BYTES];
    uint8_t mac_key[SHA256_BYTES];
    uint8_t chacha_key[CHACHA20_KEY_BYTES];
    int layers;
    size_t tag_len;
} keys;

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

/* Başlığı okur ve doğrular (etiket hariç). Alanlar etiketle korunur ama etiket
 * kontrolü için önce PBKDF2 çalışmalı; aşırı değerler burada reddedilir ki bozuk
 * bir başlık programı kilitlemesin. */
static int read_header(FILE *f, header *h)
{
    memset(h, 0, sizeof *h);
    if (fread(h->hdr, 1, 1, f) != 1)
        return BBF_ERR_FORMAT;

    if (h->hdr[0] == BBF_V2_FORMAT) {
        if (fread(h->hdr + 1, 1, BBF_V2_HEADER_BYTES - 1, f) != BBF_V2_HEADER_BYTES - 1)
            return BBF_ERR_FORMAT;
        h->version = 2;
        h->hdr_len = BBF_V2_HEADER_BYTES;
        h->tag_len = BBF_V2_TAG_BYTES;
        h->rounds = h->hdr[1] & 0x3F;
        h->layers = (h->hdr[1] & 0x40) ? 2 : 1;
        h->iters = ((uint32_t)h->hdr[2] | (uint32_t)h->hdr[3] << 8) * BBF_ITER_UNIT;
        if (h->hdr[1] & 0x80)
            return BBF_ERR_FORMAT;
    } else if (h->hdr[0] == V1_MAGIC[0]) {
        if (fread(h->hdr + 1, 1, BBF_V1_HEADER_BYTES - 1, f) != BBF_V1_HEADER_BYTES - 1 ||
            memcmp(h->hdr, V1_MAGIC, 4) != 0 || h->hdr[4] != 1)
            return BBF_ERR_FORMAT;
        h->version = 1;
        h->hdr_len = BBF_V1_HEADER_BYTES;
        h->tag_len = BBF_V1_TAG_BYTES;
        h->rounds = h->hdr[5];
        h->layers = 1;
        h->iters = (uint32_t)h->hdr[6] | (uint32_t)h->hdr[7] << 8 |
                   (uint32_t)h->hdr[8] << 16 | (uint32_t)h->hdr[9] << 24;
    } else {
        return BBF_ERR_FORMAT;
    }
    if (h->rounds < 1 || h->rounds > BB416_MAX_ROUNDS || h->iters < 1 || h->iters > BBF_MAX_ITERS)
        return BBF_ERR_FORMAT;
    return BBF_OK;
}

static int derive_keys(const char *password, const header *h, keys *k)
{
    const size_t pw_len = strlen(password);
    k->layers = h->layers;
    k->tag_len = h->tag_len;
    memset(k->nonce, 0, sizeof k->nonce);

    if (h->version == 1) {
        uint8_t dk[BB416_KEY_BYTES + SHA256_BYTES];
        pbkdf2_hmac_sha256(password, pw_len, h->hdr + 10, BBF_SALT_BYTES, h->iters, dk, sizeof dk);
        memcpy(k->mac_key, dk + BB416_KEY_BYTES, SHA256_BYTES);
        memcpy(k->nonce, h->hdr + 26, BB416_NONCE_BYTES);
        int rc = bb416_init(&k->bb, dk, h->rounds);
        wipe(dk, sizeof dk);
        return rc;
    }

    uint8_t master[SHA256_BYTES], dk[BB416_KEY_BYTES + SHA256_BYTES + CHACHA20_KEY_BYTES];
    pbkdf2_hmac_sha256(password, pw_len, h->hdr + 4, BBF_SALT_BYTES, h->iters, master, sizeof master);
    hkdf_sha256(NULL, 0, master, sizeof master, (const uint8_t *)V2_INFO, sizeof V2_INFO - 1,
                dk, sizeof dk);
    memcpy(k->mac_key, dk + BB416_KEY_BYTES, SHA256_BYTES);
    memcpy(k->chacha_key, dk + BB416_KEY_BYTES + SHA256_BYTES, CHACHA20_KEY_BYTES);
    int rc = bb416_init(&k->bb, dk, h->rounds);
    wipe(master, sizeof master);
    wipe(dk, sizeof dk);
    return rc;
}

/* ofset: verideki konum; her zaman CHUNK'ın katı (dolayısıyla 52 ve 64'ün de katı). */
static int apply_stream(const keys *k, uint64_t offset, uint8_t *buf, size_t n)
{
    static const uint8_t zero_nonce[CHACHA20_NONCE_BYTES] = { 0 };
    if (bb416_ctr_xor(&k->bb, k->nonce, offset / BB416_BLOCK_BYTES, buf, buf, n) != BB416_OK)
        return 0;
    if (k->layers == 2) {
        if (offset + n > BBF_MAX_TWO_LAYER)
            return 0;
        chacha20_xor(k->chacha_key, zero_nonce, (uint32_t)(offset / CHACHA20_BLOCK_BYTES), buf, buf, n);
    }
    return 1;
}

static void wipe_keys(keys *k)
{
    if (k) {
        bb416_wipe(&k->bb);
        wipe(k, sizeof *k);
    }
}

int bbf_encrypt_file(const char *in_path, const char *out_path, const char *password,
                     int rounds, uint32_t iterations, int layers, int overwrite)
{
    if (rounds < 1 || rounds > BB416_MAX_ROUNDS || (layers != 1 && layers != 2) ||
        iterations < BBF_ITER_UNIT || iterations > BBF_MAX_ITERS || iterations % BBF_ITER_UNIT)
        return BBF_ERR_PARAM;
    if (!overwrite && file_exists(out_path))
        return BBF_ERR_EXISTS;

    header h = { 0 };
    h.version = 2;
    h.rounds = rounds;
    h.layers = layers;
    h.iters = iterations;
    h.hdr_len = BBF_V2_HEADER_BYTES;
    h.tag_len = BBF_V2_TAG_BYTES;
    h.hdr[0] = BBF_V2_FORMAT;
    h.hdr[1] = (uint8_t)(rounds | (layers == 2 ? 0x40 : 0));
    h.hdr[2] = (uint8_t)(iterations / BBF_ITER_UNIT);
    h.hdr[3] = (uint8_t)((iterations / BBF_ITER_UNIT) >> 8);
    if (os_random(h.hdr + 4, BBF_SALT_BYTES) != 0)
        return BBF_ERR_RANDOM;

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

    keys *k = malloc(sizeof *k);
    uint8_t *buf = malloc(CHUNK);
    hmac_sha256_ctx mac;
    int ok = k && buf, too_big = 0;

    if (ok) {
        ok = derive_keys(password, &h, k) == BB416_OK;
        hmac_sha256_init(&mac, k->mac_key, SHA256_BYTES);
        hmac_sha256_update(&mac, h.hdr, h.hdr_len);
        ok = ok && fwrite(h.hdr, 1, h.hdr_len, out) == h.hdr_len;
    }

    uint64_t offset = 0;
    while (ok) {
        size_t n = fread(buf, 1, CHUNK, in);
        if (n == 0) {
            ok = !ferror(in);
            break;
        }
        if (layers == 2 && offset + n > BBF_MAX_TWO_LAYER) {
            too_big = 1;
            ok = 0;
            break;
        }
        ok = apply_stream(k, offset, buf, n);
        hmac_sha256_update(&mac, buf, n);
        ok = ok && fwrite(buf, 1, n, out) == n;
        offset += n;
    }
    if (ok) {
        uint8_t tag[SHA256_BYTES];
        hmac_sha256_final(&mac, tag);
        ok = fwrite(tag, 1, h.tag_len, out) == h.tag_len;
        wipe(tag, sizeof tag);
    }

    fclose(in);
    int rc = finish_output(out, tmp_path, out_path, ok);
    if (too_big)
        rc = BBF_ERR_SIZE;
    wipe(&mac, sizeof mac);
    wipe_keys(k);
    free(k);
    if (buf) { wipe(buf, CHUNK); free(buf); }
    free(tmp_path);
    return rc;
}

int bbf_read_info(const char *path, bbf_info *info)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return BBF_ERR_IO;
    header h;
    int rc = read_header(f, &h);
    uint64_t total = h.hdr_len;
    uint8_t buf[4096];
    size_t n;
    while (rc == BBF_OK && (n = fread(buf, 1, sizeof buf, f)) > 0)
        total += n;
    if (rc == BBF_OK && total < h.hdr_len + h.tag_len)
        rc = BBF_ERR_FORMAT;
    memset(info, 0, sizeof *info);
    if (rc == BBF_OK) {
        info->version = h.version;
        info->rounds = h.rounds;
        info->layers = h.layers;
        info->iterations = h.iters;
        info->data_bytes = total - h.hdr_len - h.tag_len;
    }
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

    header h;
    int rc = read_header(in, &h);
    if (rc != BBF_OK) {
        fclose(in);
        return rc;
    }

    keys *k = malloc(sizeof *k);
    uint8_t *buf = malloc(CHUNK + MAX_TAG);
    if (!k || !buf || derive_keys(password, &h, k) != BB416_OK) {
        if (k) wipe_keys(k);
        free(k);
        free(buf);
        fclose(in);
        return BBF_ERR_IO;
    }
    const size_t T = h.tag_len;

    /* 1. geçiş: etiketi doğrula. Son T bayt etiket olduğundan her zaman
     * T baytı geride tutarak akış hâlinde HMAC hesaplanır. */
    hmac_sha256_ctx mac;
    hmac_sha256_init(&mac, k->mac_key, SHA256_BYTES);
    hmac_sha256_update(&mac, h.hdr, h.hdr_len);
    size_t held = 0;           /* buf başındaki, henüz HMAC'e verilmemiş bayt sayısı */
    uint64_t data_len = 0;
    for (;;) {
        size_t n = fread(buf + held, 1, CHUNK, in);
        if (n == 0) break;
        held += n;
        if (held > T) {
            size_t give = held - T;
            hmac_sha256_update(&mac, buf, give);
            data_len += give;
            memmove(buf, buf + give, T);
            held = T;
        }
    }
    uint8_t tag[SHA256_BYTES], file_tag[MAX_TAG];
    if (ferror(in) || held < T) {
        rc = ferror(in) ? BBF_ERR_IO : BBF_ERR_FORMAT;
    } else {
        memcpy(file_tag, buf, T);
        hmac_sha256_final(&mac, tag);
        if (ct_memcmp(tag, file_tag, T) != 0)
            rc = BBF_ERR_AUTH;
    }
    if (rc == BBF_OK && h.layers == 2 && data_len > BBF_MAX_TWO_LAYER)
        rc = BBF_ERR_FORMAT;

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
            hmac_sha256_init(&mac, k->mac_key, SHA256_BYTES);
            hmac_sha256_update(&mac, h.hdr, h.hdr_len);
            int ok = fseek(in, (long)h.hdr_len, SEEK_SET) == 0;
            uint64_t offset = 0;
            while (ok && offset < data_len) {
                size_t want = data_len - offset < CHUNK ? (size_t)(data_len - offset) : CHUNK;
                ok = fread(buf, 1, want, in) == want;
                if (ok) {
                    hmac_sha256_update(&mac, buf, want);
                    ok = apply_stream(k, offset, buf, want) && fwrite(buf, 1, want, out) == want;
                }
                offset += want;
            }
            int same = 0;
            if (ok) {
                hmac_sha256_final(&mac, tag);
                same = ct_memcmp(tag, file_tag, T) == 0;
            }
            rc = finish_output(out, tmp_path, out_path, ok && same);
            if (ok && !same)
                rc = BBF_ERR_AUTH;
        }
        free(tmp_path);
    }

    fclose(in);
    wipe(&mac, sizeof mac);
    wipe(tag, sizeof tag);
    wipe_keys(k);
    free(k);
    wipe(buf, CHUNK + MAX_TAG);
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
    case BBF_ERR_PARAM:  return "geçersiz tur, katman veya yineleme sayısı (yineleme 1000'in katı olmalı)";
    case BBF_ERR_EXISTS: return "çıktı dosyası zaten var (üzerine yazmak için -z kullanın)";
    case BBF_ERR_RANDOM: return "işletim sisteminden rastgele sayı alınamadı";
    case BBF_ERR_SIZE:   return "iki katmanlı modda dosya en fazla 256 GiB olabilir";
    default:             return "bilinmeyen hata";
    }
}
