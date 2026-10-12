#include "bicbic_record.h"

#include <stdlib.h>
#include <string.h>

#include "chacha20.h"
#include "osrand.h"
#include "sha256.h"

static const char KDF_INFO[] = "BicBic416 kayit v1";

size_t bbr_key_size(void)
{
    return sizeof(bbr_key);
}

void bbr_key_init(bbr_key *k, const uint8_t master[BBR_KEY_BYTES])
{
    uint8_t dk[BB416_KEY_BYTES + 32 + 32 + BBR_KID_BYTES];
    hkdf_sha256(NULL, 0, master, BBR_KEY_BYTES, (const uint8_t *)KDF_INFO, sizeof KDF_INFO - 1,
                dk, sizeof dk);
    bb416_init(&k->bb, dk, 16);
    memcpy(k->mac_key, dk + 52, 32);
    memcpy(k->chacha_key, dk + 84, 32);
    memcpy(k->kid, dk + 116, BBR_KID_BYTES);
    wipe(dk, sizeof dk);
}

void bbr_key_wipe(bbr_key *k)
{
    if (k) {
        bb416_wipe(&k->bb);
        wipe(k, sizeof *k);
    }
}

int bbr_generate_key(uint8_t master[BBR_KEY_BYTES])
{
    return os_random(master, BBR_KEY_BYTES) == 0 ? BBR_OK : BBR_ERR_RANDOM;
}

/* mesaj ⊕ BicBic416-CTR ⊕ ChaCha20 (kayıt başına ChaCha20 anahtarı = HMAC(K_cc, N)). */
static void apply_layers(const bbr_key *k, const uint8_t nonce[BBR_NONCE_BYTES],
                         const uint8_t *in, uint8_t *out, size_t len)
{
    static const uint8_t zero12[CHACHA20_NONCE_BYTES] = { 0 };
    uint8_t bb_nonce[BB416_NONCE_BYTES] = { 0 }, rk[SHA256_BYTES];
    memcpy(bb_nonce, nonce, BBR_NONCE_BYTES);
    bb416_ctr_xor(&k->bb, bb_nonce, 0, in, out, len);
    hmac_sha256(k->chacha_key, sizeof k->chacha_key, nonce, BBR_NONCE_BYTES, rk);
    chacha20_xor(rk, zero12, 0, out, out, len);
    wipe(rk, sizeof rk);
}

static void compute_tag(const bbr_key *k, const uint8_t *aad, size_t aad_len,
                        const uint8_t *rec, size_t rec_len, uint8_t tag[SHA256_BYTES])
{
    uint8_t le[8];
    for (int i = 0; i < 8; i++) le[i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
    hmac_sha256_ctx c;
    hmac_sha256_init(&c, k->mac_key, sizeof k->mac_key);
    hmac_sha256_update(&c, le, sizeof le);
    hmac_sha256_update(&c, aad, aad_len);
    hmac_sha256_update(&c, rec, rec_len);
    hmac_sha256_final(&c, tag);
}

int bbr_encrypt_with_nonce(const bbr_key *k, const uint8_t nonce[BBR_NONCE_BYTES],
                           const uint8_t *msg, size_t len, const uint8_t *aad, size_t aad_len,
                           uint8_t *out, size_t *out_len)
{
    if (!k || !nonce || !out || (len && !msg) || (aad_len && !aad) || len > BBR_MAX_MESSAGE)
        return BBR_ERR_PARAM;
    out[0] = BBR_FORMAT;
    memcpy(out + 1, k->kid, BBR_KID_BYTES);
    memcpy(out + 1 + BBR_KID_BYTES, nonce, BBR_NONCE_BYTES);
    apply_layers(k, nonce, msg, out + BBR_HEADER_BYTES, len);
    uint8_t tag[SHA256_BYTES];
    compute_tag(k, aad, aad_len, out, BBR_HEADER_BYTES + len, tag);
    memcpy(out + BBR_HEADER_BYTES + len, tag, BBR_TAG_BYTES);
    wipe(tag, sizeof tag);
    if (out_len) *out_len = len + BBR_OVERHEAD;
    return BBR_OK;
}

int bbr_encrypt(const bbr_key *k, const uint8_t *msg, size_t len, const uint8_t *aad, size_t aad_len,
                uint8_t *out, size_t *out_len)
{
    uint8_t nonce[BBR_NONCE_BYTES];
    if (os_random(nonce, sizeof nonce) != 0)
        return BBR_ERR_RANDOM;
    return bbr_encrypt_with_nonce(k, nonce, msg, len, aad, aad_len, out, out_len);
}

int bbr_decrypt(const bbr_key *k, const uint8_t *in, size_t in_len, const uint8_t *aad, size_t aad_len,
                uint8_t *out, size_t *out_len)
{
    if (!k || !in || (aad_len && !aad))
        return BBR_ERR_PARAM;
    if (in_len < BBR_OVERHEAD || in[0] != BBR_FORMAT)
        return BBR_ERR_FORMAT;
    if (memcmp(in + 1, k->kid, BBR_KID_BYTES) != 0)
        return BBR_ERR_KEY;
    size_t len = in_len - BBR_OVERHEAD;
    if (len > BBR_MAX_MESSAGE || (len && !out))
        return BBR_ERR_PARAM;

    uint8_t tag[SHA256_BYTES];
    compute_tag(k, aad, aad_len, in, BBR_HEADER_BYTES + len, tag);
    int bad = ct_memcmp(tag, in + BBR_HEADER_BYTES + len, BBR_TAG_BYTES);
    wipe(tag, sizeof tag);
    if (bad)
        return BBR_ERR_AUTH;
    apply_layers(k, in + 1 + BBR_KID_BYTES, in + BBR_HEADER_BYTES, out, len);
    if (out_len) *out_len = len;
    return BBR_OK;
}

/* ---- base64url (RFC 4648 §5), dolgusuz ---------------------------------- */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t bbr_b64url_encode(const uint8_t *in, size_t len, char *out)
{
    size_t o = 0, i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out[o++] = B64[v >> 18]; out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63]; out[o++] = B64[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64[v >> 18]; out[o++] = B64[(v >> 12) & 63];
    } else if (len - i == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        out[o++] = B64[v >> 18]; out[o++] = B64[(v >> 12) & 63]; out[o++] = B64[(v >> 6) & 63];
    }
    return o;
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

size_t bbr_b64url_decode(const char *in, size_t len, uint8_t *out)
{
    if (len % 4 == 1)
        return (size_t)-1;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        int v = b64val(in[i]);
        if (v < 0)
            return (size_t)-1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    /* Kullanılmayan son bitler sıfır olmalı (tek bir doğru kodlama). */
    if (bits && (acc & ((1u << bits) - 1)))
        return (size_t)-1;
    return o;
}

/* ---- Metin biçimi --------------------------------------------------------- */

#define PREFIX_LEN (sizeof BBR_TEXT_PREFIX - 1)

static size_t b64_len(size_t n) { return n / 3 * 4 + (n % 3 ? n % 3 + 1 : 0); }

size_t bbr_text_len(size_t msg_len)
{
    return PREFIX_LEN + b64_len(msg_len + BBR_OVERHEAD) + 1;
}

int bbr_encrypt_text(const bbr_key *k, const uint8_t *msg, size_t len, const uint8_t *aad, size_t aad_len,
                     char *out, size_t out_cap)
{
    if (!out || len > BBR_MAX_MESSAGE || out_cap < bbr_text_len(len))
        return BBR_ERR_PARAM;
    size_t bin_len = len + BBR_OVERHEAD;
    uint8_t *bin = malloc(bin_len);
    if (!bin)
        return BBR_ERR_PARAM;
    int rc = bbr_encrypt(k, msg, len, aad, aad_len, bin, NULL);
    if (rc == BBR_OK) {
        memcpy(out, BBR_TEXT_PREFIX, PREFIX_LEN);
        size_t n = bbr_b64url_encode(bin, bin_len, out + PREFIX_LEN);
        out[PREFIX_LEN + n] = 0;
    }
    free(bin);
    return rc;
}

int bbr_decrypt_text(const bbr_key *k, const char *text, size_t text_len, const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!text || text_len < PREFIX_LEN || memcmp(text, BBR_TEXT_PREFIX, PREFIX_LEN) != 0)
        return BBR_ERR_FORMAT;
    size_t b64 = text_len - PREFIX_LEN;
    size_t max_bin = b64 / 4 * 3 + 2;
    if (max_bin > BBR_MAX_MESSAGE + BBR_OVERHEAD)
        return BBR_ERR_PARAM;
    uint8_t *bin = malloc(max_bin);
    if (!bin)
        return BBR_ERR_PARAM;
    int rc;
    size_t n = bbr_b64url_decode(text + PREFIX_LEN, b64, bin);
    if (n == (size_t)-1 || n < BBR_OVERHEAD)
        rc = BBR_ERR_FORMAT;
    else if (n - BBR_OVERHEAD > out_cap)
        rc = BBR_ERR_PARAM;
    else
        rc = bbr_decrypt(k, bin, n, aad, aad_len, out, out_len);
    free(bin);
    return rc;
}

int bbr_text_kid(const char *text, size_t text_len, uint8_t kid[BBR_KID_BYTES])
{
    uint8_t head[6];
    /* İlk 8 base64 karakteri 6 baytı (biçim + kimlik + 1) kapsar. */
    if (!text || text_len < PREFIX_LEN + 8 || memcmp(text, BBR_TEXT_PREFIX, PREFIX_LEN) != 0 ||
        bbr_b64url_decode(text + PREFIX_LEN, 8, head) != 6 || head[0] != BBR_FORMAT)
        return BBR_ERR_FORMAT;
    memcpy(kid, head + 1, BBR_KID_BYTES);
    return BBR_OK;
}

int bbr_key_to_text(const uint8_t master[BBR_KEY_BYTES], char *out, size_t out_cap)
{
    const size_t need = sizeof BBR_KEY_PREFIX - 1 + 43 + 1;
    if (!out || out_cap < need)
        return BBR_ERR_PARAM;
    memcpy(out, BBR_KEY_PREFIX, sizeof BBR_KEY_PREFIX - 1);
    size_t n = bbr_b64url_encode(master, BBR_KEY_BYTES, out + sizeof BBR_KEY_PREFIX - 1);
    out[sizeof BBR_KEY_PREFIX - 1 + n] = 0;
    return BBR_OK;
}

int bbr_key_from_text(const char *text, uint8_t master[BBR_KEY_BYTES])
{
    const size_t p = sizeof BBR_KEY_PREFIX - 1;
    uint8_t tmp[BBR_KEY_BYTES + 2];
    if (!text || strlen(text) != p + 43 || memcmp(text, BBR_KEY_PREFIX, p) != 0 ||
        bbr_b64url_decode(text + p, 43, tmp) != BBR_KEY_BYTES)
        return BBR_ERR_FORMAT;
    memcpy(master, tmp, BBR_KEY_BYTES);
    wipe(tmp, sizeof tmp);
    return BBR_OK;
}

const char *bbr_strerror(int code)
{
    switch (code) {
    case BBR_OK:         return "tamam";
    case BBR_ERR_PARAM:  return "geçersiz argüman veya tampon/mesaj boyutu";
    case BBR_ERR_FORMAT: return "BicBic416 kaydı/anahtarı değil veya eksik kopyalanmış";
    case BBR_ERR_KEY:    return "kayıt başka bir anahtarla şifrelenmiş";
    case BBR_ERR_AUTH:   return "mühür tutmuyor: kayıt veya ek bilgi değiştirilmiş";
    case BBR_ERR_RANDOM: return "işletim sisteminden rastgele sayı alınamadı";
    default:             return "bilinmeyen hata";
    }
}
