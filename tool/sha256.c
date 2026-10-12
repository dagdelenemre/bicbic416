#include "sha256.h"

#include <string.h>

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static inline uint32_t ror(uint32_t x, unsigned r) { return (x >> r) | (x << (32u - r)); }

static void compress(uint32_t h[8], const uint8_t p[SHA256_BLOCK])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
               (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = k + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += k;
    wipe(w, sizeof w);
}

void sha256_init(sha256_ctx *c)
{
    static const uint32_t iv[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->used = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = data;
    c->total += len;
    if (c->used) {
        size_t take = SHA256_BLOCK - c->used;
        if (take > len) take = len;
        memcpy(c->buf + c->used, p, take);
        c->used += take;
        p += take;
        len -= take;
        if (c->used < SHA256_BLOCK)
            return;
        compress(c->h, c->buf);
        c->used = 0;
    }
    for (; len >= SHA256_BLOCK; p += SHA256_BLOCK, len -= SHA256_BLOCK)
        compress(c->h, p);
    if (len) {
        memcpy(c->buf, p, len);
        c->used = len;
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[SHA256_BYTES])
{
    uint64_t bits = c->total * 8u;
    uint8_t pad[SHA256_BLOCK + 8] = { 0x80 };
    size_t padlen = (c->used < 56) ? 56 - c->used : 120 - c->used;
    for (int i = 0; i < 8; i++)
        pad[padlen + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, pad, padlen + 8);
    for (int i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
    wipe(c, sizeof *c);
}

void sha256(const void *data, size_t len, uint8_t out[SHA256_BYTES])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void hmac_sha256_init(hmac_sha256_ctx *c, const void *key, size_t key_len)
{
    uint8_t k[SHA256_BLOCK] = { 0 }, pad[SHA256_BLOCK];
    if (key_len > SHA256_BLOCK)
        sha256(key, key_len, k);
    else
        memcpy(k, key, key_len);

    for (int i = 0; i < SHA256_BLOCK; i++) pad[i] = k[i] ^ 0x36;
    sha256_init(&c->inner);
    sha256_update(&c->inner, pad, sizeof pad);
    for (int i = 0; i < SHA256_BLOCK; i++) pad[i] = k[i] ^ 0x5c;
    sha256_init(&c->outer);
    sha256_update(&c->outer, pad, sizeof pad);
    wipe(k, sizeof k);
    wipe(pad, sizeof pad);
}

void hmac_sha256_update(hmac_sha256_ctx *c, const void *data, size_t len)
{
    sha256_update(&c->inner, data, len);
}

void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[SHA256_BYTES])
{
    uint8_t ih[SHA256_BYTES];
    sha256_final(&c->inner, ih);
    sha256_update(&c->outer, ih, sizeof ih);
    sha256_final(&c->outer, out);
    wipe(ih, sizeof ih);
}

void hmac_sha256(const void *key, size_t key_len, const void *data, size_t len,
                 uint8_t out[SHA256_BYTES])
{
    hmac_sha256_ctx c;
    hmac_sha256_init(&c, key, key_len);
    hmac_sha256_update(&c, data, len);
    hmac_sha256_final(&c, out);
}

void pbkdf2_hmac_sha256(const void *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len)
{
    hmac_sha256_ctx base, c;
    uint8_t u[SHA256_BYTES], t[SHA256_BYTES];

    /* Parola anahtarlı HMAC durumu bir kez hazırlanır, her yinelemede kopyalanır. */
    hmac_sha256_init(&base, pass, pass_len);
    for (uint32_t block = 1; out_len; block++) {
        uint8_t be[4] = { (uint8_t)(block >> 24), (uint8_t)(block >> 16),
                          (uint8_t)(block >> 8), (uint8_t)block };
        c = base;
        hmac_sha256_update(&c, salt, salt_len);
        hmac_sha256_update(&c, be, 4);
        hmac_sha256_final(&c, u);
        memcpy(t, u, sizeof t);
        for (uint32_t it = 1; it < iterations; it++) {
            c = base;
            hmac_sha256_update(&c, u, sizeof u);
            hmac_sha256_final(&c, u);
            for (int i = 0; i < SHA256_BYTES; i++)
                t[i] ^= u[i];
        }
        size_t take = out_len < SHA256_BYTES ? out_len : SHA256_BYTES;
        memcpy(out, t, take);
        out += take;
        out_len -= take;
    }
    wipe(&base, sizeof base);
    wipe(&c, sizeof c);
    wipe(u, sizeof u);
    wipe(t, sizeof t);
}

int ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= x[i] ^ y[i];
    return d != 0;
}

void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--)
        *v++ = 0;
}
