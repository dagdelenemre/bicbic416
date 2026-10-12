#include "chacha20.h"

#include "sha256.h" /* wipe */

static inline uint32_t rol(uint32_t x, unsigned r) { return (x << r) | (x >> (32u - r)); }

static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define QR(a, b, c, d)                                  \
    a += b; d ^= a; d = rol(d, 16);                     \
    c += d; b ^= c; b = rol(b, 12);                     \
    a += b; d ^= a; d = rol(d, 8);                      \
    c += d; b ^= c; b = rol(b, 7);

static void block(const uint32_t in[16], uint8_t out[CHACHA20_BLOCK_BYTES])
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]) QR(x[1], x[5], x[9],  x[13])
        QR(x[2], x[6], x[10], x[14]) QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15]) QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[8],  x[13]) QR(x[3], x[4], x[9],  x[14])
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        out[4 * i]     = (uint8_t)v;
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
    wipe(x, sizeof x);
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY_BYTES], const uint8_t nonce[CHACHA20_NONCE_BYTES],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t len)
{
    uint32_t st[16] = { 0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u }; /* "expand 32-byte k" */
    uint8_t ks[CHACHA20_BLOCK_BYTES];
    for (int i = 0; i < 8; i++) st[4 + i] = le32(key + 4 * i);
    st[12] = counter;
    for (int i = 0; i < 3; i++) st[13 + i] = le32(nonce + 4 * i);

    while (len) {
        block(st, ks);
        size_t take = len < CHACHA20_BLOCK_BYTES ? len : CHACHA20_BLOCK_BYTES;
        for (size_t i = 0; i < take; i++)
            out[i] = in[i] ^ ks[i];
        in += take;
        out += take;
        len -= take;
        st[12]++;
    }
    wipe(st, sizeof st);
    wipe(ks, sizeof ks);
}
