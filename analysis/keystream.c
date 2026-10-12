/*
 * CTR anahtar akışını stdout'a ikili olarak yazar (PractRand gibi istatistik
 * test paketlerine boru ile vermek için):
 *
 *   keystream <tur> <anahtar: sifir|rastgele|desen> [bayt_sınırı]
 *
 * Nonce sıfır, sayaç 0'dan artar: ardışık sayaçlar şifre için en "yapılı"
 * girdidir, istatistiksel zayıflık varsa en kolay burada görünür.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"

#if defined(_WIN32)
#  include <fcntl.h>
#  include <io.h>
#endif

#define BUF (BB416_BLOCK_BYTES * 4096)

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "kullanım: keystream <tur> <sifir|rastgele|desen> [bayt_sınırı]\n");
        return 1;
    }
#if defined(_WIN32)
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    int rounds = atoi(argv[1]);
    unsigned long long limit = argc > 3 ? strtoull(argv[3], NULL, 0) : 0;

    uint8_t key[BB416_KEY_BYTES] = { 0 }, nonce[BB416_NONCE_BYTES] = { 0 };
    if (strcmp(argv[2], "rastgele") == 0) {
        unsigned long long x = 0x123456789ABCDEFULL;
        for (int i = 0; i < BB416_KEY_BYTES; i++) {
            x = x * 6364136223846793005ULL + 1442695040888963407ULL;
            key[i] = (uint8_t)(x >> 56);
        }
    } else if (strcmp(argv[2], "desen") == 0) {
        for (int i = 0; i < BB416_KEY_BYTES; i++) key[i] = (uint8_t)i;
    }

    static bb416_ctx ctx;
    if (bb416_init(&ctx, key, rounds) != BB416_OK) {
        fprintf(stderr, "geçersiz tur sayısı\n");
        return 1;
    }

    static uint8_t zero[BUF], out[BUF];
    unsigned long long written = 0;
    uint64_t counter = 0;
    for (;;) {
        bb416_ctr_xor(&ctx, nonce, counter, zero, out, BUF);
        counter += BUF / BB416_BLOCK_BYTES;
        size_t n = BUF;
        if (limit && written + n > limit) n = (size_t)(limit - written);
        if (fwrite(out, 1, n, stdout) != n) break; /* okuyucu kapandı */
        written += n;
        if (limit && written >= limit) break;
    }
    return 0;
}
