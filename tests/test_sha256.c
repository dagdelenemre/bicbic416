/*
 * SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256 doğruluk testi.
 * BU DOSYA ÜRETİLMİŞTİR: python tests/gen_vectors.py
 * Beklenen değerler Python hashlib/hmac (OpenSSL) çıktısıdır.
 * Mesaj deseni: msg[i] = (7*i + 3) mod 256; anahtar deseni: key[i] = (13*i + 1) mod 256.
 */
#include <stdlib.h>
#include <string.h>

#include "../tool/sha256.h"
#include "test_util.h"

static void tohex(const uint8_t *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = 0;
}

static uint8_t *pattern(size_t n, unsigned mul, unsigned add)
{
    uint8_t *p = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(i * mul + add);
    return p;
}

static const struct { size_t len; const char *hex; } sha_vec[] = {
    { 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { 1, "084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5" },
    { 3, "6ab0dba1f4f1dfbb37b4f9eeb092c09fca4900ad32bdcd147d8dde35d6c87c35" },
    { 55, "e7313d333c272e639f790978283f9eb392e843d0f29b7016828bb1daa4aac70b" },
    { 56, "4324d65f3c103567f5589c710bc08f8523f929a9272e3af36fc968e52abc6c27" },
    { 57, "35df609437dcfea3279283ab79fd554e2bf78f8f7ae2de532d8ee300b09e8f73" },
    { 63, "81c80242132f230c3bd41b3e63bbcff16107339549214a99614ff26664625055" },
    { 64, "39e3d7b6b5d075d37d053ad89b24b41bef4f3c29760c84447cab3f3be1882241" },
    { 65, "aacca6ff74fdbb296d165a45cecfa04e5127bc008770fbbdd48006f2d2fae95e" },
    { 119, "9ce7368e4daf32341631b492e80359dc9f594b48453cd0dd5bf0b19279cc177e" },
    { 120, "7836b787757e95e58b3ca5aec90b1b004e8deba1e50e9675af9cabf1a13a04b5" },
    { 127, "a8d23e75d936f303d248888d9b165ee543f4cbafcad3c9dd2a79bd84faa11d07" },
    { 128, "d2742f1f4ac6bb7ca2b239ee18402ba8b3f9f8e652d2a72973c2b9ba11c08cf6" },
    { 1000, "1e9bc38cbf860b9ec31918b065f9b52476c549a782e0e7990bed8ce3868d2371" },
    { 100000, "d96bab6a55ee326ba206dd4a85a6e95e14360d7fabbf448f03e689c24382b7d0" },
};

static const struct { size_t klen, mlen; const char *hex; } hmac_vec[] = {
    { 0, 0, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad" },
    { 20, 8, "89f9d7f95a02180c5ef1e6674810cbd28a5445d0f2e03a07dc61d0fc2a1f98e6" },
    { 32, 100, "0360ab2058d2a911e29a7e1c298a0e0fc0af5c99e32c3efb96ef18758827b9cb" },
    { 64, 50, "2bb74f06e144e3d005e80db06f249e0a6dff0ae0afb0f50d9bf4a1763566d4a1" },
    { 65, 50, "b7bfb090e4bb5ca0fa577759b79b96fdffe081739971bbcc0da2ee585ea9340e" },
    { 131, 54, "08c200c4cfdd759ddd6475428f51056252cd2963782c7df5a875119aba81f3ae" },
    { 131, 152, "73d0372fd1cb36c6aacceee69ec35b9f63a7800961cd028d95e3681b7ab6b0b8" },
};

static const struct {
    const char *pw; size_t pwlen; const char *salt; size_t saltlen;
    uint32_t it; size_t dklen; const char *hex;
} pb_vec[] = {
    { "\x70\x61\x73\x73\x77\x64", 6, "\x73\x61\x6c\x74", 4, 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783" },
    { "\x50\x61\x73\x73\x77\x6f\x72\x64", 8, "\x4e\x61\x43\x6c", 4, 80000, 64, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d" },
    { "", 0, "\x73\x61\x6c\x74", 4, 2, 32, "62384466264daadc4144018c6bd864648272b34da8980d31521ffcce92ae003b" },
    { "\x70\x61\x72\x6f\x6c\x61", 6, "\x74\x75\x7a\x2d\x74\x75\x7a\x2d\x74\x75\x7a\x2d\x74\x75\x7a\x21", 16, 1000, 84, "bd48f06722e00d4032f234dae3e073f6ebe1091a8a32608356732473cf9e3ea94522536424ca0b06c40c2d23135d50450759e9997fdc14aed3d606a00487a5aac16f29dfd2d602976305beeaf0f9a7331d4316ab" },
    { "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78", 100, "\x73", 1, 3, 33, "3857cac27a1348771a95e77308b6c8908827d474efb9772f9248e7358c87f17169" },
};

static const struct {
    const char *ikm; size_t ikmlen; const char *salt; size_t saltlen;
    const char *info; size_t infolen; size_t outlen; const char *hex;
} hkdf_vec[] = {
    { "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 22, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c", 13, "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9", 10, 42,
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" },
    { "\x01\x0e\x1b\x28\x35\x42\x4f\x5c\x69\x76\x83\x90\x9d\xaa\xb7\xc4\xd1\xde\xeb\xf8\x05\x12\x1f\x2c\x39\x46\x53\x60\x6d\x7a\x87\x94", 32, "", 0, "", 0, 32,
      "56987923696855724e745fb0cbbde844270dd3b053719f9fce66b496b7958c9b" },
    { "\x01\x0e\x1b\x28\x35\x42\x4f\x5c\x69\x76\x83\x90\x9d\xaa\xb7\xc4\xd1\xde\xeb\xf8\x05\x12\x1f\x2c\x39\x46\x53\x60\x6d\x7a\x87\x94\xa1\xae\xbb\xc8\xd5\xe2\xef\xfc\x09\x16\x23\x30\x3d\x4a\x57\x64\x71\x7e\x8b\x98\xa5\xb2\xbf\xcc\xd9\xe6\xf3\x00\x0d\x1a\x27\x34\x41\x4e\x5b\x68\x75\x82\x8f\x9c\xa9\xb6\xc3\xd0\xdd\xea\xf7\x04", 80, "\x03\x0a\x11\x18\x1f\x26\x2d\x34\x3b\x42\x49\x50\x57\x5e\x65\x6c\x73\x7a\x81\x88\x8f\x96\x9d\xa4\xab\xb2\xb9\xc0\xc7\xce\xd5\xdc\xe3\xea\xf1\xf8\xff\x06\x0d\x14\x1b\x22\x29\x30\x37\x3e\x45\x4c\x53\x5a\x61\x68\x6f\x76\x7d\x84\x8b\x92\x99\xa0\xa7\xae\xb5\xbc\xc3\xca\xd1\xd8\xdf\xe6\xed\xf4\xfb\x02\x09\x10\x17\x1e\x25\x2c", 80, "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78", 80, 82,
      "3dae2c45514085a5f35b0caf38fa342ad0971ff585a05739cebac8b32de387fb12958f0f23f6e68ebe541d72e072845732d6152655fa5f1184087be987f422cb9d74492fe0930d74ec7aac95a26ccc9dfb1a" },
    { "\x01\x0e\x1b\x28\x35\x42\x4f\x5c\x69\x76\x83\x90\x9d\xaa\xb7\xc4\xd1\xde\xeb\xf8\x05\x12\x1f\x2c\x39\x46\x53\x60\x6d\x7a\x87\x94", 32, "", 0, "\x42\x69\x63\x42\x69\x63\x34\x31\x36\x20\x76\x32\x20\x61\x6e\x61\x68\x74\x61\x72\x6c\x61\x72", 23, 116,
      "d08cf6be1e2fe7b21154e84ba9f04e2b8899d012f3ce266577c975ab4fb21d1f90481df8d0acab7b8f47de9297af60697ce9cdb926bc2a5d07a038ca7636eab251af320050d43db6084f30acff5f44878a225b2423cb17cbda8adc1c98b1ad38ce1ea4db305fe399983b766c9aa7634e0727d241" },
};

static void test_sha256(void)
{
    uint8_t d[SHA256_BYTES];
    char hex[2 * SHA256_BYTES + 1];

    sha256("abc", 3, d);
    tohex(d, sizeof d, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    for (size_t i = 0; i < sizeof sha_vec / sizeof sha_vec[0]; i++) {
        uint8_t *m = pattern(sha_vec[i].len, 7, 3);
        sha256(m, sha_vec[i].len, d);
        tohex(d, sizeof d, hex);
        CHECK(strcmp(hex, sha_vec[i].hex) == 0);

        /* Parça parça besleme aynı sonucu vermeli. */
        sha256_ctx c;
        sha256_init(&c);
        for (size_t off = 0; off < sha_vec[i].len;) {
            size_t take = 1 + tu_rand32() % 97u;
            if (take > sha_vec[i].len - off)
                take = sha_vec[i].len - off;
            sha256_update(&c, m + off, take);
            off += take;
        }
        sha256_final(&c, d);
        tohex(d, sizeof d, hex);
        CHECK(strcmp(hex, sha_vec[i].hex) == 0);
        free(m);
    }
}

static void test_hmac(void)
{
    uint8_t d[SHA256_BYTES];
    char hex[2 * SHA256_BYTES + 1];
    for (size_t i = 0; i < sizeof hmac_vec / sizeof hmac_vec[0]; i++) {
        uint8_t *k = pattern(hmac_vec[i].klen, 13, 1), *m = pattern(hmac_vec[i].mlen, 7, 3);
        hmac_sha256(k, hmac_vec[i].klen, m, hmac_vec[i].mlen, d);
        tohex(d, sizeof d, hex);
        CHECK(strcmp(hex, hmac_vec[i].hex) == 0);
        free(k);
        free(m);
    }
}

static void test_pbkdf2(void)
{
    uint8_t dk[128];
    char hex[2 * 128 + 1];
    for (size_t i = 0; i < sizeof pb_vec / sizeof pb_vec[0]; i++) {
        pbkdf2_hmac_sha256(pb_vec[i].pw, pb_vec[i].pwlen, (const uint8_t *)pb_vec[i].salt,
                           pb_vec[i].saltlen, pb_vec[i].it, dk, pb_vec[i].dklen);
        tohex(dk, pb_vec[i].dklen, hex);
        CHECK(strcmp(hex, pb_vec[i].hex) == 0);
    }
}

static void test_hkdf(void)
{
    uint8_t out[128];
    char hex[2 * 128 + 1];
    for (size_t i = 0; i < sizeof hkdf_vec / sizeof hkdf_vec[0]; i++) {
        hkdf_sha256((const uint8_t *)hkdf_vec[i].salt, hkdf_vec[i].saltlen,
                    (const uint8_t *)hkdf_vec[i].ikm, hkdf_vec[i].ikmlen,
                    (const uint8_t *)hkdf_vec[i].info, hkdf_vec[i].infolen, out, hkdf_vec[i].outlen);
        tohex(out, hkdf_vec[i].outlen, hex);
        CHECK(strcmp(hex, hkdf_vec[i].hex) == 0);
    }
}

static void test_ct_memcmp(void)
{
    uint8_t a[32] = { 0 }, b[32] = { 0 };
    CHECK(ct_memcmp(a, b, 32) == 0);
    for (int i = 0; i < 32; i++) {
        b[i] = 1;
        CHECK(ct_memcmp(a, b, 32) != 0);
        b[i] = 0;
    }
}

int main(int argc, char **argv)
{
    tu_init("test_sha256", argc, argv);
    test_sha256();
    test_hmac();
    test_pbkdf2();
    test_hkdf();
    test_ct_memcmp();
    return tu_finish("test_sha256");
}
