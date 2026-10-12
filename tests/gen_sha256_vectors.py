"""
tests/test_sha256.c'yi üretir. Beklenen değerler Python'un hashlib/hmac modüllerinden
(OpenSSL) gelir; böylece tool/sha256.c bağımsız, yaygın bir uygulamaya karşı sınanır.

Kullanım: python tests/gen_sha256_vectors.py
"""
import hashlib
import hmac
from pathlib import Path


def msg(n):
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


def key(n):
    return bytes((i * 13 + 1) & 0xFF for i in range(n))


def cstr(b):
    return '"' + "".join(f"\\x{c:02x}" for c in b) + '"'


SHA_LENS = [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1000, 100000]
HMAC_CASES = [(0, 0), (20, 8), (32, 100), (64, 50), (65, 50), (131, 54), (131, 152)]
PBKDF2_CASES = [
    (b"passwd", b"salt", 1, 64),
    (b"Password", b"NaCl", 80000, 64),
    (b"", b"salt", 2, 32),
    (b"parola", b"tuz-tuz-tuz-tuz!", 1000, 84),
    (b"x" * 100, b"s", 3, 33),
]

sha_rows = "\n".join(f'    {{ {n}, "{hashlib.sha256(msg(n)).hexdigest()}" }},' for n in SHA_LENS)
hmac_rows = "\n".join(
    f'    {{ {k}, {m}, "{hmac.new(key(k), msg(m), hashlib.sha256).hexdigest()}" }},'
    for k, m in HMAC_CASES)
pb_rows = "\n".join(
    f'    {{ {cstr(pw)}, {len(pw)}, {cstr(s)}, {len(s)}, {it}, {dl}, '
    f'"{hashlib.pbkdf2_hmac("sha256", pw, s, it, dl).hex()}" }},'
    for pw, s, it, dl in PBKDF2_CASES)

SRC = f'''/*
 * SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256 doğruluk testi.
 * BU DOSYA ÜRETİLMİŞTİR: python tests/gen_sha256_vectors.py
 * Beklenen değerler Python hashlib/hmac (OpenSSL) çıktısıdır.
 * Mesaj deseni: msg[i] = (7*i + 3) mod 256; anahtar deseni: key[i] = (13*i + 1) mod 256.
 */
#include <stdlib.h>
#include <string.h>

#include "../tool/sha256.h"
#include "test_util.h"

static void tohex(const uint8_t *p, size_t n, char *out)
{{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {{
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }}
    out[2 * n] = 0;
}}

static uint8_t *pattern(size_t n, unsigned mul, unsigned add)
{{
    uint8_t *p = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(i * mul + add);
    return p;
}}

static const struct {{ size_t len; const char *hex; }} sha_vec[] = {{
{sha_rows}
}};

static const struct {{ size_t klen, mlen; const char *hex; }} hmac_vec[] = {{
{hmac_rows}
}};

static const struct {{
    const char *pw; size_t pwlen; const char *salt; size_t saltlen;
    uint32_t it; size_t dklen; const char *hex;
}} pb_vec[] = {{
{pb_rows}
}};

static void test_sha256(void)
{{
    uint8_t d[SHA256_BYTES];
    char hex[2 * SHA256_BYTES + 1];

    sha256("abc", 3, d);
    tohex(d, sizeof d, hex);
    CHECK(strcmp(hex, "{hashlib.sha256(b"abc").hexdigest()}") == 0);

    for (size_t i = 0; i < sizeof sha_vec / sizeof sha_vec[0]; i++) {{
        uint8_t *m = pattern(sha_vec[i].len, 7, 3);
        sha256(m, sha_vec[i].len, d);
        tohex(d, sizeof d, hex);
        CHECK(strcmp(hex, sha_vec[i].hex) == 0);

        /* Parça parça besleme aynı sonucu vermeli. */
        sha256_ctx c;
        sha256_init(&c);
        for (size_t off = 0; off < sha_vec[i].len;) {{
            size_t take = 1 + tu_rand32() % 97u;
            if (take > sha_vec[i].len - off)
                take = sha_vec[i].len - off;
            sha256_update(&c, m + off, take);
            off += take;
        }}
        sha256_final(&c, d);
        tohex(d, sizeof d, hex);
        CHECK(strcmp(hex, sha_vec[i].hex) == 0);
        free(m);
    }}
}}

static void test_hmac(void)
{{
    uint8_t d[SHA256_BYTES];
    char hex[2 * SHA256_BYTES + 1];
    for (size_t i = 0; i < sizeof hmac_vec / sizeof hmac_vec[0]; i++) {{
        uint8_t *k = pattern(hmac_vec[i].klen, 13, 1), *m = pattern(hmac_vec[i].mlen, 7, 3);
        hmac_sha256(k, hmac_vec[i].klen, m, hmac_vec[i].mlen, d);
        tohex(d, sizeof d, hex);
        CHECK(strcmp(hex, hmac_vec[i].hex) == 0);
        free(k);
        free(m);
    }}
}}

static void test_pbkdf2(void)
{{
    uint8_t dk[128];
    char hex[2 * 128 + 1];
    for (size_t i = 0; i < sizeof pb_vec / sizeof pb_vec[0]; i++) {{
        pbkdf2_hmac_sha256(pb_vec[i].pw, pb_vec[i].pwlen, (const uint8_t *)pb_vec[i].salt,
                           pb_vec[i].saltlen, pb_vec[i].it, dk, pb_vec[i].dklen);
        tohex(dk, pb_vec[i].dklen, hex);
        CHECK(strcmp(hex, pb_vec[i].hex) == 0);
    }}
}}

static void test_ct_memcmp(void)
{{
    uint8_t a[32] = {{ 0 }}, b[32] = {{ 0 }};
    CHECK(ct_memcmp(a, b, 32) == 0);
    for (int i = 0; i < 32; i++) {{
        b[i] = 1;
        CHECK(ct_memcmp(a, b, 32) != 0);
        b[i] = 0;
    }}
}}

int main(int argc, char **argv)
{{
    tu_init("test_sha256", argc, argv);
    test_sha256();
    test_hmac();
    test_pbkdf2();
    test_ct_memcmp();
    return tu_finish("test_sha256");
}}
'''

out = Path(__file__).resolve().parent / "test_sha256.c"
out.write_text(SRC, encoding="utf-8", newline="\n")
print(f"yazıldı: {out}")
