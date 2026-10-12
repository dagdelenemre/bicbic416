"""
tests/test_sha256.c ve tests/test_chacha20.c'yi üretir. Beklenen değerler Python'un
hashlib/hmac modüllerinden ve `cryptography` paketinden (ikisi de OpenSSL) gelir;
böylece tool/sha256.c ve tool/chacha20.c bağımsız, yaygın uygulamalara karşı sınanır.

Kullanım: pip install cryptography && python tests/gen_vectors.py
"""
import hashlib
import hmac
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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

# (IKM, tuz, info, çıktı uzunluğu). İlki RFC 5869 test durumu 1; sonuncusu dosya
# biçimi v2'nin kullandığı biçim (32 bayt IKM, boş tuz, 116 bayt çıktı).
HKDF_CASES = [
    (b"\x0b" * 22, bytes(range(13)), bytes(range(0xF0, 0xFA)), 42),
    (key(32), b"", b"", 32),
    (key(80), msg(80), b"x" * 80, 82),
    (key(32), b"", b"BicBic416 v2 anahtarlar", 116),
]


def hkdf(ikm, salt, info, n):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt or None, info=info).derive(ikm)


hkdf_rows = "\n".join(
    f'    {{ {cstr(i)}, {len(i)}, {cstr(s)}, {len(s)}, {cstr(f)}, {len(f)}, {n},\n'
    f'      "{hkdf(i, s, f, n).hex()}" }},'
    for i, s, f, n in HKDF_CASES)

SRC = f'''/*
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

static const struct {{
    const char *ikm; size_t ikmlen; const char *salt; size_t saltlen;
    const char *info; size_t infolen; size_t outlen; const char *hex;
}} hkdf_vec[] = {{
{hkdf_rows}
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

static void test_hkdf(void)
{{
    uint8_t out[128];
    char hex[2 * 128 + 1];
    for (size_t i = 0; i < sizeof hkdf_vec / sizeof hkdf_vec[0]; i++) {{
        hkdf_sha256((const uint8_t *)hkdf_vec[i].salt, hkdf_vec[i].saltlen,
                    (const uint8_t *)hkdf_vec[i].ikm, hkdf_vec[i].ikmlen,
                    (const uint8_t *)hkdf_vec[i].info, hkdf_vec[i].infolen, out, hkdf_vec[i].outlen);
        tohex(out, hkdf_vec[i].outlen, hex);
        CHECK(strcmp(hex, hkdf_vec[i].hex) == 0);
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
    test_hkdf();
    test_ct_memcmp();
    return tu_finish("test_sha256");
}}
'''

# ---- ChaCha20 (RFC 8439) ----------------------------------------------------

SUNSCREEN = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
             b"for the future, sunscreen would be it.")
RFC_KEY = bytes(range(32))
RFC_NONCE = bytes.fromhex("000000000000004a00000000")


def chacha(k, nonce, counter, data):
    full_nonce = counter.to_bytes(4, "little") + nonce
    return Cipher(algorithms.ChaCha20(k, full_nonce), mode=None).encryptor().update(data)


# (uzunluk, sayaç). Anahtar = key(32), nonce = msg(12)[::-1], veri = msg(uzunluk).
CHACHA_CASES = [(0, 0), (1, 0), (63, 0), (64, 0), (65, 1), (1000, 7), (777, 123456)]
cc_rows = "\n".join(
    f'    {{ {n}, {c},\n      "{chacha(key(32), msg(12)[::-1], c, msg(n)).hex()}" }},'
    for n, c in CHACHA_CASES)

CHACHA_SRC = f'''/*
 * ChaCha20 (RFC 8439) doğruluk testi.
 * BU DOSYA ÜRETİLMİŞTİR: python tests/gen_vectors.py
 * Beklenen değerler Python `cryptography` paketinin (OpenSSL) çıktısıdır.
 */
#include <stdlib.h>
#include <string.h>

#include "../tool/chacha20.h"
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

static void pattern(uint8_t *p, size_t n, unsigned mul, unsigned add)
{{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(i * mul + add);
}}

/* RFC 8439 §2.4.2 */
static const char *rfc_ct = "{chacha(RFC_KEY, RFC_NONCE, 1, SUNSCREEN).hex()}";

static const struct {{ size_t len; uint32_t counter; const char *hex; }} vec[] = {{
{cc_rows}
}};

static void test_rfc(void)
{{
    static const char pt[] = "{SUNSCREEN.decode()}";
    uint8_t key[32], nonce[12] = {{ 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 }}, out[sizeof pt];
    char hex[2 * sizeof pt + 1];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    chacha20_xor(key, nonce, 1, (const uint8_t *)pt, out, sizeof pt - 1);
    tohex(out, sizeof pt - 1, hex);
    CHECK(strcmp(hex, rfc_ct) == 0);
}}

static void test_vectors(void)
{{
    uint8_t key[32], nonce12[12], nonce[12], m[1000], out[1000], io[1000];
    char hex[2 * 1000 + 1];
    pattern(key, 32, 13, 1);
    pattern(nonce12, 12, 7, 3);
    for (int i = 0; i < 12; i++) nonce[i] = nonce12[11 - i];
    for (size_t i = 0; i < sizeof vec / sizeof vec[0]; i++) {{
        size_t n = vec[i].len;
        pattern(m, n, 7, 3);
        chacha20_xor(key, nonce, vec[i].counter, m, out, n);
        tohex(out, n, hex);
        CHECK(strcmp(hex, vec[i].hex) == 0);

        /* Yerinde çalışma ve 64 baytlık blok sınırlarında parça parça işleme. */
        memcpy(io, m, n);
        size_t half = (n / 2) & ~(size_t)63;
        chacha20_xor(key, nonce, vec[i].counter, io, io, half);
        chacha20_xor(key, nonce, vec[i].counter + (uint32_t)(half / 64), io + half, io + half, n - half);
        CHECK(memcmp(io, out, n) == 0);
    }}
}}

int main(int argc, char **argv)
{{
    tu_init("test_chacha20", argc, argv);
    test_rfc();
    test_vectors();
    return tu_finish("test_chacha20");
}}
'''

here = Path(__file__).resolve().parent
for name, text in (("test_sha256.c", SRC), ("test_chacha20.c", CHACHA_SRC)):
    (here / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"yazıldı: {here / name}")
