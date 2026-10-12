/*
 * Aşama 1: rotl32, rotr32, bitrev32, mulinv32, ROT tablosu, LE yükleme/saklama.
 * Hızlı uygulamalar, bit bit çalışan basit referans uygulamalarla karşılaştırılır.
 */
#include "bb416_internal.h"
#include "test_util.h"

static uint32_t ref_rotl(uint32_t x, unsigned r)
{
    uint32_t y = 0;
    for (unsigned b = 0; b < 32; b++)
        if ((x >> b) & 1u)
            y |= 1u << ((b + r) & 31u);
    return y;
}

static uint32_t ref_bitrev(uint32_t x)
{
    uint32_t y = 0;
    for (unsigned b = 0; b < 32; b++)
        if ((x >> b) & 1u)
            y |= 1u << (31u - b);
    return y;
}

static void test_rotations(void)
{
    for (unsigned r = 0; r < 32; r++) {
        CHECK(rotl32(0x80000001u, r) == ref_rotl(0x80000001u, r));
        for (int k = 0; k < 10000; k++) {
            uint32_t x = tu_rand32();
            CHECK(rotl32(x, r) == ref_rotl(x, r));
            CHECK(rotr32(x, r) == ref_rotl(x, (32u - r) & 31u));
            CHECK(rotr32(rotl32(x, r), r) == x);
        }
    }
    CHECK(rotl32(0x12345678u, 0) == 0x12345678u);
    CHECK(rotr32(0x12345678u, 0) == 0x12345678u);
    CHECK(rotl32(0x12345678u, 8) == 0x34567812u);
    CHECK(rotr32(0x12345678u, 8) == 0x78123456u);
}

static void test_bitrev(void)
{
    CHECK(bitrev32(0x00000000u) == 0x00000000u);
    CHECK(bitrev32(0xFFFFFFFFu) == 0xFFFFFFFFu);
    CHECK(bitrev32(0x00000001u) == 0x80000000u);
    CHECK(bitrev32(0x0000000Fu) == 0xF0000000u);
    CHECK(bitrev32(0x12345678u) == 0x1E6A2C48u);

    for (int k = 0; k < 1000000; k++) {
        uint32_t x = tu_rand32();
        CHECK(bitrev32(x) == ref_bitrev(x));
        CHECK(bitrev32(bitrev32(x)) == x);
    }
}

static void test_mulinv(void)
{
    static const uint32_t edge[] = {
        1u, 3u, 5u, 0xFFFFFFFFu, 0x80000001u, 0x7FFFFFFFu,
        0x2545F491u /* KS_MUL */, 0x9E3779B9u
    };
    for (size_t i = 0; i < sizeof edge / sizeof edge[0]; i++)
        CHECK(edge[i] * mulinv32(edge[i]) == 1u);
    CHECK(mulinv32(0xFFFFFFFFu) == 0xFFFFFFFFu); /* -1'in tersi kendisi */

    for (int k = 0; k < 1000000; k++) {
        uint32_t a = tu_rand32() | 1u;
        uint32_t inv = mulinv32(a);
        CHECK(a * inv == 1u);
        CHECK(inv * a == 1u);
    }
}

static void test_rot_table(void)
{
    for (unsigned i = 0; i < 13; i++) {
        CHECK(BB416_ROT[i] == ((13u * i + 3u) & 31u));
        CHECK(BB416_ROT[i] != 0u);
        CHECK(BB416_ROT[i] < 32u);
        for (unsigned j = 0; j < i; j++)
            CHECK(BB416_ROT[i] != BB416_ROT[j]);
    }
}

static void test_load_store(void)
{
    const uint8_t b[4] = { 0x01, 0x02, 0x03, 0x04 };
    CHECK(load32_le(b) == 0x04030201u);

    uint8_t out[4];
    store32_le(out, 0xA1B2C3D4u);
    CHECK(out[0] == 0xD4 && out[1] == 0xC3 && out[2] == 0xB2 && out[3] == 0xA1);

    for (int k = 0; k < 100000; k++) {
        uint32_t x = tu_rand32();
        store32_le(out, x);
        CHECK(load32_le(out) == x);
    }
}

int main(int argc, char **argv)
{
    tu_init("test_helpers", argc, argv);
    test_rotations();
    test_bitrev();
    test_mulinv();
    test_rot_table();
    test_load_store();
    return tu_finish("test_helpers");
}
