/*
 * ChaCha20 (RFC 8439) doğruluk testi.
 * BU DOSYA ÜRETİLMİŞTİR: python tests/gen_vectors.py
 * Beklenen değerler Python `cryptography` paketinin (OpenSSL) çıktısıdır.
 */
#include <stdlib.h>
#include <string.h>

#include "../tool/chacha20.h"
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

static void pattern(uint8_t *p, size_t n, unsigned mul, unsigned add)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(i * mul + add);
}

/* RFC 8439 §2.4.2 */
static const char *rfc_ct = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";

static const struct { size_t len; uint32_t counter; const char *hex; } vec[] = {
    { 0, 0,
      "" },
    { 1, 0,
      "4e" },
    { 63, 0,
      "4e4ffc98485ab480f95705da326c54fa45ed4a697a136ad5d9905ac6498f812c585da4e5c42319baec9647492337b59be6a904d88f61d5ac4c93736d4a5ba7" },
    { 64, 0,
      "4e4ffc98485ab480f95705da326c54fa45ed4a697a136ad5d9905ac6498f812c585da4e5c42319baec9647492337b59be6a904d88f61d5ac4c93736d4a5ba7ea" },
    { 65, 1,
      "62030df575900c82f27cf3aa960b81a37b58e872220b5a40a4253f63dd737110af38458f9719f5030780d01e916b5a45c296341c872a938afc152dc83ab7bf64b4" },
    { 1000, 7,
      "07e6f9e9842300f4966e330abff5c81993d83ec4f6670c414cbbbc5c799c75c27cdaad309f619632c8795568727546fefe1c9858211b9b896dcccb95120ac9246130e975847d4fb694cb52da061c43a81ad9095aff15589d38e3f486b0de7f576415d7b3a5406045af42e86947a45d36ff91a6a161aa44034fe9770b3527d88231c726fbfa34a3d2fe75a7b3b0b725e7dca098bd40732716b9a8056c0bc9e2b6f03ba1a256e9bf1f6f8afb40cc1ff98a282d5a1c82279d63bd530931681fb0be342d5092a42bec185764e8f77d7ff30af21d2d19b43b9d7ef5ef9de5421335cb1968e5dd2b3992d945d294c7d28a7bd1002179ad81ae19a8078732a097d4774e8301cdea98f93bab2ff21cf1c0d06c854e5a69b783066ab6d715f7374acd994e15cccb86224ea91010cb15f8ac913072607349d3606421782921043e25b55577b8bf301517b528d4338674a5b427a117cfdb6877b06cb08577f9bfdfa1da7e6efc00e2e54d12f6cfaaa4fb6b67a79853dc6c22eabd620b14c91e96b572582d60e9a61191549e81f693352f5cac64dec88d4c2efc843587043adda44cffa5b97f5b5885de08f65c69faf0db166ed5f330a290c4b8cd0afbcc5898f223e1f484bbae6f00b59ffcdfb01ade61406da8c638c80173bc52fa2d55e88a2a2383a5fe9e3296f679a0e19b416c5a191e9dc6cbbf6f5148a401527b63a19768168123ef875974cb3561c9f7f09aa6e9cf1cf8399796bafc16dfc4d7a60ac5a42ba6865d779cdcf75eea58549f241203e5d972ae61f81c1561a6a531a9b48647d2c9330884fb82431504f0e4ff791e027a07f216a9c037dccf2fbecf7e75487e036205c2bfdd049249c219d8d43bda42098a581d4f7248799eae6ca12a1242467accadc91fd2ce8897e00110d2c80f4d67ead2049a0725d6bfdf570ecd26fa17c7769cbdfbffd0bde3a0de1b4d1111be31dac865eadf574a6045c8a0eca81c40b1a71651f703a9b07fd6db3f08780c7e3403c95f052fa780d1491cdd27eddaa444a74cd88e2dc9ff4525df7fee37b7fa14231d0e0b30fecae184a5a739258273d33319f05ab198da24f6ceef1c4ad46222b9116f2e9e7e41c9577db1e99788dfb58ed2e989ded083a31154422de90ae0580799fb3c57bff7056b4441e7f30577f1fa591a57fc5a85c73a644937309db5c398a6c006bc070bac5555cbb4c3ac6235f7cc6a2917d68c699209344cf484235aa33d9d0a4d0231438ff5b5dddeca05e9b56726e4fb7f73d9483bf6e87a3397d6d5b1d40f521b85ba17d8056fcb3ea8bf9963e76b21239389e4a8d2f3fe90c8b0d55838f4ba6076f2f0dd6d546c85c05263cabd2319e09320e86eef566311396995b4881197adaa3c9295afba792482d5775b239dd2e4660091f627d6" },
    { 777, 123456,
      "97583aeaab83943c4b933baf6d840a637f9cd859bf7b99a21576c4a19d089a1357d5a44de5633683d543362fe4956d8a60f423d04d28cf5da5a589a9cce697e27173c2a8bc558ae20d252c69b72c4255f90c34f2c2d7ce7160aaac4b88b96943f7d6b9924b44e2391029f155340ef10ed2b45b758e5a606275e913f60f71f7724fa1545e1f3dc8323e2805295a795d98d2d28869a8a13edb4ce885df08aab6cdc88b70042a9d7e0129b47b512cadb7311a26e1b025f150161553b3d36c2991f14b4ecd24bc7b6f37ccd6f9a85c9c2809a12bef6bf2785922bca26b699c941154dd036dd4b57a33aeb1a570774dc5c725cb0880c8cb572ccd6776e67ab139d610b52fb5fecb2ab51d97ba686dbf7332ee4db8c085d30295d542be3bab791070e03c1fedffbeae873e1225de3d54872d33864f293070cc47e32d1ae52f74a4f93fd1365e80267d7f86be0ab92fdbf5919566de25a29a3dbb83cb48a5865ebeefb390fc85adb4b904dcc0b0a796afbdd1b15ec614e29ea002349995986da46683b303d16a4a1114514d50f7f46913c263042314dbc9229a7206d11c1067eb388559faf6820568500f64f516229a6c2d321a5e5435761e525d2ac35cc040cfb2ac7509df4484d70caac6965450b2ccd500ac667a0684faa4b05b47959b6abc1879f50053705ded65808c8bf95d696f0f8c51d8170c1ae27a1af2dedd38a689cbc03f40ed68f59666dc0be7de5c7ad424492a02728be0d65f747b9450c39f884428d6d5b789f75adedc7d2b86b2a65730da409ae57cff48b86a5cb29cb01d8bd102d790d1a20825bb9d73429fdf4df845f7d85dcf2a99552006a0d9edd16c1ca4d4eb460075bd6fe595130cd8d4ed8f245650585ca80ad738fb9590650a4db0dec0e53f3a2f8370acfdb05789a15116ccd8f1bab8f5b5b624bae5c757e630689443f6c75626201dd86d7900075cdc403f4ea4352a7d75e1460af6a777ebb18e403b81613a313c7c5801ba78d1ef7a435c79f1618d16e727d2f453d06abcceb465b44b0f43f00bc21fda157acf1ddd187448b5cc9f4fdd9475ecc0b10217e0be4a45b4dd17eaa01b2a6bc635" },
};

static void test_rfc(void)
{
    static const char pt[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t key[32], nonce[12] = { 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 }, out[sizeof pt];
    char hex[2 * sizeof pt + 1];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    chacha20_xor(key, nonce, 1, (const uint8_t *)pt, out, sizeof pt - 1);
    tohex(out, sizeof pt - 1, hex);
    CHECK(strcmp(hex, rfc_ct) == 0);
}

static void test_vectors(void)
{
    uint8_t key[32], nonce12[12], nonce[12], m[1000], out[1000], io[1000];
    char hex[2 * 1000 + 1];
    pattern(key, 32, 13, 1);
    pattern(nonce12, 12, 7, 3);
    for (int i = 0; i < 12; i++) nonce[i] = nonce12[11 - i];
    for (size_t i = 0; i < sizeof vec / sizeof vec[0]; i++) {
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
    }
}

int main(int argc, char **argv)
{
    tu_init("test_chacha20", argc, argv);
    test_rfc();
    test_vectors();
    return tu_finish("test_chacha20");
}
