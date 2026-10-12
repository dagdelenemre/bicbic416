/*
 * BicBic416 — eğitim / araştırma amaçlı oyuncak blok şifre. Üretimde KULLANMAYIN.
 * Tasarım: SPEC.md. Bu dosyadaki sabitler orada tanımlıdır, sessizce değiştirilmez.
 *
 * Sabit zamanlı kod: gizli veriye bağlı dal veya dizi indeksi yok; tüm döngü
 * sınırları ve döndürme miktarları sabittir.
 */
#include <assert.h>
#include <string.h>

#include "bicbic416.h"
#include "bb416_internal.h"

/* ---- Adım 1: anahtar ekleme ------------------------------------------- */

void bb416_step1(uint32_t S[13], const uint32_t rk[13])
{
    for (int i = 0; i < 13; i++)
        S[i] ^= rk[i];
}

void bb416_step1_inv(uint32_t S[13], const uint32_t rk[13])
{
    bb416_step1(S, rk);
}

/* ---- Adım 2: anahtarla çarpma + karıştırma ----------------------------- */

void bb416_step2(uint32_t S[13], const uint32_t mk[13])
{
    for (int i = 0; i < 13; i++) {
        S[i] *= mk[i];
        S[i] ^= S[i] >> 16;
    }
}

/* x ^= x >> 16 kendi tersidir: üst 16 bit değişmez, alt 16 bite aynı değer XOR'lanır. */
void bb416_step2_inv(uint32_t S[13], const uint32_t mkinv[13])
{
    for (int i = 0; i < 13; i++) {
        S[i] ^= S[i] >> 16;
        S[i] *= mkinv[i];
    }
}

/* ---- Adım 3: çapraz/satır döndürme ------------------------------------- */

void bb416_step3(uint32_t S[13])
{
    for (int i = 0; i < 13; i++)
        S[i] = rotl32(S[i], BB416_ROT[i]);
}

void bb416_step3_inv(uint32_t S[13])
{
    for (int i = 0; i < 13; i++)
        S[i] = rotr32(S[i], BB416_ROT[i]);
}

/* ---- Adım 4: sarmal çift karıştırma ------------------------------------ */

void bb416_step4(uint32_t S[13])
{
    for (int i = 0; i < 6; i++) {
        int j = 12 - i;
        S[j] += S[i];
        S[i] ^= rotl32(S[j], 7);
    }
}

void bb416_step4_inv(uint32_t S[13])
{
    for (int i = 0; i < 6; i++) {
        int j = 12 - i;
        S[i] ^= rotl32(S[j], 7);
        S[j] -= S[i];
    }
}

/* ---- Adım 5: merkez kelime topla ve dağıt ------------------------------ */

static uint32_t sum_except_center(const uint32_t S[13])
{
    uint32_t t = 0;
    for (int i = 0; i < 13; i++)
        if (i != 6) /* i gizli değil: sabit döngü indeksi */
            t += S[i];
    return t;
}

void bb416_step5(uint32_t S[13])
{
    S[6] += sum_except_center(S);
    for (int i = 0; i < 13; i++)
        if (i != 6)
            S[i] ^= rotl32(S[6], (unsigned)i + 1u);
}

void bb416_step5_inv(uint32_t S[13])
{
    for (int i = 0; i < 13; i++)
        if (i != 6)
            S[i] ^= rotl32(S[6], (unsigned)i + 1u);
    S[6] -= sum_except_center(S);
}

/* ---- Adım 6: sarmal takas ---------------------------------------------- */

void bb416_step6(uint32_t S[13])
{
    for (int i = 0; i < 6; i++) {
        uint32_t t = S[i];
        S[i] = S[12 - i];
        S[12 - i] = t;
    }
    S[6] = bitrev32(S[6]);
}

void bb416_step6_inv(uint32_t S[13])
{
    bb416_step6(S);
}

/* ---- Bellek temizleme -------------------------------------------------- */

/* volatile yazımlar, "sonra okunmuyor" diye derleyicinin silmesini engeller. */
static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

void bb416_wipe(bb416_ctx *ctx)
{
    if (ctx)
        secure_zero(ctx, sizeof *ctx);
}

/* ---- Anahtar planı (SPEC.md §6) ---------------------------------------- */

#define KS_MUL   0x2545F491u
#define KS_GOLD  0x9E3779B9u

/* Anahtarsız karıştırma: sabit çarpan + Adım 2'nin kaydırması + Adım 3–6. */
static void ks_mix(uint32_t K[13])
{
    for (int i = 0; i < 13; i++) {
        K[i] *= KS_MUL;
        K[i] ^= K[i] >> 16;
        K[i] = rotl32(K[i], BB416_ROT[i]);
    }
    bb416_step4(K);
    bb416_step5(K);
    bb416_step6(K);
}

/* üret(): n. çağrıda K[0] ^= (n+1)*KS_GOLD, iki kez karıştır, kopyala. */
static void ks_next(uint32_t K[13], uint32_t *n, uint32_t out[13])
{
    K[0] ^= (*n + 1u) * KS_GOLD;
    ks_mix(K);
    ks_mix(K);
    (*n)++;
    for (int i = 0; i < 13; i++)
        out[i] = K[i];
}

int bb416_init(bb416_ctx *ctx, const uint8_t key[BB416_KEY_BYTES], int rounds)
{
    if (!ctx)
        return BB416_ERR_PARAM;

    /* Önce sıfırla: hata durumunda yarım hazırlanmış ctx kalmaz,
     * başarıda kullanılmayan tur dilimleri de sıfır olur. */
    bb416_wipe(ctx);
    if (!key || rounds < 1 || rounds > BB416_MAX_ROUNDS)
        return BB416_ERR_PARAM;

    uint32_t K[13];
    uint32_t n = 0;
    for (int i = 0; i < 13; i++)
        K[i] = load32_le(key + 4 * i);

    ctx->rounds = rounds;
    for (int r = 0; r < rounds; r++) {
        ks_next(K, &n, ctx->rk[r]);
        ks_next(K, &n, ctx->mk[r]);
        for (int i = 0; i < 13; i++) {
            ctx->mk[r][i] |= 1u;
            ctx->mkinv[r][i] = mulinv32(ctx->mk[r][i]);
        }
    }
    ks_next(K, &n, ctx->rk[rounds]);

    secure_zero(K, sizeof K);
    return BB416_OK;
}

/* ---- Hızlı tur gövdesi --------------------------------------------------
 *
 * Yukarıdaki bb416_stepN fonksiyonları spesifikasyonun okunur hâlidir ve testlerde
 * referans olarak kullanılır. Şifreleme yolunda aynı matematik, 13 kelime için
 * açılmış (unrolled) makrolarla yazılır: kelime indeksleri ve döndürme miktarları
 * sabit olduğundan durum yazmaçlarda kalır. Makrolar hem skaler (uint32_t) hem
 * vektör (çok bloklu) türde çalışır; ROTL/ROTR/BITREV o türün işlemleridir.
 * test_roundtrip, bu yolun bb416_stepN bileşimiyle birebir aynı olduğunu doğrular.
 */

#define BB416_R123(s, t, rk, mk, ROTL, i)                                          \
    t = (s[i] ^ (rk)[i]) * (mk)[i];                                               \
    t ^= t >> 16;                                                                 \
    s[i] = ROTL(t, BB416_ROT[i]);

#define BB416_R123_INV(s, t, rk, mkinv, ROTR, i)                                   \
    t = ROTR(s[i], BB416_ROT[i]);                                                  \
    t ^= t >> 16;                                                                 \
    s[i] = (t * (mkinv)[i]) ^ (rk)[i];

#define BB416_PAIR(s, ROTL, i, j)   s[j] += s[i]; s[i] ^= ROTL(s[j], 7);
#define BB416_UNPAIR(s, ROTL, i, j) s[i] ^= ROTL(s[j], 7); s[j] -= s[i];

#define BB416_SUM12(s)                                                             \
    (((s[0] + s[1]) + (s[2] + s[3])) + ((s[4] + s[5]) + (s[7] + s[8])) +          \
     ((s[9] + s[10]) + (s[11] + s[12])))

#define BB416_SPREAD_ALL(s, ROTL)                                                  \
    s[0] ^= ROTL(s[6], 1);   s[1] ^= ROTL(s[6], 2);   s[2] ^= ROTL(s[6], 3);     \
    s[3] ^= ROTL(s[6], 4);   s[4] ^= ROTL(s[6], 5);   s[5] ^= ROTL(s[6], 6);     \
    s[7] ^= ROTL(s[6], 8);   s[8] ^= ROTL(s[6], 9);   s[9] ^= ROTL(s[6], 10);    \
    s[10] ^= ROTL(s[6], 11); s[11] ^= ROTL(s[6], 12); s[12] ^= ROTL(s[6], 13);

#define BB416_SWAP_ALL(s, t)                                                       \
    t = s[0]; s[0] = s[12]; s[12] = t;   t = s[1]; s[1] = s[11]; s[11] = t;       \
    t = s[2]; s[2] = s[10]; s[10] = t;   t = s[3]; s[3] = s[9];  s[9] = t;        \
    t = s[4]; s[4] = s[8];  s[8] = t;    t = s[5]; s[5] = s[7];  s[7] = t;

/* Tur r'nin ileri yönü (Adım 1–6). s: 13 elemanlı dizi, t: geçici. */
#define BB416_ROUND(s, t, rk, mk, ROTL, BITREV)                                    \
    do {                                                                          \
        BB416_R123(s, t, rk, mk, ROTL, 0)  BB416_R123(s, t, rk, mk, ROTL, 1)       \
        BB416_R123(s, t, rk, mk, ROTL, 2)  BB416_R123(s, t, rk, mk, ROTL, 3)       \
        BB416_R123(s, t, rk, mk, ROTL, 4)  BB416_R123(s, t, rk, mk, ROTL, 5)       \
        BB416_R123(s, t, rk, mk, ROTL, 6)  BB416_R123(s, t, rk, mk, ROTL, 7)       \
        BB416_R123(s, t, rk, mk, ROTL, 8)  BB416_R123(s, t, rk, mk, ROTL, 9)       \
        BB416_R123(s, t, rk, mk, ROTL, 10) BB416_R123(s, t, rk, mk, ROTL, 11)      \
        BB416_R123(s, t, rk, mk, ROTL, 12)                                         \
        BB416_PAIR(s, ROTL, 0, 12) BB416_PAIR(s, ROTL, 1, 11)                       \
        BB416_PAIR(s, ROTL, 2, 10) BB416_PAIR(s, ROTL, 3, 9)                        \
        BB416_PAIR(s, ROTL, 4, 8)  BB416_PAIR(s, ROTL, 5, 7)                        \
        s[6] += BB416_SUM12(s);                                                    \
        BB416_SPREAD_ALL(s, ROTL)                                                  \
        BB416_SWAP_ALL(s, t)                                                       \
        s[6] = BITREV(s[6]);                                                      \
    } while (0)

/* Tur r'nin tersi (Ters Adım 6 → 1). */
#define BB416_ROUND_INV(s, t, rk, mkinv, ROTL, ROTR, BITREV)                       \
    do {                                                                          \
        BB416_SWAP_ALL(s, t)                                                       \
        s[6] = BITREV(s[6]);                                                      \
        BB416_SPREAD_ALL(s, ROTL)                                                  \
        s[6] -= BB416_SUM12(s);                                                    \
        BB416_UNPAIR(s, ROTL, 0, 12) BB416_UNPAIR(s, ROTL, 1, 11)                   \
        BB416_UNPAIR(s, ROTL, 2, 10) BB416_UNPAIR(s, ROTL, 3, 9)                    \
        BB416_UNPAIR(s, ROTL, 4, 8)  BB416_UNPAIR(s, ROTL, 5, 7)                    \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 0)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 1)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 2)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 3)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 4)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 5)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 6)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 7)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 8)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 9)                                   \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 10)                                  \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 11)                                  \
        BB416_R123_INV(s, t, rk, mkinv, ROTR, 12)                                  \
    } while (0)

/* ---- Blok şifreleme / çözme (SPEC.md §4–5) ----------------------------- */

static void load_block(uint32_t S[13], const uint8_t in[BB416_BLOCK_BYTES])
{
    for (int i = 0; i < 13; i++)
        S[i] = load32_le(in + 4 * i);
}

static void store_block(uint8_t out[BB416_BLOCK_BYTES], const uint32_t S[13])
{
    for (int i = 0; i < 13; i++)
        store32_le(out + 4 * i, S[i]);
}

/* Tüm blok önce duruma yüklenip sonra yazıldığı için in == out güvenlidir. */
void bb416_encrypt_block(const bb416_ctx *ctx, const uint8_t in[BB416_BLOCK_BYTES],
                        uint8_t out[BB416_BLOCK_BYTES])
{
    assert(ctx && in && out);
    assert(ctx->rounds >= 1 && ctx->rounds <= BB416_MAX_ROUNDS);

    uint32_t s[13], t;
    const int R = ctx->rounds;

    load_block(s, in);
    for (int r = 0; r < R; r++)
        BB416_ROUND(s, t, ctx->rk[r], ctx->mk[r], rotl32, bitrev32);
    for (int i = 0; i < 13; i++)
        s[i] ^= ctx->rk[R][i]; /* son beyazlatma */
    store_block(out, s);
    secure_zero(s, sizeof s);
    secure_zero(&t, sizeof t);
}

void bb416_decrypt_block(const bb416_ctx *ctx, const uint8_t in[BB416_BLOCK_BYTES],
                        uint8_t out[BB416_BLOCK_BYTES])
{
    assert(ctx && in && out);
    assert(ctx->rounds >= 1 && ctx->rounds <= BB416_MAX_ROUNDS);

    uint32_t s[13], t;
    const int R = ctx->rounds;

    load_block(s, in);
    for (int i = 0; i < 13; i++)
        s[i] ^= ctx->rk[R][i];
    for (int r = R - 1; r >= 0; r--)
        BB416_ROUND_INV(s, t, ctx->rk[r], ctx->mkinv[r], rotl32, rotr32, bitrev32);
    store_block(out, s);
    secure_zero(s, sizeof s);
    secure_zero(&t, sizeof t);
}

/* ---- Çok bloklu (şeritli) şifreleme: CTR hızlandırması --------------------
 *
 * CTR'de bloklar birbirinden bağımsızdır; BB416_LANES blok aynı anda şifrelenir.
 * GCC/Clang'da bunun için derleyicinin taşınabilir vektör türleri kullanılır
 * (intrinsic veya platforma özel başlık yok; aynı kod x86, ARM vb. üzerinde
 * derlenir). Şerit sayısı derleme hedefinin vektör genişliğine göre seçilir:
 * AVX-512 → 16, AVX2 → 8, diğerleri → 4. Başka derleyicilerde aynı makrolar
 * düz C üzerinde, blok blok çalışır (BB416_PORTABLE tanımlanarak da seçilebilir).
 */
#if (defined(__GNUC__) || defined(__clang__)) && !defined(BB416_PORTABLE)
#  if defined(__AVX512F__)
#    define BB416_LANES 16
#  elif defined(__AVX2__)
#    define BB416_LANES 8
#  else
#    define BB416_LANES 4
#  endif

typedef uint32_t bb416_vec __attribute__((vector_size(4 * BB416_LANES)));

static inline bb416_vec vrotl(bb416_vec x, unsigned r)
{
    return (x << r) | (x >> (32u - r)); /* r her zaman 1..31 sabiti */
}

static inline bb416_vec vbitrev(bb416_vec x)
{
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0F0F0F0Fu) | ((x & 0x0F0F0F0Fu) << 4);
    x = ((x >> 8) & 0x00FF00FFu) | ((x & 0x00FF00FFu) << 8);
    return (x >> 16) | (x << 16);
}

static void encrypt_lanes(const bb416_ctx *ctx, uint32_t S[13][BB416_LANES])
{
    const int R = ctx->rounds;
    bb416_vec s[13], t;

    for (int i = 0; i < 13; i++)
        memcpy(&s[i], S[i], sizeof s[i]);
    for (int r = 0; r < R; r++)
        BB416_ROUND(s, t, ctx->rk[r], ctx->mk[r], vrotl, vbitrev);
    for (int i = 0; i < 13; i++) {
        s[i] ^= ctx->rk[R][i];
        memcpy(S[i], &s[i], sizeof s[i]);
    }
    secure_zero(s, sizeof s);
    secure_zero(&t, sizeof t);
}

#else /* taşınabilir C yedeği */
#  define BB416_LANES 4

static void encrypt_lanes(const bb416_ctx *ctx, uint32_t S[13][BB416_LANES])
{
    const int R = ctx->rounds;
    for (int l = 0; l < BB416_LANES; l++) {
        uint32_t s[13], t;
        for (int i = 0; i < 13; i++)
            s[i] = S[i][l];
        for (int r = 0; r < R; r++)
            BB416_ROUND(s, t, ctx->rk[r], ctx->mk[r], rotl32, bitrev32);
        for (int i = 0; i < 13; i++)
            S[i][l] = s[i] ^ ctx->rk[R][i];
        secure_zero(s, sizeof s);
        secure_zero(&t, sizeof t);
    }
}
#endif

/* ---- CTR modu (SPEC.md §7.3) ------------------------------------------- */

int bb416_ctr_xor(const bb416_ctx *ctx, const uint8_t nonce[BB416_NONCE_BYTES],
                 uint64_t counter, const uint8_t *in, uint8_t *out, size_t len)
{
    if (!ctx || !nonce)
        return BB416_ERR_PARAM;
    if (len == 0)
        return BB416_OK;
    if (!in || !out)
        return BB416_ERR_PARAM;
    assert(ctx->rounds >= 1 && ctx->rounds <= BB416_MAX_ROUNDS);

    /* Gereken blok sayısı n = ceil(len / 52); son bloğun sayacı counter + (n-1).
     * len gizli değildir: bu bölme yalnızca herkese açık uzunluk üzerindedir.
     * Taşacaksa hiçbir bayt yazılmadan dönülür; sayaç asla başa sarmaz. */
    const uint64_t extra = (uint64_t)((len - 1) / BB416_BLOCK_BYTES);
    if (counter > UINT64_MAX - extra)
        return BB416_ERR_COUNTER;

    /* Sayaç bloğu = nonce (kelime 0..10) || sayaç (kelime 11 = alt 32 bit,
     * kelime 12 = üst 32 bit; little-endian yükleme ile aynı düzen). */
    uint32_t nw[11];
    for (int i = 0; i < 11; i++)
        nw[i] = load32_le(nonce + 4 * i);

    uint32_t S[13][BB416_LANES];
    uint8_t ks[BB416_LANES * BB416_BLOCK_BYTES];

    for (;;) {
        /* Kısmi grupta fazladan şeritler de hesaplanır ama kullanılmaz;
         * onların sayacı başa sarabilir, bu zararsızdır. */
        for (int l = 0; l < BB416_LANES; l++) {
            uint64_t c = counter + (uint64_t)l;
            for (int i = 0; i < 11; i++)
                S[i][l] = nw[i];
            S[11][l] = (uint32_t)c;
            S[12][l] = (uint32_t)(c >> 32);
        }
        encrypt_lanes(ctx, S);
        for (int l = 0; l < BB416_LANES; l++)
            for (int i = 0; i < 13; i++)
                store32_le(ks + l * BB416_BLOCK_BYTES + 4 * i, S[i][l]);

        size_t take = len < sizeof ks ? len : sizeof ks;
        /* Bayt bayt oku-yaz: in == out güvenli. */
        for (size_t i = 0; i < take; i++)
            out[i] = in[i] ^ ks[i];

        len -= take;
        if (len == 0)
            break;
        in += take;
        out += take;
        counter += BB416_LANES; /* yukarıdaki kontrol sayesinde taşmaz */
    }

    secure_zero(S, sizeof S);
    secure_zero(ks, sizeof ks);
    return BB416_OK;
}
