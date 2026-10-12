# BicBic416 — Tasarım ve Uygulama Spesifikasyonu

> **Durum:** Eğitim / araştırma amaçlı oyuncak blok şifre.
> Kriptanalizden geçmemiştir. Gerçek verileri korumak için **kullanılmamalıdır**
> (gerçek kullanım için AES-GCM veya ChaCha20-Poly1305).
> Algoritmanın adı **BicBic416**'dır.

Bu belge, herhangi bir geliştiricinin şifreyi C dilinde sıfırdan uygulayabilmesi
için yazılmıştır. Tasarım sabitleri burada tanımlıdır;
**uygulayıcı bunları sessizce değiştirmemeli**, bir sorun görürse raporlamalıdır.

---

## 1. Tasarımın arka planı

Tasarım, yazarın şu orijinal fikirlerinden yola çıkar:

| Orijinal fikir | Şifredeki karşılığı |
|---|---|
| Metni 13 parçaya bölmek | Durum = 13 adet 32 bitlik kelime (13 × 32 = 416 bit) |
| Anahtarla çarpmak | Her turda, her kelime anahtardan türetilen tek sayıyla çarpılır (Adım 2) |
| 13 sütunlu matris, çapraz okuma | 13×32 bit matrisin her satırı farklı miktarda döndürülür (Adım 3) |
| Sarmal XOR (1. parça ile 13. parça) | Tek yönlü, geri alınabilir sarmal çift karıştırma (Adım 4) |
| 7. parçanın özel rolü | Merkez kelime (S[6]) tüm durumu toplayıp geri dağıtır (Adım 5) |
| Sarmal takas, 7. parçayı ters çevirme | 1↔13, 2↔12… takas ve S[6]'nın bitlerinin ters çevrilmesi (Adım 6) |

Temel ilke: **anahtar tek bir kez değil, her turda karışıma girer.** Tüm adımlar
birçok tur boyunca tekrarlanır. Her adım tersine çevrilebilir olmalıdır, aksi hâlde
şifre çözme imkânsızdır.

---

## 2. Parametreler

| Parametre | Değer |
|---|---|
| Blok boyutu | 416 bit = 52 bayt |
| Anahtar boyutu | 416 bit = 52 bayt |
| Durum | `uint32_t S[13]` (indeks 0..12) |
| Tur sayısı (R) | Varsayılan **16**, çalışma zamanında 1..32 arası ayarlanabilir |
| Bayt sırası | Little-endian (bayt dizisi → kelime yükleme/saklama) |
| Dil | C11, harici bağımlılık yok |

Yükleme: `S[i] = in[4i] | in[4i+1]<<8 | in[4i+2]<<16 | in[4i+3]<<24`. Saklama tersidir.
Platformun endianness'ına güvenilmemeli, her zaman bu açık dönüşüm kullanılmalıdır.

---

## 3. Yardımcı fonksiyonlar

```c
static inline uint32_t rotl32(uint32_t x, unsigned r); // r 1..31, r==0 güvenli olmalı
static inline uint32_t rotr32(uint32_t x, unsigned r);
static inline uint32_t bitrev32(uint32_t x);           // bit sırasını ters çevirir, kendi tersidir
static uint32_t mulinv32(uint32_t a);                  // a tek sayı; a * inv ≡ 1 (mod 2^32)
```

`mulinv32`: Newton yöntemi. `inv = a;` sonra 5 kez `inv *= 2 - a * inv;`
(tüm aritmetik `uint32_t`, taşma mod 2^32 olarak doğaldır).

Satır döndürme sabitleri:

```
ROT[i] = (13*i + 3) mod 32   →   3,16,29,10,23,4,17,30,11,24,5,18,31
```

(13 ile 32 aralarında asal olduğu için 13 değerin hepsi farklı ve sıfırdan farklıdır.)

---

## 4. Tur fonksiyonu (tur r, 0 ≤ r < R)

Girdi: durum `S[13]`, tur anahtarları `RK[r][13]`, çarpanlar `MK[r][13]` (hepsi tek sayı).

**Adım 1 — Anahtar ekleme**
```
for i in 0..12:  S[i] ^= RK[r][i]
```

**Adım 2 — Anahtarla çarpma + karıştırma** (doğrusal olmayan adım)
```
for i in 0..12:
    S[i] = S[i] * MK[r][i]        // mod 2^32
    S[i] ^= S[i] >> 16            // çarpmanın güçlü üst bitlerini alt bitlere taşır
```

**Adım 3 — Çapraz/satır döndürme** (matris fikri)
```
for i in 0..12:  S[i] = rotl32(S[i], ROT[i])
```

**Adım 4 — Sarmal çift karıştırma** (tek yönlü, geri alınabilir)
```
for i in 0..5:
    j = 12 - i
    S[j] += S[i]                  // mod 2^32
    S[i] ^= rotl32(S[j], 7)
```

**Adım 5 — Merkez kelime: topla ve dağıt** (7. parça)
```
t = toplam(S[i] for i != 6)       // mod 2^32
S[6] += t
for i in 0..12, i != 6:
    S[i] ^= rotl32(S[6], i + 1)   // döndürme miktarları 1..6 ve 8..13
```
Bu adım sayesinde tek bir turda her kelime diğer tüm kelimelere bağımlı hâle gelir.
(Adım 4 tek başına yalnızca çiftleri karıştırır; Adım 5 olmadan durum birbirinden
bağımsız 6 çift + 1 merkeze ayrışırdı.)

**Adım 6 — Sarmal takas**
```
for i in 0..5:  swap(S[i], S[12 - i])
S[6] = bitrev32(S[6])
```

R turdan sonra **son beyazlatma (whitening):**
```
for i in 0..12:  S[i] ^= RK[R][i]
```

---

## 5. Şifre çözme (ters tur)

Önce `S[i] ^= RK[R][i]`, sonra r = R-1'den 0'a kadar her tur için adımlar **ters sırada**:

- **Ters Adım 6:** aynı takas + `bitrev32` (kendi tersidir)
- **Ters Adım 5:**
  ```
  for i != 6:  S[i] ^= rotl32(S[6], i + 1)
  t = toplam(S[i] for i != 6)
  S[6] -= t
  ```
- **Ters Adım 4:**
  ```
  for i in 0..5:
      j = 12 - i
      S[i] ^= rotl32(S[j], 7)
      S[j] -= S[i]
  ```
- **Ters Adım 3:** `S[i] = rotr32(S[i], ROT[i])`
- **Ters Adım 2:**
  ```
  S[i] ^= S[i] >> 16              // kendi tersidir (kaydırma ≥ 16 olduğu için)
  S[i] = S[i] * MKINV[r][i]
  ```
- **Ters Adım 1:** `S[i] ^= RK[r][i]`

`MKINV[r][i] = mulinv32(MK[r][i])` anahtar hazırlığında önceden hesaplanır.

---

## 6. Anahtar planı (key schedule)

Amaç: 52 baytlık ana anahtardan her tur için **farklı** `RK` ve `MK` değerleri üretmek.
(Her turda aynı anahtarı kullanmak "slide" saldırılarına kapı açar.)

```
K[13] = ana anahtar (little-endian yüklenmiş)
KS_MUL = 0x2545F491              // sabit tek sayı

KS_MIX(K):                       // anahtarsız karıştırma
    for i in 0..12:
        K[i] = K[i] * KS_MUL
        K[i] ^= K[i] >> 16
        K[i] = rotl32(K[i], ROT[i])
    Adım 4, Adım 5, Adım 6'yı K üzerinde uygula

n = 0
üret():
    K[0] ^= (n + 1) * 0x9E3779B9 // tur sabiti, simetriyi kırar
    KS_MIX(K); KS_MIX(K)
    n += 1
    return kopya(K)

for r in 0..R-1:
    RK[r] = üret()
    MK[r] = üret(), her kelime için | 1 (tek sayı yap)
    MKINV[r][i] = mulinv32(MK[r][i])
RK[R] = üret()
```

Bilinen zayıflık (kabul edildi): anahtar planı tersine çevrilebilir; bir tur anahtarı
sızarsa ana anahtar bulunabilir (AES'te de durum benzerdir).

---

## 7. API

```c
#define BB416_BLOCK_BYTES 52
#define BB416_KEY_BYTES   52
#define BB416_NONCE_BYTES 44
#define BB416_MAX_ROUNDS  32

typedef struct {
    int rounds;
    uint32_t rk[BB416_MAX_ROUNDS + 1][13];
    uint32_t mk[BB416_MAX_ROUNDS][13];
    uint32_t mkinv[BB416_MAX_ROUNDS][13];
} bb416_ctx;

#define BB416_OK             0
#define BB416_ERR_PARAM     -1   // NULL işaretçi veya geçersiz tur sayısı
#define BB416_ERR_COUNTER   -2   // CTR sayacı taşacaktı

int  bb416_init(bb416_ctx *ctx, const uint8_t key[BB416_KEY_BYTES], int rounds);
void bb416_encrypt_block(const bb416_ctx *ctx, const uint8_t in[52], uint8_t out[52]);
void bb416_decrypt_block(const bb416_ctx *ctx, const uint8_t in[52], uint8_t out[52]);
int  bb416_ctr_xor(const bb416_ctx *ctx, const uint8_t nonce[BB416_NONCE_BYTES],
                  uint64_t counter, const uint8_t *in, uint8_t *out, size_t len);
void bb416_wipe(bb416_ctx *ctx); // derleyicinin silemeyeceği şekilde sıfırlar
```

### 7.1 `bb416_init` hata davranışı
- `ctx == NULL` → `BB416_ERR_PARAM` döner.
- `key == NULL` veya `rounds` 1..32 dışında → `ctx` sıfırlanır (`bb416_wipe`),
  `BB416_ERR_PARAM` döner. Yarım hazırlanmış bir `ctx` asla kullanılabilir kalmaz.
- Başarıda `BB416_OK` döner.

### 7.2 Blok fonksiyonları
- Dönüş değeri yoktur. `NULL` argüman çağıranın hatasıdır; debug derlemede `assert`
  ile yakalanır, release derlemede kontrol edilmez.
- **Yerinde çalışma desteklenir:** `in == out` geçerlidir. Uygulama önce tüm bloğu
  duruma yükler, sonra yazar. Kısmi örtüşme (`in != out` ama bellek bölgeleri kesişiyor)
  desteklenmez, belgelenir.

### 7.3 CTR modu
- Sayaç bloğu = `nonce (44 bayt) || sayaç (8 bayt, little-endian)`.
- `counter` **ilk bloğun** sayaç değeridir; her 52 baytlık blokta **1 artar**.
  Anahtar akışı = sayaç bloğunun şifrelenmiş hâli; girdi ile XOR'lanır.
- **Taşma:** İşlem başlamadan önce gereken blok sayısı `n = ceil(len / 52)` hesaplanır.
  `n > 0` ve `counter > UINT64_MAX - (n - 1)` ise **hiçbir bayt yazılmadan**
  `BB416_ERR_COUNTER` döner. Sayaç asla başa sarmaz, çünkü başa sarmak aynı anahtar
  akışını tekrar kullanmak demektir ve şifreyi tamamen kırar.
- `len == 0` geçerlidir; hiçbir şey yapmadan `BB416_OK` döner (`in`/`out` NULL olabilir).
- `ctx`, `nonce` NULL ise veya `len > 0` iken `in`/`out` NULL ise `BB416_ERR_PARAM` döner.
- **Yerinde çalışma desteklenir** (`in == out`); kısmi örtüşme desteklenmez.
- Parça parça şifreleme: Uzun bir veri birden fazla çağrıyla işlenecekse, son çağrı
  dışındaki her çağrının `len` değeri 52'nin katı olmalı ve sonraki çağrının
  `counter` değeri önceki çağrının işlediği blok sayısı kadar artırılmalıdır.
- Padding gerekmez; **her uzunlukta** girdi (0 bayttan itibaren) çalışır ve çıktı
  girdiyle aynı uzunluktadır. Şifreleme ve çözme aynı fonksiyondur.
- **Aynı anahtarla aynı nonce asla tekrar kullanılmamalıdır.** Nonce gizli değildir,
  şifreli metinle birlikte saklanır/gönderilir. Önerilen: her mesaj için işletim
  sisteminin güvenli rastgele üretecinden 44 bayt nonce.
- CTR modu kimlik doğrulama sağlamaz (şifreli veri fark edilmeden değiştirilebilir).

---

## 8. Uygulama kuralları

- Gizli veriye bağlı `if` dalı veya dizi indeksi yok (sabit zamanlı kod).
- `%` ve `/` kullanılmaz; tüm döndürme miktarları sabittir.
- Tüm kelime aritmetiği `uint32_t`; işaretli tiplere dönüşüm yok.
- Derleme: `-std=c11 -O2 -Wall -Wextra -Wpedantic` uyarısız geçmeli.
- Kod taşınabilir C11 olmalı; platforma özel başlık veya intrinsic kullanılmaz.

### 8.1 Derleme ortamı
- **Windows:** w64devkit (GCC + make) ve llvm-mingw (Clang). Clang, Windows'ta da
  `-fsanitize=address,undefined` destekler. `make check` testleri GCC, Clang ve
  Clang + sanitizer ile çalıştırır.
- **Linux:** Sistem GCC/Clang. GitHub Actions her değişiklikte aynı test setini
  Ubuntu üzerinde çalıştırır.
- Makefile `SANITIZE=1` seçeneğiyle sanitizer bayraklarını açar; varsayılan kapalıdır.

Önerilen klasör yapısı:
```
include/bicbic416.h
src/bicbic416.c
tests/test_helpers.c     // rotl, bitrev, mulinv
tests/test_steps.c       // her adımın tersinin doğruluğu
tests/test_roundtrip.c   // şifrele → çöz → aynı mı
tests/test_avalanche.c   // çığ etkisi
tests/test_kat.c         // sabitlenmiş test vektörleri
bench/bench.c
Makefile
README.md
```

---

## 9. Uygulama aşamaları

Her aşamadan sonra testler çalıştırılır; geçmeden bir sonraki aşamaya geçilmez.

1. **İskelet:** Makefile, başlık dosyası, yardımcı fonksiyonlar ve testleri.
   `mulinv32` en az 1.000.000 rastgele tek sayıyla, `bitrev32` kendi tersi olarak test edilir.
2. **Tur adımları:** Adım 1–6 ve tersleri ayrı fonksiyonlar olarak. Her adım için
   rastgele durumlarla `ters(adım(S)) == S` testi.
3. **Anahtar planı.**
4. **Blok şifreleme/çözme:** 100.000 rastgele anahtar+blok ile gidiş-dönüş testi;
   1..32 arası tüm tur sayıları için.
5. **Çığ etkisi testi** (en önemli çıktı):
   - Düz metinde rastgele 1 bit çevir, şifreli metinde kaç bitin değiştiğini say.
   - Aynısını anahtar için yap.
   - **Her tur sayısı için (1..16)** ortalama, standart sapma ve min/max'ı tablo olarak yazdır.
   - İdeal: 416 bitin yarısı ≈ **208** bit değişmeli, standart sapma ≈ 10.2.
   - Ayrıca bit başına değişme olasılığının 0.5'ten en büyük sapmasını raporla.
6. **CTR modu** ve testi: gidiş-dönüş, farklı uzunluklar (0, 1, 51, 52, 53, 1000 bayt),
   yerinde çalışma (`in == out`), parça parça şifrelemenin tek seferlikle aynı sonucu
   vermesi, sayaç taşma sınırı (`counter = UINT64_MAX` ile 52 bayt geçer, 53 bayt
   `BB416_ERR_COUNTER` döner ve çıktıya dokunmaz), `bb416_init` hata kodları.
7. **Benchmark:** blok şifreleme ve CTR için MB/s, `-O2` ve `-O3` ile.
8. **Bilinen cevap testleri (KAT):** Tasarım kesinleşince sıfır anahtar/sıfır blok gibi
   birkaç girdinin çıktısını üretip `test_kat.c` içine sabitle. Bundan sonra yapılan
   değişiklikler çıktıyı bozarsa test yakalasın.
9. **README:** Tasarımın özeti, "eğitim amaçlıdır, üretimde kullanmayın" uyarısı,
   çığ etkisi tablosu ve benchmark sonuçları.

---

## 10. Tur sayısının belirlenmesi

Varsayılan 16 geçicidir. Aşama 5'teki tabloya göre karar verilecek:
çığ etkisinin ~208 bite ulaştığı tur sayısı **T** ise, yaygın kural **R ≥ 3T–4T**'dir
(güvenlik payı). Örneğin T = 3 ise R = 12–16 makul olur.

---

## 11. Bu şifre için iddia edilmeyenler

- Diferansiyel, lineer veya cebirsel kriptanalize dayanıklı olduğu **kanıtlanmamıştır**.
- İstatistiksel testleri geçmesi güvenli olduğu anlamına **gelmez**.
- Kimlik doğrulama (MAC) içermez.

Sonraki çalışma önerileri: azaltılmış turlarda (2–4) diferansiyel karakteristik arama,
NIST STS / dieharder ile CTR çıktısının istatistiksel analizi.

---

## 12. BicBic-Hash (416-bit özet fonksiyonu)

BicBic416 blok şifresinden **Miyaguchi–Preneel** yapısıyla türetilen, 416 bit (52 bayt)
çıktılı bir özet fonksiyonu. Whirlpool da aynı yöntemle bir blok şifreden türetilmiştir.
Anahtar ve blok boyutu eşit (52 bayt) olduğundan zincirleme değeri doğrudan bir sonraki
bloğun anahtarı olur.

```
R_H   = 16                                 // hash için tur sayısı (sabit)
IV    = E_{0^52}(0^52)                     // sıfır anahtarla sıfır bloğun şifresi
FINAL = "BicBic-Hash/son" || 0x00 × 37     // 52 baytlık son blok sabiti

Dolgu (Merkle–Damgård güçlendirmesi):
    M' = M || 0x80 || 0x00 × k || uzunluk_bit (8 bayt, little-endian)
    k, |M'| 52'nin katı olacak şekilde en küçük değer

Sıkıştırma:
    C(h, m) = E_h(m) ⊕ m ⊕ h               // E_h: h anahtarıyla R_H turluk BicBic416

h = IV
her 52 baytlık M' bloğu m için:  h = C(h, m)
H(M) = C(h, FINAL)
```

- **Son blok:** Çıktı son zincirleme değerini doğrudan açığa çıkarmaz. Böylece uzunluk
  uzatma (length extension) saldırısı engellenir.
- **Genel (yapıdan gelen) güvenlik sınırı:** Çakışmaya karşı 2^208, ön-görüntüye karşı
  2^416. Bu sınırlar yalnızca BicBic416 ideal bir blok şifre gibi davranırsa geçerlidir;
  bu varsayım kanıtlanmamıştır.
- **Hız:** Her blokta anahtar planı yeniden çalıştığı için yavaştır (yaklaşık 16 MB/s).
- **Deneyseldir.** Parola türetme, mühür (MAC) ve dijital imza gibi güvenlik işlerinde
  SHA-256 / SHA-3 kullanılır; dosya aracı da bu işler için SHA-256 kullanır.

---

## 13. İki katmanlı mod ve dosya biçimi

Dosya aracı ve web uygulaması, isteğe bağlı olarak BicBic416-CTR'nin üstüne ikinci,
bağımsız bir **ChaCha20** (RFC 8439) katmanı ekler:

```
şifreli = düz ⊕ BicBic416-CTR(K1) ⊕ ChaCha20(K2)        K1, K2 bağımsız anahtarlar
```

İki anahtar akışının XOR'u, ikisinden **en az biri** öngörülemez kaldıkça öngörülemezdir.
Yani saldırganın iki şifreyi birden kırması gerekir.

Anahtarlar paroladan şöyle türetilir:

```
ana_sır    = PBKDF2-HMAC-SHA256(parola, tuz, yineleme, 32)
anahtarlar = HKDF-SHA256(ana_sır, "BicBic416 v2 anahtarlar", 116)
           → K1 (52) | HMAC anahtarı (32) | K2 (32)
```

Her dosyanın tuzu rastgeledir, bu yüzden anahtarlar her dosyada farklıdır. Nonce'lar bu
nedenle sabit tutulabilir (sıfır) ve dosyaya yazılmaz. Dosya biçimi sürüm 2'nin ek yükü
36 bayttır (20 bayt başlık + 16 bayt etiket); ayrıntılar `tool/bicbic_file.h` içindedir.
Sürüm 1 dosyaları (102 bayt ek yük) okunmaya devam eder.
