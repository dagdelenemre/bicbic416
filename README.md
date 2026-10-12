# BicBic416

[![CI](https://github.com/dagdelenemre/bicbic416/actions/workflows/ci.yml/badge.svg)](https://github.com/dagdelenemre/bicbic416/actions/workflows/ci.yml)
[![Lisans: MIT](https://img.shields.io/badge/lisans-MIT-blue.svg)](LICENSE)
[![Web](https://img.shields.io/badge/web-bicbic416.vercel.app-black.svg)](https://bicbic416.vercel.app)

Bu proje, 416 bitlik (52 bayt) bir blok şifrenin C11 uygulamasıdır. Yanında bir CTR modu,
parolayla dosya şifreleyen bir araç, tarayıcıda çalışan bir web uygulaması ve kapsamlı
bir test/kriptanaliz paketi bulunur.

> **English:** BicBic416 is an experimental 416-bit block cipher (13 × 32-bit words,
> ARX-style rounds with key-dependent multiplication) written in portable C11, with
> CTR mode, a password-based file encryption tool (PBKDF2 + HMAC-SHA256), a browser
> version, an independent Python reference implementation and a reduced-round
> cryptanalysis report. It is an educational project and must not be used to protect
> real data. Documentation is in Turkish.

> ⚠️ **Eğitim ve araştırma amaçlıdır. Gerçek verileri korumak için kullanmayın.**
> BicBic416 uzman kriptanalizinden geçmemiştir. Testlerin hepsini geçmesi güvenli
> olduğu anlamına gelmez. Gerçek kullanım için AES-GCM veya ChaCha20-Poly1305 kullanın.

Tasarımın tamamı [SPEC.md](SPEC.md) dosyasında, güvenlik analizi
[ANALIZ.md](ANALIZ.md) dosyasında anlatılıyor.

## Tasarımın özeti

Şifre, 52 baytlık bloğu 13 adet 32-bit kelimeye bölüyor ve aşağıdaki 6 adımı
(varsayılan) 16 tur boyunca tekrarlıyor. Anahtar her turda yeniden karışıma giriyor.

| Adım | İşlem | Kaynağı (orijinal fikir) |
|---|---|---|
| 1 | Tur anahtarıyla XOR | — |
| 2 | Anahtardan türetilen tek sayıyla çarpma, `x ^= x >> 16` | "Anahtarla çarpmak" |
| 3 | Her kelimeyi farklı miktarda döndürme | 13 sütunlu matris, çapraz okuma |
| 4 | 1.↔13., 2.↔12. … kelime çiftlerini karıştırma | Sarmal XOR |
| 5 | Merkez kelime (7.) hepsini toplayıp herkese geri dağıtıyor | 7. parçanın özel rolü |
| 6 | Sarmal takas, merkez kelimenin bitlerini ters çevirme | Sarmal takas |

Uzun mesajlar CTR modunda şifreleniyor (44 bayt nonce + 8 bayt sayaç). Bu modda padding
gerekmiyor.

## Derleme

**Linux / macOS:** Sistemdeki GCC veya Clang ile GNU make yeterlidir.

**Windows:** Kurulum gerektirmeyen iki araç zinciri önerilir:

- [w64devkit](https://github.com/skeeto/w64devkit): GCC ve make
- [llvm-mingw](https://github.com/mstorsjo/llvm-mingw): Clang ile Windows'ta ASan ve UBSan

İkisini de örneğin `C:\Tools` altına açın ve `bin` dizinlerini PATH'e ekleyin.

| Komut | Ne yapar |
|---|---|
| `make test` | Tüm testleri GCC ile derler ve çalıştırır |
| `make check` | Testleri GCC, Clang ve Clang + ASan/UBSan ile çalıştırır |
| `make tool` | Dosya şifreleme aracını derler: `build/bicbic.exe` |
| `make bench` | Hız ölçümü (`-O2` ve `-O3`) |
| `make ... NATIVE=1` | Bu işlemciye özel derler (AVX2/AVX-512; CTR 3–4 kat hızlanır) |
| `make analysis` | Kriptanaliz araçlarını derler (bkz. ANALIZ.md) |

Windows'ta derlenen programların adı `.exe` ile biter (`build/bicbic.exe`).

## Dosya şifreleme aracı

```bash
build/bicbic sifrele rapor.pdf rapor.bb416
```

```bash
build/bicbic coz rapor.bb416 rapor.pdf
```

```bash
build/bicbic bilgi rapor.bb416
```

- **Parola:** Ekranda görünmeden sorulur. Betiklerde `BICBIC_PAROLA` ortam değişkeni de
  kullanılabilir.
- **Anahtar türetme:** Paroladan PBKDF2-HMAC-SHA256 ile (600 000 yineleme) bir şifreleme
  anahtarı ve bir doğrulama anahtarı türetilir.
- **Kurcalama koruması:** Dosyanın tamamı HMAC-SHA256 ile mühürlenir. Tek bir bayt bile
  değiştirilirse veya parola yanlışsa çözme reddedilir ve çıktı dosyası hiç oluşmaz.
- **Seçenekler:** `-r TUR` (1..32), `-i YINELEME`, `-z` (var olan dosyanın üzerine yaz)
- **Dosya biçimi:** [tool/bicbic_file.h](tool/bicbic_file.h) içinde tanımlı.

## Web sayfası

**https://bicbic416.vercel.app**

Sayfada metni bir anahtarla şifreleyip çözebilir ya da rastgele bir anahtar
üretebilirsiniz. Bütün işlemler tarayıcıda yapılır; metin ve anahtar sunucuya
gönderilmez. Bunu güvenlik başlığı da zorunlu kılar: CSP `connect-src 'none'`.

Sayfanın ürettiği şifreli metin, `.bb416` dosya biçiminin base64 hâlidir. Base64'ten
çözülüp kaydedildiğinde `bicbic coz` ile açılabilir; tersi de geçerlidir.

- **Kaynak:** [web/](web/). Şifre [web/bicbic416.js](web/bicbic416.js) içindeki
  JavaScript'e taşındı; PBKDF2, HMAC ve rastgele sayılar için tarayıcının WebCrypto
  arayüzü kullanılıyor.
- **Doğrulama:** `node web/test.mjs` komutu, C'deki 17 sabit vektörü ve komut satırı
  aracıyla iki yönlü uyumluluğu sınar.
- **Yeniden yayınlama:** `web/` dizininde `vercel deploy --prod` çalıştırın.

## Testler

| Test | İçerik |
|---|---|
| `test_helpers` | Döndürme, bit ters çevirme, çarpımsal ters (1 milyon sayı), `ROT` tablosu |
| `test_steps` | Her tur adımı için `ters(adım(S)) == S` (100 000 durum), yayılma özellikleri |
| `test_keysched` | Anahtar planı: bağımsız referansla karşılaştırma, hata kodları, çığ etkisi, bilinen zayıflığın gösterimi |
| `test_roundtrip` | 1..32 turun her biri için 100 000 gidiş-dönüş; hızlı yol = spesifikasyon adımları |
| `test_ctr` | CTR modu: tüm uzunluklar, yerinde çalışma, parça parça, sayaç taşması |
| `test_kat` | Sabit test vektörleri. Bağımsız Python uygulamasıyla (`ref/bicbic416_ref.py`) doğrulandı |
| `test_sha256` | SHA-256, HMAC ve PBKDF2. Python hashlib (OpenSSL) çıktısıyla karşılaştırılır |
| `test_file` | Dosya aracı: boyutlar, yanlış parola, kurcalama, kesme, TOCTOU saldırısı |
| `test_avalanche` | Çığ etkisi tablosu (aşağıda) |

## Çığ etkisi

Düz metinde tek bir bit değiştirildiğinde şifreli metinde kaç bitin değiştiği ölçüldü.
Her tur sayısı için 20 000 deneme yapıldı. İdeal sonuç ortalama 208 bit, standart sapma
10.2'dir.

| Tur | Ortalama | Std. sapma | İdeal mi? |
|---:|---:|---:|:---:|
| 1 | 192.92 | 47.05 | hayır |
| 2 | 208.09 | 10.17 | evet |
| 3 | 208.08 | 10.13 | evet |
| 4 | 208.03 | 10.26 | evet |
| 8 | 208.00 | 10.26 | evet |
| 16 | 208.03 | 10.12 | evet |

Çığ etkisi 2. turda ideale ulaşıyor (T = 2). Spesifikasyonun kuralı (R ≥ 3T–4T) 6–8 tur
öneriyor; varsayılan olan 16 tur iki kat güvenlik payı bırakıyor. Her girdi biti ayrı
ayrı ölçüldüğünde (SAC) de sonuç aynı: 2. turdan itibaren 416 girdi bitinin hepsi ideal.

## Hız

i5-11400H, tek çekirdek, R = 16:

| Derleme | Blok şifreleme | CTR (uzun veri) |
|---|---:|---:|
| GCC `-O2`, taşınabilir | 205 MB/s | 280–290 MB/s |
| Clang `-O2`, taşınabilir | 195 MB/s | 390–405 MB/s |
| GCC `-O3`, `NATIVE=1` | 208 MB/s | 870 MB/s |
| Clang `-O2`, `NATIVE=1` | 207 MB/s | **1 325 MB/s** |

R = 8 ile hız yaklaşık 1,5–2 kat artıyor.

CTR modunda bloklar birbirinden bağımsız olduğu için 4, 8 veya 16 blok aynı anda
işleniyor. Bunun için derleyicinin taşınabilir vektör türleri kullanılıyor; intrinsic
yok. Kaç bloğun birlikte işleneceği (şerit sayısı), derleme hedefinin vektör genişliğine
göre otomatik seçiliyor.

### Log / SOC senaryosu

Bu senaryoda her log kaydı ayrı ayrı şifrelenip HMAC ile mühürleniyor
([bench/bench_log.c](bench/bench_log.c)). Ortalama kayıt boyutu 374 bayt, test tek
çekirdekte, R = 16 ile yapıldı:

| | Kayıt/saniye | Gecikme (medyan / %99) |
|---|---:|---:|
| Şifrele + mühürle | 200 000 – 263 000 | 3–4 µs / 11–18 µs |
| Doğrula + çöz | 214 000 – 260 000 | 3–4 µs / 11–13 µs |

Tipik bir SOC/SIEM saniyede 1 000–100 000 olay işler. Burada zamanın yaklaşık %80'ini
HMAC-SHA256 alıyor, şifrenin kendisi değil.

## Dizin yapısı

```
include/bicbic416.h     genel API
src/bicbic416.c         şifre: tur adımları, anahtar planı, blok, CTR (vektörlü)
src/bb416_internal.h     yardımcılar ve tur adımı bildirimleri (testler için)
tool/                   SHA-256/HMAC/PBKDF2, OS rastgele üreteci, dosya biçimi, komut satırı aracı
tests/                  birim testleri ve SHA-256 test vektörü üreticisi
bench/                  hız ölçümleri (genel ve log senaryosu)
analysis/               kriptanaliz ve güvenlik testleri (ANALIZ.md)
ref/bicbic416_ref.py    bağımsız Python referans uygulaması
web/                    tarayıcı sayfası (JS uygulaması, Vercel)
```
