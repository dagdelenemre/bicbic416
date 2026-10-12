# BicBic416 — Kriptanaliz ve Güvenlik Testleri Raporu

Tarih: 2026-10-12 · Ortam: Intel Core i5-11400H (AVX-512), Windows 11, GCC 16.2 / Clang 23.1

> **Önce sonucu söyleyelim:** Burada yapılan testlerin hiçbiri 16 turluk BicBic416'da bir
> zayıflık bulamadı. **Ama bu, şifrenin güvenli olduğunu göstermez.** Bu testler,
> uzman kriptanalistlerin aylarca süren elle analizinin yerini tutmaz. Gerçek gizli veriler
> için AES-GCM veya ChaCha20-Poly1305 kullanın.

Bütün sonuçlar yeniden üretilebilir. Komutlar her bölümde verilmiştir. Ham çıktılar
`build/analysis/` altına yazılır.

---

## 1. Özet

| Test | Ne arar? | Kırılan tur | 16 tur |
|---|---|---|---|
| Çığ etkisi (SAC, bit bit) | Karıştırma eksikliği | 1 | ✅ ideal |
| Diferansiyel (tek bit + tasarıma özel MSB çiftleri) | Girdi farkının çıktıda iz bırakması | 1 | ✅ iz yok |
| Lineer (tek bit korelasyonları) | Girdi/çıktı bitleri arasında doğrusal ilişki | — (bkz. not) | ✅ ilişki yok |
| Integral (XOR toplamı) | Dengeli bit | — (bkz. not) | ✅ yok |
| PractRand (istatistik paketi) | CTR çıktısında rastgelelikten sapma | 1 | ✅ 64 GB temiz |
| Yapısal simetri | Tümleme, döndürme, ayna simetrisi | — | ✅ yok |
| Zamanlama yan kanalı | Süreye bakarak sır sızdırma | — | ✅ sızıntı yok |
| Bulanık test (dosya aracı) | Çökme, bellek hatası, sahte dosya kabulü | — | ✅ 20 000 mutant, 0 sorun |
| Kod incelemesi ve uyumluluk testi | Uygulama hataları | — | ⚠️ 1 güvenlik açığı + 1 hata bulundu, ikisi de düzeltildi |

**Tur sayısı için yorum:** Azaltılmış tur testlerinin hepsinde şifre **yalnızca 1 turda**
kırılıyor. 2. turdan itibaren hiçbir test ayırt edemiyor. Spesifikasyondaki kural
(R ≥ 3T–4T, T = 2) 6–8 tur öneriyor. 16 tur bunun iki katı güvenlik payı bırakıyor.
Ancak 2 turun bile bu testleri geçmesi, testlerin sınırına işaret ediyor: gerçek bir
saldırı birden çok tekniği birleştirir ve genellikle bu basit ayırt edicilerden birkaç tur
daha ileri gider.

---

## 2. Doğruluk: bağımsız referans uygulama

`ref/bicbic416_ref.py`, yalnızca SPEC.md okunarak Python ile ayrıca yazıldı. Bu
uygulamada ters çarpım `pow(a, -1, 2^32)` ile, bit ters çevirme metin işlemiyle, `ROT`
ise `%` ile hesaplanıyor; yani C kodundan farklı yöntemler kullanılıyor. `tests/test_kat.c`
içindeki 17 vektörün **17'si de** aynı çıktıyı veriyor.

```
python ref/bicbic416_ref.py
```

Ek olarak `test_roundtrip`, hızlı (açılmış/vektörlü) yolun, spesifikasyonun adım adım
okunur hâliyle (`bb416_stepN`) 1..32 turun hepsinde birebir aynı olduğunu doğruluyor.

---

## 3. Diferansiyel kriptanaliz (azaltılmış turlar)

`build/analysis/differential 6 21`

Analiz iki aşamada yapıldı:

1. **Tarama:** 494 aday girdi farkı denendi. Bunlar 416 tek-bit fark ile 78 "iki kelimenin
   31. biti" farkıdır. İkinci grup bu tasarıma özel bir adaydır: en üst bit, modüler
   toplamada XOR gibi davranır. İki kelimedeki bu farklar Adım 5'in toplamında birbirini
   götürebilir ve böylece merkez kelimeyi atlatabilir. Her aday için 4 096 çift ölçüldü.
2. **Doğrulama:** En şüpheli 8 aday, **bağımsız** 2^21 çiftle yeniden ölçüldü.

| Tur | En güçlü girdi farkı | Değişme olasılığı | z | Sonuç |
|---:|---|---:|---:|---|
| 1 | kelime 3 bit 31 | 1.0000 | 1448 | **Kırık:** bazı çıktı bitleri her zaman değişiyor; tam çıktı farkı ~2^-4 olasılıkla tekrarlanıyor |
| 2 | kelime 0 ve 11, bit 31 | 0.4985 | 4.5 | Eşiğin (5.5) altında |
| 3 | kelime 12 bit 28 | 0.5012 | 3.5 | Ayırt edilemedi |
| 4 | kelime 11 bit 16 | 0.5014 | 3.9 | Ayırt edilemedi |
| 5 | kelime 6 bit 9 | 0.5012 | 3.6 | Ayırt edilemedi |
| 6 | kelime 5 ve 10, bit 31 | 0.5013 | 3.8 | Ayırt edilemedi |

**2. tur için ek doğrulama:** Gürültü beklentisinin biraz üstünde kalan aday (kelime 0+11,
bit 31) önceden belirlenmiş bir hipotez olarak, farklı bir tohumla 2^26 (67 milyon) çiftle
yeniden test edildi. Sonuç: z = −0.92. Yani bu bir **yanlış alarmdı** ve aday seçiminden
kaynaklanıyordu.

**Sınır:** Bu test her çıktı bitine tek tek bakar. Çok bitli (kesilmiş) diferansiyeller ve
uzman tarafından elle kurulan karakteristikler denenmedi.

---

## 4. Lineer kriptanaliz (azaltılmış turlar)

`build/analysis/linear 4 18`

Sabit bir anahtar için 416 × 416 (girdi biti, çıktı biti) çiftinin hepsinde korelasyon
ölçüldü. Her anahtar için 2^18 düz metin kullanıldı ve her tur sayısında 2 anahtar denendi.

| Tur | En büyük \|korelasyon\| | z | Sonuç |
|---:|---:|---:|---|
| 1 | 0.0091 | 4.7 | Ayırt edilemedi |
| 2 | 0.0093 | 4.7 | Ayırt edilemedi |
| 3 | 0.0092 | 4.7 | Ayırt edilemedi |

(Saf gürültüde beklenen en büyük z ≈ 4.9.)

**Önemli not:** Bu test, diferansiyel testte tamamen kırık çıkan **1 turu bile ayırt
edemedi.** Bu yüzden tek-bit lineer test bu tasarım için zayıf bir araçtır. Adım 2'deki
`x ^= x >> 16` ve Adım 5'in tüm kelimeleri birbirine bağlaması, tek bitlik doğrusal
ilişkileri ilk turda dağıtıyor. Anlamlı bir lineer kriptanaliz, çok bitli maskelerin ve
toplama/çarpma için bilinen doğrusal yaklaşımların elle aranmasını gerektirir.

---

## 5. Integral analizi (azaltılmış turlar)

`build/analysis/integral 5`

Bir kelimenin alt k biti (k = 8, 16, 20) tüm değerlerinden geçirildi. Ardından şifreli
metinlerin XOR toplamında 32 bağımsız denemenin hepsinde sıfır kalan ("dengeli") bit
arandı.

**Sonuç:** 1–5 turda, 35 yapılandırmanın hiçbirinde dengeli bit bulunmadı.

İlk çalıştırmada 16 denemeyle bir dengeli bit görülmüştü (2 tur, kelime 6, k = 16). Ancak
o koşullarda tüm tablo boyunca ≈ 0.2 yanlış alarm bekleniyordu. Deneme sayısı 32'ye
çıkarılınca bu bit de kayboldu.

**Not:** Lineer testte olduğu gibi, bu test de 1 turu ayırt edemedi. Bunun sebebi,
modüler çarpma ve `x ^= x >> 16` işlemlerinin XOR toplamı özelliğini ilk turda bozması.
ARX benzeri tasarımlarda gerçek integral saldırıları için "bölünme özelliği" (division
property) gibi daha ileri araçlar gerekir.

---

## 6. İstatistiksel testler: PractRand

`sh analysis/run_practrand.sh` · PractRand 0.95, `-tf 2` (genişletilmiş test seti)

Test edilen girdi CTR anahtar akışıdır: nonce sıfır, sayaç 0'dan başlayıp birer artıyor.
Bu, şifre için en "düzenli" girdidir; istatistiksel bir zayıflık varsa en kolay burada
görünür. Testin çalıştığından emin olmak için önce kasıtlı olarak bozuk bir veri verildi
ve PractRand bunu 16 MB'ta yakaladı.

| Tur | Anahtar | Test edilen veri | Sonuç |
|---:|---|---:|---|
| 1 | rastgele | 1 GB | **Anında kaldı** (p = 0) |
| 2 | rastgele | **256 GB** | Temiz (915 test sonucu, anormallik yok) |
| 3 | rastgele | 64 GB | Temiz (843 test sonucu, anormallik yok) |
| 4, 5, 6 | rastgele | 1 GB her biri | Temiz |
| 8 | rastgele | 16 GB | Temiz |
| 16 | sıfır anahtar | 16 GB | Temiz |
| **16** | rastgele | **64 GB** | **Temiz** (843 test sonucu, anormallik yok) |

Arada görülen tek tük "unusual" veya "mildly suspicious" uyarıları normaldir; gerçek
rastgele veride de olur. Bunların hepsi veri arttıkça kayboldu.

**Yorum:** 2 tur, 256 GB'ta bile PractRand'a takılmıyor. Oysa diferansiyel test 1 turu
birkaç düzine çiftle kırıyor. Bu fark, genel amaçlı istatistik paketlerinin bir şifrenin
güvenliğini ölçmek için ne kadar kaba bir araç olduğunu gösteriyor. PractRand'ı geçmek
gerekli bir koşul, ama yeterli değil. Spesifikasyonun §11'deki uyarısı bu yüzden önemli.

---

## 7. Yapısal simetriler ve özel durumlar (16 tur)

`build/analysis/structure`

Burada bakılan şey, bir σ dönüşümü için E(σK, σP) ile σE(K, P) arasındaki Hamming
uzaklığı. Bu uzaklık 208 civarındaysa simetri yok demektir. Uzaklık küçükse, anahtar
uzayı fiilen küçülür; DES'in tümleme özelliği buna bir örnektir.

| Dönüşüm | Ort. uzaklık | Std. sapma | Sonuç |
|---|---:|---:|---|
| Tümleme | 208.18 | 10.15 | Simetri yok |
| Her kelimeyi 1 bit döndür | 208.01 | 10.23 | Simetri yok |
| Her kelimeyi 16 bit döndür | 208.23 | 10.22 | Simetri yok |
| Kelime sırasını ters çevir (sarmal ayna) | 207.92 | 10.16 | Simetri yok |
| Kelime bitlerini ters çevir | 207.91 | 10.23 | Simetri yok |
| Üst bitleri çevir | 208.07 | 10.20 | Simetri yok |

Diğer kontroller:

- **Sabit nokta / 2-döngü:** 200 000 denemede hiç görülmedi.
- **Zayıf çarpanlar:** MK ≡ 1 (mod 2^16) olduğunda çarpma, o kelimenin alt yarısını hiç
  değiştirmez. Bu durum anahtarların %0.66'sında en az bir tur kelimesinde görülüyor.
  Beklenen oran %0.63, yani rastlantı düzeyinde. Tek bir kelimede, tek bir turda, yalnızca
  çarpmayı zayıflatıyor; diğer adımlar etkilenmiyor. Pratik bir zayıflık değil, ama
  tasarımda not edilmeli.

---

## 8. Zamanlama yan kanalı

`build/analysis/timing` · dudect yöntemi (Welch t-testi, 1 milyon ölçüm)

Bir saldırgan, şifrelemenin ne kadar sürdüğünü ölçerek gizli veriyi tahmin edebilir mi?
Bunu anlamak için iki girdi sınıfı karşılaştırıldı: sabit girdi ve rastgele girdi.

| İşlem | En büyük \|t\| | Sonuç |
|---|---:|---|
| Blok şifreleme | 1.76 | Sızıntı yok |
| Blok çözme | 1.97 | Sızıntı yok |
| Anahtar hazırlığı | 1.00 | Sızıntı yok |
| CTR 520 bayt | 2.34 | Sızıntı yok |
| Etiket karşılaştırma (`ct_memcmp`) | 1.37 | Sızıntı yok |
| **Pozitif kontrol:** standart `memcmp` | **1594** | Sızıntı var (beklenen) |

Eşik \|t\| < 4.5. Pozitif kontrol, testin bu ortamda gerçek bir sızıntıyı
yakalayabildiğini gösteriyor.

**Sınır:** Sonuç bu işlemci için geçerlidir. Bazı eski veya gömülü işlemcilerde (örneğin
ARM Cortex-M3) 32-bit çarpma, değere bağlı sürede çalışabilir. Bu tasarım her turda
anahtara bağlı çarpma yaptığı için, öyle bir işlemcide zamanlama sızıntısı oluşabilir.

---

## 9. Dosya aracının güvenliği

### 9.1 Bulanık test (fuzz)

`build/analysis/fuzz_file 20000` · AddressSanitizer + UBSan ile

20 000 bozuk veya kötü niyetli dosya denendi. Kullanılan mutasyonlar: bit çevirme,
rastgele bayt, kesme, uzatma, parça silme, başlık alanlarına uç değerler ve tamamen
rastgele dosyalar.

- Çökme, bellek hatası veya tanımsız davranış görülmedi.
- **Değiştirilmiş dosyaların hiçbiri doğru parolayla bile kabul edilmedi.**
  Dağılım: 13 828 doğrulama hatası, 5 642 biçim hatası. 530 mutasyon dosyayı fiilen
  değiştirmemişti.

### 9.2 Kod incelemesinde bulunan ve düzeltilen açık

**TOCTOU (kontrol ile kullanım arasındaki zaman):** Çözme işlemi dosyayı iki kez okuyor:
önce etiketi doğruluyor, sonra şifreyi çözüyor. Dosyayı bu iki okuma arasında
değiştirebilen biri (örneğin aynı makinedeki başka bir süreç), doğrulanmamış veriyi
çıktıya sokabiliyordu.

**Düzeltme:** İkinci geçişte etiket yeniden hesaplanıyor. Eşleşmezse geçici çıktı
siliniyor ve hedef dosya hiç oluşmuyor. `test_file` bu saldırıyı taklit ediyor:
düzeltilmemiş kod testi geçemiyor, düzeltilmiş kod geçiyor.

**Parola kodlaması (Windows):** `BICBIC_PAROLA` ortam değişkeni, Windows'ta UTF-8
olarak değil, ANSI kod sayfasıyla (cp1254) okunuyordu. Klavyeden girilen parola ise
UTF-8'e çevriliyordu. Bu yüzden "ğüşıöç" içeren aynı parola, girildiği yola göre farklı
anahtar üretiyordu. Hata, web sayfası ile komut satırı aracı arasındaki uyumluluk
testinde (`node web/test.mjs`) ortaya çıktı.

**Düzeltme:** Ortam değişkeni geniş karakterle okunup UTF-8'e çevriliyor. Artık her yol
(klavye, ortam değişkeni, web sayfası) aynı anahtarı üretiyor.

### 9.3 Bilinen sınırlar (kabul edilmiş)

- **PBKDF2-HMAC-SHA256 (600 000 yineleme):** GPU ile parola tahminine karşı Argon2 kadar
  dirençli değil. Kısa ve tahmin edilebilir parolalar yine de kırılabilir.
- **Anahtar planı tersine çevrilebilir** (SPEC.md §6): Bir tur anahtarı sızarsa ana anahtar
  bulunur. `test_keysched` bunu 1000 denemenin 1000'inde gösteriyor. Bellekteki tur
  anahtarları `bb416_wipe` ile siliniyor. Ancak derleyicinin yazmaç veya yığında
  bıraktığı kopyalar garanti altında değil.
- **`BICBIC_PAROLA` ortam değişkeni:** Aynı kullanıcının diğer süreçleri bunu görebilir.
  Yalnızca otomasyon için kullanılmalı.
- **Geçici dosya adı tahmin edilebilir** (`<çıktı>.bb416tmp`). Çok kullanıcılı Unix
  sistemlerinde paylaşılan dizinlerde sembolik bağlantı saldırısına açık olabilir.
- **Kütüphane CTR modu kimlik doğrulama sağlamaz.** Dosya aracı ve log örneği bunu
  HMAC ile ekliyor; kütüphaneyi doğrudan kullananlar eklemek zorunda.

---

## 10. Bu raporun yapmadıkları

- Elle diferansiyel/lineer karakteristik arama, otomatik iz arama (MILP/SAT tabanlı)
- Toplama/çarpma için bilinen ARX diferansiyel ve lineer yaklaşımların sistematik kullanımı
- Bölünme özelliği (division property) ile integral analizi
- İlişkili anahtar (related-key) ve kayma (slide) saldırılarının ayrıntılı analizi.
  Yapılanlar şunlarla sınırlı: anahtar planının çığ etkisi ölçüldü ve tur anahtarlarının
  birbirinden farklı olduğu test edildi.
- Cebirsel saldırılar, ortada buluşma (meet-in-the-middle) saldırıları
- TestU01 BigCrush ve NIST STS

Bunlar, spesifikasyonun "sonraki çalışma" önerileriyle birlikte, bir şifrenin güvenli
sayılabilmesi için gereken asgari analizin parçasıdır.
