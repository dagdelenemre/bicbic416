# Değişiklik Günlüğü

Biçim [Keep a Changelog](https://keepachangelog.com/tr-TR/1.1.0/) kurallarını,
sürüm numaraları [Anlamsal Sürümleme](https://semver.org/lang/tr/) kurallarını izler.

## [0.3.0] — 2026-10-13

### Eklenenler

- **Log kayıt biçimi** (SPEC.md §14): Satır satır, **her zaman iki katmanlı**
  (BicBic416 + ChaCha20), HMAC-SHA256 ile mühürlü kayıtlar.
  - Metin hâli `bb416r1:…`; ek yük 37 bayt.
  - Parola yerine 32 baytlık bir ana anahtar kullanılır (`bb416k1:…`).
  - Anahtar kimliği sayesinde anahtar değiştirilebilir; isteğe bağlı ek bilgi (aad)
    desteklenir.
- **Python paketi `bicbic416`:**
  - `RecordCipher`, `EncryptingFormatter` ve `FieldEncryptingFilter` (logging
    entegrasyonu), BicBic-Hash
  - Saf Python (bağımlılıksız) çalışır; C kütüphanesi bulunursa onu kullanır.
  - Komut satırı: `python -m bicbic416`
- **Node.js / tarayıcı:** `web/bicbic416.js` içinde `RecordCipher`
- **Komut satırı:**
  - `bicbic anahtar-uret`
  - `bicbic log-sifrele`
  - `bicbic log-coz`: satırdaki tüm kayıtları yerinde açar
  - Anahtar halkası: `BICBIC_ANAHTAR` ya da `-k` ile dosya
- **Paylaşımlı kütüphane:** `make lib` (`bicbic416.dll`, `libbicbic416.so`)
- **Ortak test vektörleri:** `tests/data/record_vectors.json`. C, Python ve JavaScript
  testleri bu vektörleri kullanır.
- **ENTEGRASYON.md:** Python, Django, Node.js, rsyslog ve SIEM tarafı için örnekler;
  anahtar yönetimi ve sınırlar

## [0.2.0] — 2026-10-12

### Eklenenler

- **BicBic-Hash:** BicBic416'dan Miyaguchi–Preneel yapısıyla türetilen 416 bitlik
  (52 bayt) özet fonksiyonu (SPEC.md §12)
  - C API: `bb416_hash()` ve akışlı kullanım için `bb416_hash_init/update/final`
  - `bicbic hash` komutu
  - Web sayfasında Hash bölümü
- **İsteğe bağlı iki katmanlı şifreleme:** BicBic416-CTR'nin üstüne bağımsız anahtarlı
  ChaCha20 (RFC 8439) katmanı. Programda `bicbic sifrele -2`, web sayfasında bir kutucuk.
- HKDF-SHA256 (RFC 5869) ve ChaCha20 uygulamaları, OpenSSL çıktısıyla doğrulanan testlerle

### Değişenler

- **Dosya ve metin biçimi sürüm 2:** Ek yük 102 bayttan **36 bayta** indi.
  - Nonce'lar kaldırıldı; her dosya rastgele tuz sayesinde zaten kendine özgü anahtar alıyor.
  - Etiket 16 bayta indirildi.
  - Yineleme sayısı 2 baytta saklanıyor ve artık 1000'in katı olmalı.
  - Sürüm 1 dosyaları açılmaya devam ediyor.
- **Anahtar türetme:** PBKDF2 artık tek bir 32 baytlık ana sır üretiyor; anahtarlar
  HKDF ile bundan türetiliyor. Şifreleme ve çözme yaklaşık 3 kat hızlandı. Her parola
  tahmini yine 600 000 yineleme gerektirdiği için parola tahminine karşı koruma aynı.
- Dosya aracının parça boyutu, hem 52'nin hem 64'ün katı olacak şekilde 64 896 bayt yapıldı.

## [0.1.0] — 2026-10-12

İlk sürüm.

### Eklenenler

- **Blok şifre:** BicBic416 (416-bit blok, 416-bit anahtar, 1–32 tur, varsayılan 16)
  için C11 uygulaması, anahtar planı ve CTR modu
- **Vektörlü CTR yolu:** GCC/Clang taşınabilir vektör türleriyle aynı anda 4, 8 veya 16
  blok işlenir (AVX-512 ile 1.3 GB/s'ye kadar)
- **`bicbic` komut satırı aracı:** Parolayla dosya şifreleme
  - PBKDF2-HMAC-SHA256 ile anahtar türetme
  - Önce şifreleme, sonra HMAC-SHA256 ile mühürleme
  - `.bb416` dosya biçimi
- **Web uygulaması:** Tarayıcıda metin şifreleme (https://bicbic416.vercel.app);
  komut satırı aracıyla aynı biçimi kullanır
- **Bağımsız Python referans uygulaması** ve sabit test vektörleri (KAT)
- **Test paketi:** Birim testleri, gidiş-dönüş, CTR, dosya biçimi, çığ etkisi
- **Kriptanaliz araçları ve raporu (ANALIZ.md):**
  - Diferansiyel, lineer ve integral analiz
  - PractRand
  - Yapısal simetri testleri
  - Zamanlama yan kanalı testi
  - Dosya ayrıştırıcısı için bulanık test (fuzz)
