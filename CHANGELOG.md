# Değişiklik Günlüğü

Biçim [Keep a Changelog](https://keepachangelog.com/tr-TR/1.1.0/) kurallarını,
sürüm numaraları [Anlamsal Sürümleme](https://semver.org/lang/tr/) kurallarını izler.

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
