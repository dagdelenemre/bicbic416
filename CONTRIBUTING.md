# Katkı Rehberi

Katkılarınız için teşekkürler. Özellikle kriptanaliz bulguları, ek testler ve
taşınabilirlik düzeltmeleri değerlidir.

## Geliştirme ortamı

Gerekenler:

- C11 derleyicisi (GCC veya Clang) ve GNU make
- Python 3 (referans uygulama için; test vektörlerini yeniden üretmek için ayrıca
  `pip install cryptography` ve `python tests/gen_vectors.py`)
- Node.js 20 veya üzeri (web uygulaması testi için)

Windows'ta [w64devkit](https://github.com/skeeto/w64devkit) ve
[llvm-mingw](https://github.com/mstorsjo/llvm-mingw) önerilir. llvm-mingw Windows'ta
ASan ve UBSan destekler.

## Değişiklik göndermeden önce

Aşağıdaki komutların hepsi hatasız geçmeli:

```bash
make check
```

```bash
make tool
```

```bash
python ref/bicbic416_ref.py
```

```bash
node web/test.mjs
```

`make check` testleri GCC, Clang ve Clang + AddressSanitizer/UBSan ile çalıştırır.
Kod `-Wall -Wextra -Wpedantic` altında uyarısız derlenmelidir; `-Werror` açıktır.

## Kurallar

- **Tasarım sabitleri** (tur adımları, döndürme miktarları, anahtar planı sabitleri)
  yalnızca [SPEC.md](SPEC.md) ile birlikte değiştirilir. Böyle bir değişiklik
  algoritmanın çıktısını değiştirir. Bu durumda `tests/test_kat.c` yeniden üretilmeli
  ve `ref/bicbic416_ref.py` güncellenmelidir.
- **Performans değişiklikleri** şifrenin çıktısını değiştirmemelidir. `test_kat` ve
  `test_roundtrip` bunu doğrular.
- Şifre kütüphanesi (`src/`, `include/`) taşınabilir C11 olarak kalmalıdır:
  platforma özel başlık veya intrinsic kullanılmaz. Platforma özel kod yalnızca
  `tool/` ve `analysis/` altında yer alabilir.
- Gizli veriye bağlı dal veya dizi indeksi kullanılmaz (sabit zamanlı kod).
- Kod stili mevcut dosyalarla aynıdır: 4 boşluk girinti, Türkçe yorumlar.

## Kriptanaliz bulguları

Bulgularınızı bir issue olarak açın. Şunları ekleyin:

- Tur sayısı
- Kullanılan veri miktarı
- Bulguyu yeniden üretmek için gereken kod veya komutlar

Ayrıntılar için [SECURITY.md](SECURITY.md) dosyasına bakın.
