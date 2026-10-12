## Ne değişiyor?

<!-- Kısa açıklama ve ilgili issue (ör. "#12'yi kapatır") -->

## Değişiklik türü

- [ ] Hata düzeltmesi
- [ ] Yeni özellik
- [ ] Performans (çıktı değişmemeli)
- [ ] Belgeler
- [ ] Tasarım değişikliği (SPEC.md ile birlikte; çıktıyı değiştirir)

## Kontrol listesi

- [ ] `make check` geçiyor (GCC, Clang ve sanitizer'lar)
- [ ] `python ref/bicbic416_ref.py` geçiyor
- [ ] `node web/test.mjs` geçiyor
- [ ] `python -m unittest discover -s python/tests` geçiyor
- [ ] Tasarım değiştiyse `SPEC.md`, `tests/test_kat.c` ve `make vectors` güncellendi
- [ ] `CHANGELOG.md` güncellendi
- [ ] Anahtar, parola veya gerçek log verisi eklenmedi
