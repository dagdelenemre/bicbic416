# bicbic416 (Python)

Log kayıtlarını **iki katmanlı** (BicBic416 + ChaCha20) şifreleyen ve HMAC-SHA256 ile
mühürleyen Python paketi. BicBic-Hash ve Python `logging` entegrasyonu da içerir.

> ⚠️ BicBic416 eğitim amaçlı, bağımsız kriptanalizden geçmemiş bir şifredir. İki katmanlı
> modda gizliliği ChaCha20 de sağlar; yine de kritik veriler için standart, denetlenmiş
> kütüphaneler tercih edin.

## Kurulum

```bash
pip install "git+https://github.com/dagdelenemre/bicbic416#subdirectory=python"
```

Bağımlılığı yoktur; yalnızca Python standart kütüphanesini kullanır (Python 3.9+).

## Kullanım

```python
import bicbic416

anahtar = bicbic416.generate_key()          # bir kez üretin, gizli saklayın
s = bicbic416.RecordCipher(anahtar)          # veya RecordCipher.from_env()

kayit = s.encrypt("kullanici=ayse ip=203.0.113.7")   # 'bb416r1:...'
s.decrypt(kayit)                                       # 'kullanici=ayse ip=203.0.113.7'
```

Python `logging` sistemine bağlamak için:

```python
import logging, bicbic416

s = bicbic416.RecordCipher.from_env()       # BICBIC_ANAHTAR ortam değişkeni
handler = logging.FileHandler("guvenlik.log")
handler.setFormatter(bicbic416.EncryptingFormatter(s))
logging.getLogger("site").addHandler(handler)
```

Komut satırından kullanım:

```bash
python -m bicbic416 anahtar-uret
```

```bash
python -m bicbic416 log-coz < guvenlik.log
```

Ayrıntılı rehber: [ENTEGRASYON.md](https://github.com/dagdelenemre/bicbic416/blob/main/ENTEGRASYON.md)

## Hız

- **Saf Python:** Kayıt başına yaklaşık 1,6 ms, saniyede yaklaşık 600 kayıt.
- **C kütüphanesiyle:** Paket kütüphaneyi bulursa otomatik olarak onu kullanır; kayıt
  başına birkaç mikrosaniye sürer. Kütüphaneyi depoda `make lib` ile derleyip
  `BICBIC416_LIB` ortam değişkeniyle gösterebilir ya da paket dizinine
  kopyalayabilirsiniz.
- Hangi yolun kullanıldığını `bicbic416.backend` gösterir: `"native"` veya `"pure"`.
