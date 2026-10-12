# Entegrasyon Rehberi: Log Kayıtlarını BicBic416 ile Şifreleme

Bu rehber, bir web sitesinin veya uygulamanın güvenlik loglarını **iki katmanlı**
(BicBic416 + ChaCha20) şifreleyip HMAC-SHA256 ile mühürlemeyi ve bu logları SOC/SIEM
tarafında okumayı anlatır. Biçimin teknik tanımı [SPEC.md §14](SPEC.md) bölümündedir.

> ⚠️ BicBic416 deneysel bir şifredir. İki katmanlı yapıda gizliliği ChaCha20 de sağlar,
> ama bu kod bağımsız bir güvenlik denetiminden geçmedi. Yasal saklama yükümlülüğü olan
> veya kritik loglar için standart, denetlenmiş çözümleri tercih edin.

---

## Hangi yolu seçmeliyim?

| Siteniz / ortamınız | Önerilen yol | Hız (tek çekirdek) |
|---|---|---|
| Python (Flask, Django, FastAPI…) | `bicbic416` Python paketi | ~500 kayıt/s saf Python; C kütüphanesiyle ~55 000+ |
| Node.js (Express, Next.js…) | `web/bicbic416.js` dosyası | ~9 000 kayıt/s |
| PHP, Go, Java, kabuk betikleri… | `bicbic log-sifrele` komutu (boru ile) | ~60 000 kayıt/s |
| SOC / SIEM tarafında okuma | `bicbic log-coz` veya Python paketi | — |

Hepsi aynı biçimi üretir. Bir dilde şifrelenen kayıt öbür dillerde açılabilir; bu,
ortak test vektörleriyle (`tests/data/record_vectors.json`) sürekli doğrulanır.

---

## 1. Anahtar üretin ve saklayın

Her kurulum için **bir kez** bir ana anahtar üretin. Aşağıdaki komutlardan birini
kullanabilirsiniz:

```bash
bicbic anahtar-uret
```

```bash
python -m bicbic416 anahtar-uret
```

Çıktı `bb416k1:` ile başlayan 51 karakterlik bir metindir. Anahtar kimliği (8 karakter)
ayrıca ekrana yazılır.

**Anahtarı nerede saklamalı:**

- **Uygulamaya ortam değişkeniyle verin:** `BICBIC_ANAHTAR`. Örneğin systemd için
  `EnvironmentFile=/etc/bicbic/ortam` (dosya izni `600`) ya da barındırma panelinizin
  "secret" / "environment variable" ayarı.
- **Git deposuna asla koymayın.**
- **Güvenli bir yere yedekleyin** (ör. parola yöneticisi). Anahtarı kaybederseniz o
  anahtarla şifrelenmiş loglar **bir daha açılamaz**.

**Anahtar değiştirme:** Yeni bir anahtar üretin ve listenin başına koyun:
`BICBIC_ANAHTAR="yeni,eski"`. Yeni kayıtlar ilk anahtarla şifrelenir; eski kayıtlar
listedeki eski anahtarla açılmaya devam eder. Hangi kaydın hangi anahtarla şifrelendiği
kaydın içinde yazılıdır.

---

## 2. Neyi şifrelemeli?

Şifrelenmiş içeriği SIEM aratamaz. Bu yüzden önce bir seçim yapmanız gerekir:

| Yöntem | Kayıt örneği | Avantajı | Dezavantajı |
|---|---|---|---|
| **Yalnızca hassas alanlar** (önerilen) | `giris basarili kullanici=bb416r1:… ip=bb416r1:…` | SIEM olay türü, zaman ve sonuçla arama yapabilir | Hassas alanları sizin belirlemeniz gerekir |
| **Tüm mesaj** | `2026-10-13 10:00 WARNING site bb416r1:…` | En gizli seçenek | SIEM'e girmeden önce çözme adımı gerekir |

Hassas alan örnekleri: kullanıcı adı ve e-posta, IP adresi, oturum ve parola sıfırlama
bağlantıları, kişisel veriler, istek gövdeleri.

---

## 3. Python

Paketi kurmak için:

```bash
pip install "git+https://github.com/dagdelenemre/bicbic416#subdirectory=python"
```

Bağımlılığı yoktur (Python 3.9+).

### Tüm mesajı şifrelemek (logging)

```python
import logging
import bicbic416

sifreleyici = bicbic416.RecordCipher.from_env()          # BICBIC_ANAHTAR

handler = logging.FileHandler("/var/log/site/guvenlik.log", encoding="utf-8")
handler.setFormatter(bicbic416.EncryptingFormatter(
    sifreleyici, "%(asctime)s %(levelname)s %(name)s %(message)s"))

guvenlik = logging.getLogger("guvenlik")
guvenlik.addHandler(handler)
guvenlik.setLevel(logging.INFO)

guvenlik.warning("basarisiz giris kullanici=%s ip=%s", "ayse", "203.0.113.7")
# 2026-10-13 10:00:00,123 WARNING guvenlik bb416r1:s-a2LYim...
```

Tarih, seviye ve kaynak açık kalır; mesaj, hata ve yığın izi (traceback) şifrelenir.

### Yalnızca belirli alanları şifrelemek

```python
guvenlik.addFilter(bicbic416.FieldEncryptingFilter(sifreleyici, ["kullanici", "ip"]))
handler.setFormatter(logging.Formatter(
    "%(asctime)s %(levelname)s %(message)s kullanici=%(kullanici)s ip=%(ip)s"))

guvenlik.info("giris basarili", extra={"kullanici": "ayse", "ip": "203.0.113.7"})
# 2026-10-13 10:00:00,123 INFO giris basarili kullanici=bb416r1:… ip=bb416r1:…
```

JSON loglarında:

```python
import json
olay = {"olay": "giris", "sonuc": "basarili", "kullanici": "ayse", "ip": "203.0.113.7"}
guvenlik.info(json.dumps(sifreleyici.encrypt_fields(olay, ["kullanici", "ip"]), ensure_ascii=False))
```

### Django

Django'da `settings.py` içinde:

```python
LOGGING = {
    "version": 1,
    "formatters": {
        "sifreli": {
            "()": "bicbic416.EncryptingFormatter",
            "cipher": "ext://projem.guvenlik.SIFRELEYICI",
            "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "guvenlik": {"class": "logging.FileHandler", "filename": "/var/log/site/guvenlik.log",
                     "formatter": "sifreli", "encoding": "utf-8"},
    },
    "loggers": {"guvenlik": {"handlers": ["guvenlik"], "level": "INFO"}},
}
```

`projem/guvenlik.py` dosyasında ise:

```python
import bicbic416
SIFRELEYICI = bicbic416.RecordCipher.from_env()
```

### C hızlandırması (isteğe bağlı)

Saf Python saniyede yaklaşık 500 kayıt işler; bu çoğu site için fazlasıyla yeterlidir.
Daha fazlası gerekirse depoda C kütüphanesini derleyin:

```bash
make lib
```

Sonra kütüphane dosyasını `BICBIC416_LIB` ortam değişkeniyle gösterin ya da paket
dizinine kopyalayın. Paket kütüphaneyi otomatik bulur ve kullanır; hangi yolun
kullanıldığını `bicbic416.backend` gösterir (`"native"` veya `"pure"`).

---

## 4. Node.js

[web/bicbic416.js](web/bicbic416.js) dosyasını projenize kopyalayın. Bağımlılığı yoktur;
Node.js 19 veya üzeri gerekir (20 LTS önerilir).

```js
import { RecordCipher } from "./bicbic416.js";

const sifreleyici = await RecordCipher.create(process.env.BICBIC_ANAHTAR.split(","));

app.post("/giris", async (req, res) => {
  // ...
  console.log(new Date().toISOString(), "INFO giris basarili",
              "kullanici=" + await sifreleyici.encrypt(kullanici),
              "ip=" + await sifreleyici.encrypt(req.ip));
});
```

Kullanılabilecek diğer yöntemler:

- `encryptFields(nesne, ["alan", ...])` ve `decryptFields(nesne)`: JSON loglarındaki
  alanları şifreler ve açar.
- `decryptLine(satir)`: Bir satırdaki tüm kayıtları yerinde açar.

---

## 5. Diğer diller ve mevcut log dosyaları

`bicbic` komut satırı aracı standart girdiden satır okur ve standart çıktıya yazar. Bu
sayede her dilden ve her log sisteminden kullanılabilir. Aracı derlemek için:

```bash
make tool
```

Anahtarı `BICBIC_ANAHTAR` ortam değişkeniyle ya da her satırında bir anahtar olan bir
dosyayla verin. Dosyayı kullanırken `-k /etc/bicbic/anahtarlar` ekleyin.

Bir uygulamanın çıktısını doğrudan şifreli olarak kaydetmek için:

```bash
uygulama 2>&1 | bicbic log-sifrele >> /var/log/site/guvenlik.bb416.log
```

**rsyslog:** `omprog` modülü, mesajları bir programın standart girdisine verir. Önce
`/usr/local/bin/bicbic-yaz` adında küçük bir betik oluşturun:

```sh
#!/bin/sh
exec bicbic log-sifrele -k /etc/bicbic/anahtarlar >> /var/log/guvenlik.bb416.log
```

Ardından rsyslog yapılandırmasına şunu ekleyin:

```text
module(load="omprog")
if $programname == 'site' then action(type="omprog" binary="/usr/local/bin/bicbic-yaz")
```

> **Not:** `tail -F duz.log | bicbic log-sifrele` gibi kurulumlarda düz metin bir süre
> diskte kalır. Mümkünse uygulamanın doğrudan şifreli yazmasını sağlayın (Python ve
> Node.js yolları bunu yapar). PHP için yerel bir uygulama ileride eklenebilir; o zamana
> kadar komut satırı aracını kullanın.

---

## 6. SOC / SIEM tarafında okuma

**Elle inceleme.** Satırlardaki tüm kayıtlar yerinde açılır, gerisi aynen kalır.
Açılamayan kayıtların yerine `[ÇÖZÜLEMEDİ: …]` yazılır ve çıkış kodu 2 olur:

```bash
bicbic log-coz -k /etc/bicbic/anahtarlar < guvenlik.bb416.log | less
```

**SIEM'e göndermeden önce otomatik çözme.** Örneğin Filebeat, Fluent Bit veya Vector'ün
okuyacağı bir dosyaya yazmak için:

```python
import sys, bicbic416
s = bicbic416.RecordCipher.from_env()
for satir in sys.stdin:
    print(s.decrypt_line(satir.rstrip("\n")), flush=True)
```

Bu betiği çalıştıran makine anahtara sahip olduğu için, o makinenin güvenliği
şifrelemenin güvenliği kadar önemlidir.

---

## 7. Boyut ve hız

- **Boyut:** Her kayda 37 bayt ek bilgi eklenir; metin hâlinde bu yaklaşık **58
  karaktere** karşılık gelir. Örneğin "merhaba", `bb416r1:` dahil 67 karakter olur.
- **Hız:** Tek çekirdekte, yaklaşık 375 baytlık kayıtlarla ölçüldü:

| Yol | Şifreleme | Çözme |
|---|---:|---:|
| C komut satırı (`bicbic`, dosya okuma/yazma dahil) | ~59 000 kayıt/s | ~41 000 kayıt/s |
| Python + C kütüphanesi | ~78 000 kayıt/s | ~56 000 kayıt/s |
| Node.js | ~9 400 kayıt/s | ~10 000 kayıt/s |
| Saf Python | ~520 kayıt/s | ~590 kayıt/s |

Tipik bir topluluk sitesi saniyede birkaç ile birkaç yüz arası güvenlik olayı üretir;
her yol bunun çok üstündedir.

---

## 8. Güvenlik notları ve sınırlar

- **Simetrik anahtar:** Logları yazan sunucu, aynı anahtarla eski logları da okuyabilir.
  Sunucu ele geçirilirse anahtar da ele geçmiş sayılmalıdır. "Yazan okuyamasın"
  gerekiyorsa açık anahtarlı (asimetrik) bir yapı gerekir; bu, gelecekteki bir sürümün
  konusudur.
- **Silme tespit edilmez:** Her kayıt tek tek mühürlenir; değiştirilen kayıt açılmaz.
  Ama log dosyasına yazabilen biri bir satırı **tamamen silebilir** ve bu biçim bunu fark
  etmez. Önlem olarak şifreli mesajın içine artan bir sıra numarası koyun ve SIEM'de
  boşlukları izleyin. Daha iyisi, loglar oluştukları anda merkezî ve yalnızca
  eklenebilen (append-only) bir depoya gönderilsin.
- **Ek bilgi (`aad`):** Açık kalan ama değiştirilmesi engellenen bilgiler (ör. sunucu
  adı) için kullanılır. Çözerken aynı ek verilmelidir. `bicbic log-coz` ek bilgisiz
  kayıtları açar; ek bilgi kullanıyorsanız çözmeyi Python veya Node.js ile yapın.
- **Anahtar kaybı:** Anahtarı yedeklemeyi unutmayın. Yedek yoksa loglar geri gelmez.
- **Deneysellik:** BicBic416 katmanı analiz edilmemiş bir tasarımdır. Gizliliğin tabanını
  ChaCha20 sağlar; mühürleme standart HMAC-SHA256'dır. Uygulama kodu ise bağımsız bir
  denetimden geçmedi.
