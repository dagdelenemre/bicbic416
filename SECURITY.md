# Güvenlik Politikası

## Durum

BicBic416 **eğitim ve araştırma amaçlı, deneysel** bir blok şifredir. Bağımsız uzman
kriptanalizinden geçmemiştir ve hiçbir güvenlik garantisi verilmez. Gerçek verileri
korumak için AES-GCM veya ChaCha20-Poly1305 gibi standart algoritmalar kullanın.

Bugüne kadar yapılan analizler ve bilinen sınırlar [ANALIZ.md](ANALIZ.md) dosyasında
belgelenmiştir.

## Bildirim

İki tür bulgu birbirinden ayrılır:

- **Kriptanaliz bulguları:** Ayırt edici, anahtar kurtarma, zayıf anahtar sınıfı gibi.
  Bunlar memnuniyetle karşılanır ve **herkese açık bir issue** olarak bildirilebilir.
  Algoritma deneysel olduğu için bu bulguların gizli tutulmasına gerek yoktur. Lütfen
  kullandığınız tur sayısını, veri miktarını ve sonucu yeniden üretmek için gereken
  adımları ekleyin.
- **Uygulama açıkları:** Komut satırı aracında, dosya biçimi ayrıştırıcısında veya web
  sayfasında bellek hatası, kimlik doğrulamayı atlatma gibi.
  Bunları GitHub'ın **"Report a vulnerability"** özelliğiyle, yani
  [özel güvenlik bildirimi](https://github.com/dagdelenemre/bicbic416/security/advisories/new)
  üzerinden iletin.

## Desteklenen sürümler

Yalnızca `main` dalındaki en son sürüm desteklenir.
