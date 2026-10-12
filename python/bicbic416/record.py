"""
Log kayıtlarını iki katmanlı (BicBic416 + ChaCha20) şifreleme ve HMAC-SHA256 ile
mühürleme — SPEC.md §14.

    >>> import bicbic416
    >>> anahtar = bicbic416.generate_key()            # bir kez üretin, gizli saklayın
    >>> sifreleyici = bicbic416.RecordCipher(anahtar)
    >>> kayit = sifreleyici.encrypt("kullanici=ayse giris=basarili")
    >>> sifreleyici.decrypt(kayit)
    'kullanici=ayse giris=basarili'
"""
import base64
import os
import re

from . import _pure

TEXT_PREFIX = "bb416r1:"
KEY_PREFIX = "bb416k1:"
TOKEN_RE = re.compile(r"bb416r1:[A-Za-z0-9_-]+")

_ERRORS = {
    2: "BicBic416 kaydı değil veya eksik kopyalanmış",
    3: "kayıt, verilen anahtarlardan hiçbiriyle şifrelenmemiş",
    4: "mühür tutmuyor: kayıt veya ek bilgi değiştirilmiş",
}


class DecryptionError(ValueError):
    """Kayıt açılamadı (biçim hatası, yanlış anahtar veya kurcalama)."""


def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s):
    if len(s) % 4 == 1 or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise DecryptionError(_ERRORS[2])
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if _b64e(raw) != s:  # kanonik olmayan kodlamayı reddet (C ile aynı davranış)
        raise DecryptionError(_ERRORS[2])
    return raw


def _bytes(x):
    if isinstance(x, str):
        return x.encode("utf-8")
    return bytes(x)


def generate_key():
    """Yeni rastgele ana anahtar ("bb416k1:..."). Bir kez üretip gizli saklayın."""
    return KEY_PREFIX + _b64e(os.urandom(32))


def parse_key(text):
    """"bb416k1:..." metnini 32 baytlık anahtara çevirir."""
    if not isinstance(text, str) or not text.startswith(KEY_PREFIX) or len(text) != len(KEY_PREFIX) + 43:
        raise ValueError('geçersiz anahtar: "bb416k1:" ile başlamalı (üretmek için: bicbic416.generate_key())')
    try:
        raw = _b64d(text[len(KEY_PREFIX):])
    except DecryptionError:
        raise ValueError("geçersiz anahtar: base64url çözülemedi") from None
    return raw


class RecordCipher:
    """
    Log kayıtları için şifreleyici.

    keys: tek anahtar ("bb416k1:...") veya anahtar listesi. Listenin İLK anahtarı yeni
    kayıtları şifreler; hepsi eski kayıtları açmak için denenir (anahtar değiştirme).
    """

    def __init__(self, keys):
        from . import _backend  # döngüsel içe aktarmayı önlemek için geç yüklenir

        if isinstance(keys, (str, bytes)):
            keys = [keys]
        keys = [k.strip() for k in keys if k and k.strip()]
        if not keys:
            raise ValueError("en az bir anahtar gerekli")
        self._keys = []
        for k in keys:
            master = parse_key(k) if isinstance(k, str) else bytes(k)
            self._keys.append(_backend().record_key(master))
        self._by_kid = {k.kid: k for k in reversed(self._keys)}

    @classmethod
    def from_env(cls, name="BICBIC_ANAHTAR"):
        """Anahtarları ortam değişkeninden okur (virgülle ayrılmış; ilki şifreler)."""
        value = os.environ.get(name)
        if not value:
            raise ValueError(f"{name} ortam değişkeni tanımlı değil (yeni anahtar: python -m bicbic416 anahtar-uret)")
        return cls(value.split(","))

    @property
    def key_id(self):
        """Şifreleme anahtarının 8 karakterlik kimliği (loglarda hangi anahtarın kullanıldığını görmek için)."""
        return self._keys[0].kid.hex()

    def encrypt_bytes(self, data, aad=b""):
        return TEXT_PREFIX + _b64e(self._keys[0].encrypt(_bytes(data), _bytes(aad)))

    def encrypt(self, message, aad=b""):
        """Mesajı tek satırlık bir kayda ("bb416r1:...") çevirir. aad: şifrelenmeyen ama mühre giren ek bilgi."""
        return self.encrypt_bytes(_bytes(message), aad)

    def decrypt_bytes(self, token, aad=b""):
        token = token.strip()
        if not token.startswith(TEXT_PREFIX):
            raise DecryptionError(_ERRORS[2])
        rec = _b64d(token[len(TEXT_PREFIX):])
        key = self._by_kid.get(rec[1:5]) if len(rec) >= 5 else None
        if key is None:
            raise DecryptionError(_ERRORS[2] if len(rec) < _pure.OVERHEAD or rec[0] != _pure.RECORD_FORMAT
                                  else _ERRORS[3])
        rc, plain = key.decrypt(rec, _bytes(aad))
        if rc:
            raise DecryptionError(_ERRORS.get(rc, "kayıt açılamadı"))
        return plain

    def decrypt(self, token, aad=b""):
        """Kaydı açar ve UTF-8 metin olarak döndürür. Açılamazsa DecryptionError."""
        return self.decrypt_bytes(token, aad).decode("utf-8", errors="replace")

    def encrypt_fields(self, data, fields):
        """Sözlükteki yalnızca belirtilen alanları şifreler (diğerleri SIEM'de aranabilir kalır)."""
        out = dict(data)
        for f in fields:
            if f in out and out[f] is not None:
                out[f] = self.encrypt(str(out[f]))
        return out

    def decrypt_fields(self, data):
        """Sözlükteki "bb416r1:" ile başlayan tüm alanları açar."""
        return {k: (self.decrypt(v) if isinstance(v, str) and v.startswith(TEXT_PREFIX) else v)
                for k, v in data.items()}

    def decrypt_line(self, line, on_error="[ÇÖZÜLEMEDİ]"):
        """Bir satırdaki tüm kayıtları yerinde açar; açılamayanların yerine on_error yazılır."""
        def repl(m):
            try:
                return self.decrypt(m.group(0))
            except DecryptionError:
                if on_error is None:
                    raise
                return on_error
        return TOKEN_RE.sub(repl, line)
