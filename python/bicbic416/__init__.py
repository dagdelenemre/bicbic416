"""
BicBic416 — deneysel 416-bit blok şifre için Python paketi.

Log kayıtlarını iki katmanlı (BicBic416 + ChaCha20) şifreleme, BicBic-Hash ve Python
``logging`` entegrasyonu sağlar. C kütüphanesi bulunursa onu kullanır (hızlı), bulunamazsa
saf Python ile çalışır (yalnızca standart kütüphane).

UYARI: BicBic416 eğitim amaçlı, bağımsız kriptanalizden geçmemiş bir şifredir. İki katmanlı
modda gizlilik ChaCha20 tarafından da sağlanır; yine de kritik veriler için standart,
denetlenmiş kütüphaneler tercih edin.

Hızlı başlangıç::

    import bicbic416
    sifreleyici = bicbic416.RecordCipher.from_env()      # BICBIC_ANAHTAR ortam değişkeni
    kayit = sifreleyici.encrypt("kullanici=ayse ip=203.0.113.7")
    sifreleyici.decrypt(kayit)
"""
from . import _native, _pure
from .log import EncryptingFormatter, FieldEncryptingFilter
from .record import (KEY_PREFIX, TEXT_PREFIX, TOKEN_RE, DecryptionError, RecordCipher,
                     generate_key, parse_key)

__version__ = "0.3.1"
__all__ = [
    "RecordCipher", "DecryptionError", "EncryptingFormatter", "FieldEncryptingFilter",
    "generate_key", "parse_key", "hash", "hash_hex", "backend", "KEY_PREFIX", "TEXT_PREFIX", "TOKEN_RE",
]


class _PureBackend:
    name = "pure"

    @staticmethod
    def record_key(master):
        return _pure.RecordKey(master)

    @staticmethod
    def bb_hash(data):
        return _pure.bb_hash(data)


_BACKEND = _native.load() or _PureBackend()
backend = _BACKEND.name
"""Kullanılan arka uç: "native" (C kütüphanesi) veya "pure" (saf Python)."""


def _backend():
    return _BACKEND


def hash(data):
    """BicBic-Hash: 416 bitlik (52 bayt) özet. Metin UTF-8 olarak işlenir. Deneyseldir."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return _BACKEND.bb_hash(data)


def hash_hex(data):
    """BicBic-Hash'in 104 karakterlik onaltılık hâli."""
    return hash(data).hex()
