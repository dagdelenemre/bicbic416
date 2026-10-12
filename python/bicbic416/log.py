"""
Python ``logging`` entegrasyonu.

Tüm mesajı şifrelemek (tarih, seviye ve kaynak açık kalır, SIEM bunlarla arama yapabilir)::

    handler.setFormatter(EncryptingFormatter(cipher, "%(asctime)s %(levelname)s %(name)s %(message)s"))

Yalnızca hassas alanları şifrelemek (``extra=`` ile verilen alanlar; her formatter ile çalışır)::

    logger.addFilter(FieldEncryptingFilter(cipher, ["kullanici", "ip"]))
    logger.info("giris", extra={"kullanici": "ayse", "ip": "203.0.113.7"})
"""
import logging

from .record import RecordCipher


class EncryptingFormatter(logging.Formatter):
    """
    Mesajı (ve varsa hata/yığın izini) şifreler; biçimin geri kalanı (tarih, seviye,
    kaynak) açık kalır. Kayıtlar ``bicbic log-coz``, ``python -m bicbic416 log-coz`` veya
    ``RecordCipher.decrypt_line`` ile açılır.
    """

    def __init__(self, cipher, fmt=None, datefmt=None, style="%"):
        if not isinstance(cipher, RecordCipher):
            raise TypeError("cipher bir RecordCipher olmalı")
        super().__init__(fmt or "%(asctime)s %(levelname)s %(name)s %(message)s", datefmt, style)
        self.cipher = cipher

    def format(self, record):
        message = record.getMessage()
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            message += "\n" + record.exc_text
        if record.stack_info:
            message += "\n" + self.formatStack(record.stack_info)

        safe = logging.makeLogRecord(record.__dict__)
        safe.msg, safe.args = self.cipher.encrypt(message), None
        safe.exc_info = safe.exc_text = safe.stack_info = None
        return super().format(safe)


class FieldEncryptingFilter(logging.Filter):
    """``extra=`` ile verilen belirli alanları kayda yazılmadan önce şifreler."""

    def __init__(self, cipher, fields):
        super().__init__()
        self.cipher = cipher
        self.fields = tuple(fields)

    def filter(self, record):
        for f in self.fields:
            value = record.__dict__.get(f)
            if value is not None and not (isinstance(value, str) and value.startswith("bb416r1:")):
                setattr(record, f, self.cipher.encrypt(str(value)))
        return True
