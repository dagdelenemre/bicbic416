"""
C kütüphanesi arka ucu (ctypes). Kütüphane şu sırayla aranır:

1. BICBIC416_LIB ortam değişkenindeki yol
2. Bu paketin dizini (bicbic416.dll / libbicbic416.so / libbicbic416.dylib)

Bulunamazsa ``load()`` None döndürür ve paket saf Python arka ucunu kullanır.
Kütüphaneyi derlemek için depo kökünde: ``make lib``.
"""
import ctypes
import os
import sys

from ._pure import hkdf_sha256

_NAMES = {"win32": "bicbic416.dll", "darwin": "libbicbic416.dylib"}


def _candidates():
    env = os.environ.get("BICBIC416_LIB")
    if env:
        yield env
    name = _NAMES.get(sys.platform, "libbicbic416.so")
    yield os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


class NativeRecordKey:
    """_pure.RecordKey ile aynı arayüz; işi C kütüphanesi yapar."""

    __slots__ = ("_lib", "_buf", "kid")

    def __init__(self, lib, master):
        if len(master) != 32:
            raise ValueError("ana anahtar 32 bayt olmalı")
        self._lib = lib
        self._buf = ctypes.create_string_buffer(lib.bbr_key_size())
        lib.bbr_key_init(self._buf, bytes(master))
        # Kimlik, C ile aynı HKDF çıktısının son 4 baytıdır (anahtar halkasında seçim için).
        self.kid = hkdf_sha256(bytes(master), b"BicBic416 kayit v1", 120)[116:]

    def encrypt(self, msg, aad=b"", nonce=None):
        msg, aad = bytes(msg), bytes(aad)
        out = ctypes.create_string_buffer(len(msg) + 37)
        out_len = ctypes.c_size_t()
        if nonce is None:
            rc = self._lib.bbr_encrypt(self._buf, msg, len(msg), aad, len(aad), out, ctypes.byref(out_len))
        else:
            rc = self._lib.bbr_encrypt_with_nonce(self._buf, bytes(nonce), msg, len(msg), aad, len(aad),
                                                  out, ctypes.byref(out_len))
        if rc != 0:
            raise OSError("kayıt şifrelenemedi (C hata kodu %d)" % rc)
        return out.raw[:out_len.value]

    def decrypt(self, rec, aad=b""):
        rec, aad = bytes(rec), bytes(aad)
        out = ctypes.create_string_buffer(max(len(rec) - 37, 1))
        out_len = ctypes.c_size_t()
        rc = self._lib.bbr_decrypt(self._buf, rec, len(rec), aad, len(aad), out, ctypes.byref(out_len))
        return (rc, out.raw[:out_len.value]) if rc == 0 else (rc, None)

    def __del__(self):
        try:
            ctypes.memset(self._buf, 0, len(self._buf))
        except Exception:
            pass


class NativeBackend:
    name = "native"

    def __init__(self, lib):
        self.lib = lib

    def record_key(self, master):
        return NativeRecordKey(self.lib, master)

    def bb_hash(self, data):
        data = bytes(data)
        out = ctypes.create_string_buffer(52)
        self.lib.bb416_hash(data, len(data), out)
        return out.raw


def load():
    for path in _candidates():
        if not os.path.isfile(path):
            continue
        try:
            lib = ctypes.CDLL(path)
            _declare(lib)
        except (OSError, AttributeError):
            continue  # yüklenemeyen veya eski sürüm kütüphane: saf Python'a dön
        return NativeBackend(lib)
    return None


def _declare(lib):
    """Fonksiyon imzalarını tanımlar; eksik fonksiyon varsa AttributeError fırlatır."""
    sz, vp, cp = ctypes.c_size_t, ctypes.c_void_p, ctypes.c_char_p
    lib.bbr_key_size.restype = sz
    lib.bbr_key_size.argtypes = []
    lib.bbr_key_init.restype = None
    lib.bbr_key_init.argtypes = [vp, cp]
    lib.bbr_encrypt.restype = ctypes.c_int
    lib.bbr_encrypt.argtypes = [vp, cp, sz, cp, sz, vp, ctypes.POINTER(sz)]
    lib.bbr_encrypt_with_nonce.restype = ctypes.c_int
    lib.bbr_encrypt_with_nonce.argtypes = [vp, cp, cp, sz, cp, sz, vp, ctypes.POINTER(sz)]
    lib.bbr_decrypt.restype = ctypes.c_int
    lib.bbr_decrypt.argtypes = [vp, cp, sz, cp, sz, vp, ctypes.POINTER(sz)]
    lib.bb416_hash.restype = None
    lib.bb416_hash.argtypes = [cp, sz, vp]
