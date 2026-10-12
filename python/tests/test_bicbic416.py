"""
bicbic416 Python paketi testleri (yalnızca standart kütüphane: python -m unittest).

- Ortak test vektörleri (tests/data/record_vectors.json, C ile üretildi): saf Python ve
  (varsa) C arka ucu aynı kayıtları üretmeli ve açmalı
- RecordCipher API'si: gidiş-dönüş, ek bilgi, kurcalama, anahtar değiştirme, alanlar, satırlar
- logging entegrasyonu
- C komut satırı aracıyla (`bicbic`) ve `python -m bicbic416` ile karşılıklı uyumluluk
"""
import base64
import io
import json
import logging
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "python"))

import bicbic416  # noqa: E402
from bicbic416 import _native, _pure  # noqa: E402

VECTORS = os.path.join(ROOT, "tests", "data", "record_vectors.json")
LIB = os.path.join(ROOT, "build", {"win32": "bicbic416.dll", "darwin": "libbicbic416.dylib"}
                   .get(sys.platform, "libbicbic416.so"))
CLI = os.path.join(ROOT, "build", "bicbic.exe" if sys.platform == "win32" else "bicbic")


def backends():
    """Test edilecek arka uçlar: saf Python her zaman, C kütüphanesi derlenmişse o da."""
    out = [("pure", _pure.RecordKey, _pure.bb_hash)]
    if os.path.isfile(LIB):
        old = os.environ.get("BICBIC416_LIB")
        os.environ["BICBIC416_LIB"] = LIB
        nb = _native.load()
        if old is None:
            del os.environ["BICBIC416_LIB"]
        else:
            os.environ["BICBIC416_LIB"] = old
        if nb:
            out.append(("native", nb.record_key, nb.bb_hash))
    return out


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class TestVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS, encoding="utf-8") as f:
            cls.data = json.load(f)

    def test_records_match_c(self):
        for name, make_key, _ in backends():
            for v in self.data["kayitlar"]:
                with self.subTest(arka_uc=name, kayit=v["kayit"][:24]):
                    k = make_key(bicbic416.parse_key(v["anahtar"]))
                    self.assertEqual(k.kid.hex(), v["kimlik"])
                    aad, msg = bytes.fromhex(v["ek_hex"]), bytes.fromhex(v["mesaj_hex"])
                    rec = k.encrypt(msg, aad, bytes.fromhex(v["nonce"]))
                    self.assertEqual("bb416r1:" + b64u(rec), v["kayit"])
                    self.assertEqual(k.decrypt(rec, aad), (0, msg))

    def test_hash_matches_c(self):
        for name, _, h in backends():
            for v in self.data["hashler"]:
                with self.subTest(arka_uc=name):
                    self.assertEqual(h(bytes.fromhex(v["mesaj_hex"])).hex(), v["hash"])

    def test_backends_agree(self):
        bs = backends()
        if len(bs) < 2:
            self.skipTest("C kütüphanesi derlenmemiş (make lib)")
        master = os.urandom(32)
        (_, pk, ph), (_, nk, nh) = bs[0], bs[1]
        p, n = pk(master), nk(master)
        for size in (0, 1, 51, 52, 53, 63, 64, 65, 500, 3000):
            msg, aad, nonce = os.urandom(size), os.urandom(size % 40), os.urandom(16)
            self.assertEqual(p.encrypt(msg, aad, nonce), n.encrypt(msg, aad, nonce))
            self.assertEqual(n.decrypt(p.encrypt(msg, aad), aad), (0, msg))
            self.assertEqual(ph(msg), nh(msg))


class TestRecordCipher(unittest.TestCase):
    def setUp(self):
        self.key = bicbic416.generate_key()
        self.c = bicbic416.RecordCipher(self.key)

    def test_roundtrip(self):
        for msg in ["", "a", "kullanici=ayşe ip=203.0.113.7 🔐", "x" * 5000]:
            tok = self.c.encrypt(msg)
            self.assertTrue(tok.startswith("bb416r1:"))
            self.assertEqual(self.c.decrypt(tok), msg)
        self.assertEqual(self.c.decrypt_bytes(self.c.encrypt_bytes(b"\x00\xff")), b"\x00\xff")
        self.assertNotEqual(self.c.encrypt("ayni"), self.c.encrypt("ayni"))
        self.assertEqual(len(self.c.encrypt("merhaba")), 8 + 59)

    def test_aad(self):
        tok = self.c.encrypt("mesaj", aad="2026-10-13 web-1")
        self.assertEqual(self.c.decrypt(tok, aad="2026-10-13 web-1"), "mesaj")
        with self.assertRaises(bicbic416.DecryptionError):
            self.c.decrypt(tok, aad="2026-10-13 web-2")
        with self.assertRaises(bicbic416.DecryptionError):
            self.c.decrypt(tok)

    def test_tamper(self):
        tok = self.c.encrypt("kritik olay")
        body = tok[8:]
        for i in range(len(body)):
            ch = "A" if body[i] != "A" else "B"
            bad = "bb416r1:" + body[:i] + ch + body[i + 1:]
            with self.assertRaises(bicbic416.DecryptionError):
                self.c.decrypt(bad)
        for bad in ["", "bb416r1:", "bb416r1:!!!!", tok[:-1], tok + "A", "xx" + tok]:
            with self.assertRaises(bicbic416.DecryptionError):
                self.c.decrypt(bad)

    def test_key_rotation(self):
        old, new = self.c, bicbic416.RecordCipher(bicbic416.generate_key())
        t_old, t_new = old.encrypt("eski"), new.encrypt("yeni")
        with self.assertRaises(bicbic416.DecryptionError):
            new.decrypt(t_old)
        ring = bicbic416.RecordCipher([bicbic416.generate_key(), self.key])
        self.assertEqual(ring.decrypt(t_old), "eski")
        self.assertNotEqual(ring.key_id, old.key_id)
        with self.assertRaises(bicbic416.DecryptionError):  # yeni kayıtlar listenin ilk anahtarıyla
            old.decrypt(ring.encrypt("ilk anahtarla"))

    def test_from_env(self):
        os.environ["BICBIC_TEST_ANAHTAR"] = f" {bicbic416.generate_key()} , {self.key}"
        try:
            c = bicbic416.RecordCipher.from_env("BICBIC_TEST_ANAHTAR")
            self.assertEqual(c.decrypt(self.c.encrypt("ortam")), "ortam")
        finally:
            del os.environ["BICBIC_TEST_ANAHTAR"]
        with self.assertRaises(ValueError):
            bicbic416.RecordCipher.from_env("BICBIC_YOK_BOYLE_BIR_DEGISKEN")

    def test_keys(self):
        k = bicbic416.generate_key()
        self.assertEqual(len(bicbic416.parse_key(k)), 32)
        for bad in ["", "bb416k1:kisa", k[:-1] + "!", "bb416k2:" + k[8:], k + "A"]:
            with self.assertRaises(ValueError):
                bicbic416.parse_key(bad)
        with self.assertRaises(ValueError):
            bicbic416.RecordCipher([])

    def test_fields_and_lines(self):
        olay = {"olay": "giris", "kullanici": "ayşe@ornek.org", "ip": "203.0.113.7", "sure_ms": 42}
        enc = self.c.encrypt_fields(olay, ["kullanici", "ip"])
        self.assertEqual(enc["olay"], "giris")
        self.assertEqual(enc["sure_ms"], 42)
        self.assertTrue(enc["kullanici"].startswith("bb416r1:") and enc["ip"].startswith("bb416r1:"))
        self.assertEqual(self.c.decrypt_fields(enc), {**olay, "sure_ms": 42})

        line = f'2026-10-13 web-1 kullanici={enc["kullanici"]} ip={enc["ip"]} durum=ok'
        self.assertEqual(self.c.decrypt_line(line),
                         "2026-10-13 web-1 kullanici=ayşe@ornek.org ip=203.0.113.7 durum=ok")
        broken = line.replace(enc["ip"], enc["ip"][:-3])
        self.assertIn("[ÇÖZÜLEMEDİ]", self.c.decrypt_line(broken))
        with self.assertRaises(bicbic416.DecryptionError):
            self.c.decrypt_line(broken, on_error=None)

    def test_hash(self):
        self.assertEqual(bicbic416.hash_hex("abc")[:16], "67a30eca09035424")
        self.assertEqual(len(bicbic416.hash(b"")), 52)


class TestLogging(unittest.TestCase):
    def setUp(self):
        self.c = bicbic416.RecordCipher(bicbic416.generate_key())
        self.stream = io.StringIO()
        self.logger = logging.getLogger(f"bicbic416-test-{id(self)}")
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)

    def test_encrypting_formatter(self):
        h = logging.StreamHandler(self.stream)
        h.setFormatter(bicbic416.EncryptingFormatter(self.c, "%(levelname)s %(name)s %(message)s"))
        self.logger.addHandler(h)
        self.logger.warning("başarısız giriş: kullanici=%s", "ayşe")
        try:
            1 / 0
        except ZeroDivisionError:
            self.logger.exception("beklenmeyen hata")
        lines = self.stream.getvalue().splitlines()
        self.assertTrue(lines[0].startswith(f"WARNING {self.logger.name} bb416r1:"))
        self.assertNotIn("ayşe", self.stream.getvalue())
        self.assertNotIn("ZeroDivisionError", self.stream.getvalue())
        self.assertEqual(self.c.decrypt_line(lines[0]),
                         f"WARNING {self.logger.name} başarısız giriş: kullanici=ayşe")
        second = self.c.decrypt(lines[1].split(" ", 2)[2])
        self.assertTrue(second.startswith("beklenmeyen hata\nTraceback"))
        self.assertIn("ZeroDivisionError", second)

    def test_field_filter(self):
        h = logging.StreamHandler(self.stream)
        h.setFormatter(logging.Formatter("%(message)s kullanici=%(kullanici)s ip=%(ip)s"))
        self.logger.addHandler(h)
        self.logger.addFilter(bicbic416.FieldEncryptingFilter(self.c, ["kullanici", "ip"]))
        self.logger.info("giris", extra={"kullanici": "ayşe", "ip": "203.0.113.7"})
        out = self.stream.getvalue().strip()
        self.assertTrue(out.startswith("giris kullanici=bb416r1:"))
        self.assertEqual(self.c.decrypt_line(out), "giris kullanici=ayşe ip=203.0.113.7")


class TestInterop(unittest.TestCase):
    def run_py(self, args, stdin, env):
        return subprocess.run([sys.executable, "-m", "bicbic416", *args], input=stdin.encode("utf-8"),
                              capture_output=True, env=env, cwd=os.path.join(ROOT, "python"))

    def setUp(self):
        self.key = bicbic416.generate_key()
        self.env = {**os.environ, "BICBIC_ANAHTAR": self.key, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
        self.text = "giriş başarılı kullanici=ayşe\nikinci satır\n"

    def test_python_cli(self):
        enc = self.run_py(["log-sifrele"], self.text, self.env)
        self.assertEqual(enc.returncode, 0, enc.stderr)
        dec = self.run_py(["log-coz"], enc.stdout.decode("utf-8"), self.env)
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.decode("utf-8").replace("\r\n", "\n"), self.text)

    def test_c_cli(self):
        if not os.path.isfile(CLI):
            self.skipTest("C aracı derlenmemiş (make tool)")
        c = bicbic416.RecordCipher(self.key)
        py_tokens = "".join(c.encrypt(l) + "\n" for l in self.text.splitlines())
        dec = subprocess.run([CLI, "log-coz"], input=py_tokens.encode("utf-8"), capture_output=True, env=self.env)
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(dec.stdout.decode("utf-8").replace("\r\n", "\n"), self.text)

        enc = subprocess.run([CLI, "log-sifrele"], input=self.text.encode("utf-8"), capture_output=True,
                             env=self.env)
        self.assertEqual(enc.returncode, 0, enc.stderr)
        got = [c.decrypt(l) for l in enc.stdout.decode("utf-8").splitlines()]
        self.assertEqual(got, self.text.splitlines())


if __name__ == "__main__":
    unittest.main(verbosity=2)
