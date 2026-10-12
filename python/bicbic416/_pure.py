"""
Saf Python arka ucu: BicBic416, BicBic-Hash, ChaCha20 ve kayıt biçimi (SPEC.md §14).

Yalnızca standart kütüphaneyi kullanır; her Python 3.9+ ortamında çalışır. C kütüphanesi
bulunursa paket otomatik olarak onu kullanır (bkz. _native.py); bu modül hem yedek hem de
testlerde karşılaştırma için referanstır. Tur fonksiyonu hız için açılmış (unrolled) hâlde
yazılmıştır; okunur hâli ref/bicbic416_ref.py dosyasındadır.
"""
import hashlib
import hmac
import os
import struct

M = 0xFFFFFFFF
ROT = (3, 16, 29, 10, 23, 4, 17, 30, 11, 24, 5, 18, 31)
KS_MUL = 0x2545F491
KS_GOLD = 0x9E3779B9
BLOCK = 52
KEY_BYTES = 52


def _rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & M


def _bitrev(x):
    x = ((x >> 1) & 0x55555555) | ((x & 0x55555555) << 1)
    x = ((x >> 2) & 0x33333333) | ((x & 0x33333333) << 2)
    x = ((x >> 4) & 0x0F0F0F0F) | ((x & 0x0F0F0F0F) << 4)
    x = ((x >> 8) & 0x00FF00FF) | ((x & 0x00FF00FF) << 8)
    return ((x >> 16) | (x << 16)) & M


# ---- Anahtar planı (SPEC.md §6) ---------------------------------------------

def _mix456(s):
    for i in range(6):
        j = 12 - i
        s[j] = (s[j] + s[i]) & M
        s[i] ^= _rotl(s[j], 7)
    s[6] = (s[6] + sum(s[i] for i in range(13) if i != 6)) & M
    for i in range(13):
        if i != 6:
            s[i] ^= _rotl(s[6], i + 1)
    for i in range(6):
        s[i], s[12 - i] = s[12 - i], s[i]
    s[6] = _bitrev(s[6])


def _ks_mix(k):
    for i in range(13):
        x = (k[i] * KS_MUL) & M
        x ^= x >> 16
        k[i] = _rotl(x, ROT[i])
    _mix456(k)


def _schedule(key, rounds):
    if len(key) != KEY_BYTES:
        raise ValueError("BicBic416 anahtarı 52 bayt olmalı")
    if not 1 <= rounds <= 32:
        raise ValueError("tur sayısı 1..32 olmalı")
    k = list(struct.unpack("<13I", key))
    n = 0

    def next_key():
        nonlocal n
        k[0] ^= ((n + 1) * KS_GOLD) & M
        _ks_mix(k)
        _ks_mix(k)
        n += 1
        return tuple(k)

    rk, mk = [], []
    for _ in range(rounds):
        rk.append(next_key())
        mk.append(tuple(w | 1 for w in next_key()))
    rk.append(next_key())
    return rk, mk


def _encrypt_words(rk, mk, rounds, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12):
    """Tek bloğu şifreler (SPEC.md §4). Okunur hâli için ref/bicbic416_ref.py."""
    M = 0xFFFFFFFF
    for r in range(rounds):
        k = rk[r]
        m = mk[r]
        # Adım 1–3: anahtar ekleme, çarpma + x ^= x >> 16, satır döndürme
        x = ((s0 ^ k[0]) * m[0]) & M; x ^= x >> 16; s0 = (((x) << 3) | ((x) >> 29)) & M
        x = ((s1 ^ k[1]) * m[1]) & M; x ^= x >> 16; s1 = (((x) << 16) | ((x) >> 16)) & M
        x = ((s2 ^ k[2]) * m[2]) & M; x ^= x >> 16; s2 = (((x) << 29) | ((x) >> 3)) & M
        x = ((s3 ^ k[3]) * m[3]) & M; x ^= x >> 16; s3 = (((x) << 10) | ((x) >> 22)) & M
        x = ((s4 ^ k[4]) * m[4]) & M; x ^= x >> 16; s4 = (((x) << 23) | ((x) >> 9)) & M
        x = ((s5 ^ k[5]) * m[5]) & M; x ^= x >> 16; s5 = (((x) << 4) | ((x) >> 28)) & M
        x = ((s6 ^ k[6]) * m[6]) & M; x ^= x >> 16; s6 = (((x) << 17) | ((x) >> 15)) & M
        x = ((s7 ^ k[7]) * m[7]) & M; x ^= x >> 16; s7 = (((x) << 30) | ((x) >> 2)) & M
        x = ((s8 ^ k[8]) * m[8]) & M; x ^= x >> 16; s8 = (((x) << 11) | ((x) >> 21)) & M
        x = ((s9 ^ k[9]) * m[9]) & M; x ^= x >> 16; s9 = (((x) << 24) | ((x) >> 8)) & M
        x = ((s10 ^ k[10]) * m[10]) & M; x ^= x >> 16; s10 = (((x) << 5) | ((x) >> 27)) & M
        x = ((s11 ^ k[11]) * m[11]) & M; x ^= x >> 16; s11 = (((x) << 18) | ((x) >> 14)) & M
        x = ((s12 ^ k[12]) * m[12]) & M; x ^= x >> 16; s12 = (((x) << 31) | ((x) >> 1)) & M
        # Adım 4: sarmal çift karıştırma
        s12 = (s12 + s0) & M; s0 ^= (((s12) << 7) | ((s12) >> 25)) & M
        s11 = (s11 + s1) & M; s1 ^= (((s11) << 7) | ((s11) >> 25)) & M
        s10 = (s10 + s2) & M; s2 ^= (((s10) << 7) | ((s10) >> 25)) & M
        s9 = (s9 + s3) & M; s3 ^= (((s9) << 7) | ((s9) >> 25)) & M
        s8 = (s8 + s4) & M; s4 ^= (((s8) << 7) | ((s8) >> 25)) & M
        s7 = (s7 + s5) & M; s5 ^= (((s7) << 7) | ((s7) >> 25)) & M
        # Adım 5: merkez kelime topla ve dağıt
        s6 = (s6 + s0 + s1 + s2 + s3 + s4 + s5 + s7 + s8 + s9 + s10 + s11 + s12) & M
        s0 ^= (((s6) << 1) | ((s6) >> 31)) & M
        s1 ^= (((s6) << 2) | ((s6) >> 30)) & M
        s2 ^= (((s6) << 3) | ((s6) >> 29)) & M
        s3 ^= (((s6) << 4) | ((s6) >> 28)) & M
        s4 ^= (((s6) << 5) | ((s6) >> 27)) & M
        s5 ^= (((s6) << 6) | ((s6) >> 26)) & M
        s7 ^= (((s6) << 8) | ((s6) >> 24)) & M
        s8 ^= (((s6) << 9) | ((s6) >> 23)) & M
        s9 ^= (((s6) << 10) | ((s6) >> 22)) & M
        s10 ^= (((s6) << 11) | ((s6) >> 21)) & M
        s11 ^= (((s6) << 12) | ((s6) >> 20)) & M
        s12 ^= (((s6) << 13) | ((s6) >> 19)) & M
        # Adım 6: sarmal takas ve merkez kelimeyi bit-ters çevirme
        s0, s1, s2, s3, s4, s5, s7, s8, s9, s10, s11, s12 = s12, s11, s10, s9, s8, s7, s5, s4, s3, s2, s1, s0
        s6 = _bitrev(s6)
    k = rk[rounds]
    return (s0 ^ k[0], s1 ^ k[1], s2 ^ k[2], s3 ^ k[3], s4 ^ k[4], s5 ^ k[5], s6 ^ k[6],
            s7 ^ k[7], s8 ^ k[8], s9 ^ k[9], s10 ^ k[10], s11 ^ k[11], s12 ^ k[12])


class Cipher:
    """BicBic416 blok şifresi (yalnızca şifreleme yönü; CTR ve hash için yeterli)."""

    __slots__ = ("rounds", "rk", "mk")

    def __init__(self, key, rounds=16):
        self.rounds = rounds
        self.rk, self.mk = _schedule(bytes(key), rounds)

    def encrypt_block(self, block):
        return struct.pack("<13I", *_encrypt_words(self.rk, self.mk, self.rounds,
                                                  *struct.unpack("<13I", block)))

    def ctr_xor(self, nonce44, data, counter=0):
        """CTR: sayaç bloğu = nonce (44 bayt) || sayaç (8 bayt, little-endian)."""
        out = bytearray(data)
        nw = struct.unpack("<11I", nonce44)
        rk, mk, R = self.rk, self.mk, self.rounds
        for off in range(0, len(out), BLOCK):
            c = counter + off // BLOCK
            ks = struct.pack("<13I", *_encrypt_words(rk, mk, R, *nw, c & M, (c >> 32) & M))
            chunk = out[off:off + BLOCK]
            out[off:off + BLOCK] = (int.from_bytes(chunk, "little") ^
                                    int.from_bytes(ks[:len(chunk)], "little")).to_bytes(len(chunk), "little")
        return bytes(out)


# ---- BicBic-Hash (SPEC.md §12) ---------------------------------------------

HASH_BYTES = 52
_HASH_FINAL = b"BicBic-Hash/son".ljust(BLOCK, b"\0")
_HASH_IV = None


def _hash_compress(h, m):
    e = Cipher(h, 16).encrypt_block(m)
    return (int.from_bytes(e, "little") ^ int.from_bytes(m, "little") ^
            int.from_bytes(h, "little")).to_bytes(BLOCK, "little")


def bb_hash(data):
    """416 bitlik (52 bayt) BicBic-Hash özeti."""
    global _HASH_IV
    if _HASH_IV is None:
        _HASH_IV = Cipher(bytes(KEY_BYTES), 16).encrypt_block(bytes(BLOCK))
    data = bytes(data)
    padded = data + b"\x80" + b"\0" * ((-len(data) - 9) % BLOCK) + struct.pack("<Q", (8 * len(data)) & (2**64 - 1))
    h = _HASH_IV
    for off in range(0, len(padded), BLOCK):
        h = _hash_compress(h, padded[off:off + BLOCK])
    return _hash_compress(h, _HASH_FINAL)


# ---- ChaCha20 (RFC 8439) ------------------------------------------------------

def _chacha_block(st):
    x = list(st)
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            xa = (x[a] + x[b]) & M; xd = x[d] ^ xa; xd = ((xd << 16) | (xd >> 16)) & M
            xc = (x[c] + xd) & M; xb = x[b] ^ xc; xb = ((xb << 12) | (xb >> 20)) & M
            xa = (xa + xb) & M; xd ^= xa; xd = ((xd << 8) | (xd >> 24)) & M
            xc = (xc + xd) & M; xb ^= xc; xb = ((xb << 7) | (xb >> 25)) & M
            x[a], x[b], x[c], x[d] = xa, xb, xc, xd
    return struct.pack("<16I", *((x[i] + st[i]) & M for i in range(16)))


def chacha20_xor(key, nonce, counter, data):
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, *struct.unpack("<8I", key),
          counter, *struct.unpack("<3I", nonce)]
    out = bytearray(data)
    for off in range(0, len(out), 64):
        ks = _chacha_block(st)
        chunk = out[off:off + 64]
        out[off:off + 64] = (int.from_bytes(chunk, "little") ^
                             int.from_bytes(ks[:len(chunk)], "little")).to_bytes(len(chunk), "little")
        st[12] = (st[12] + 1) & M
    return bytes(out)


# ---- HKDF-SHA256 (RFC 5869) ---------------------------------------------------

def hkdf_sha256(ikm, info, length, salt=b""):
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


# ---- Kayıt biçimi (SPEC.md §14) ---------------------------------------------

RECORD_FORMAT = 0xB3
KID_BYTES = 4
NONCE_BYTES = 16
TAG_BYTES = 16
HEADER_BYTES = 1 + KID_BYTES + NONCE_BYTES
OVERHEAD = HEADER_BYTES + TAG_BYTES
_KDF_INFO = b"BicBic416 kayit v1"


class RecordKey:
    """Ana anahtardan türetilmiş alt anahtarlar (K_bb, K_mac, K_cc, kimlik)."""

    __slots__ = ("bb", "mac_key", "chacha_key", "kid")

    def __init__(self, master):
        if len(master) != 32:
            raise ValueError("ana anahtar 32 bayt olmalı")
        dk = hkdf_sha256(bytes(master), _KDF_INFO, 120)
        self.bb = Cipher(dk[:52], 16)
        self.mac_key = dk[52:84]
        self.chacha_key = dk[84:116]
        self.kid = dk[116:120]

    def _layers(self, nonce, data):
        ct = self.bb.ctr_xor(nonce + bytes(28), data)
        rk = hmac.new(self.chacha_key, nonce, hashlib.sha256).digest()
        return chacha20_xor(rk, bytes(12), 0, ct)

    def _tag(self, aad, rec):
        return hmac.new(self.mac_key, struct.pack("<Q", len(aad)) + aad + rec, hashlib.sha256).digest()[:TAG_BYTES]

    def encrypt(self, msg, aad=b"", nonce=None):
        nonce = os.urandom(NONCE_BYTES) if nonce is None else bytes(nonce)
        head = bytes([RECORD_FORMAT]) + self.kid + nonce
        rec = head + self._layers(nonce, bytes(msg))
        return rec + self._tag(bytes(aad), rec)

    def decrypt(self, rec, aad=b""):
        """Döndürür: (hata_kodu, düz_metin). Hata kodları C ile aynı (BBR_*)."""
        rec = bytes(rec)
        if len(rec) < OVERHEAD or rec[0] != RECORD_FORMAT:
            return 2, None
        if rec[1:1 + KID_BYTES] != self.kid:
            return 3, None
        body, tag = rec[:-TAG_BYTES], rec[-TAG_BYTES:]
        if not hmac.compare_digest(self._tag(bytes(aad), body), tag):
            return 4, None
        return 0, self._layers(rec[1 + KID_BYTES:HEADER_BYTES], body[HEADER_BYTES:])
