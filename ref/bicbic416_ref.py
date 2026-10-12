"""
BicBic416 bağımsız Python referans uygulaması.

Yalnızca SPEC.md okunarak, C kodundan bağımsız yazılmıştır; amacı C uygulamasının
spesifikasyonu doğru uyguladığını çapraz kontrol etmektir. Yavaştır, gerçek
kullanım için değildir.

Kullanım:
    python ref/bicbic416_ref.py            # tests/test_kat.c'deki tüm vektörleri doğrular
"""
import re
import sys
from pathlib import Path

M32 = 0xFFFFFFFF
ROT = [(13 * i + 3) % 32 for i in range(13)]
KS_MUL = 0x2545F491
KS_GOLD = 0x9E3779B9


def rotl(x, r):
    r %= 32
    return ((x << r) | (x >> (32 - r))) & M32 if r else x


def rotr(x, r):
    return rotl(x, (32 - r) % 32)


def bitrev(x):
    return int(f"{x:032b}"[::-1], 2)


def mulinv(a):
    return pow(a, -1, 1 << 32)


def load(b):
    return [int.from_bytes(b[4 * i:4 * i + 4], "little") for i in range(13)]


def store(S):
    return b"".join(w.to_bytes(4, "little") for w in S)


# ---- Tur adımları (SPEC.md §4) --------------------------------------------

def step4(S):
    for i in range(6):
        j = 12 - i
        S[j] = (S[j] + S[i]) & M32
        S[i] ^= rotl(S[j], 7)


def step5(S):
    t = sum(S[i] for i in range(13) if i != 6) & M32
    S[6] = (S[6] + t) & M32
    for i in range(13):
        if i != 6:
            S[i] ^= rotl(S[6], i + 1)


def step6(S):
    for i in range(6):
        S[i], S[12 - i] = S[12 - i], S[i]
    S[6] = bitrev(S[6])


def inv_step4(S):
    for i in range(6):
        j = 12 - i
        S[i] ^= rotl(S[j], 7)
        S[j] = (S[j] - S[i]) & M32


def inv_step5(S):
    for i in range(13):
        if i != 6:
            S[i] ^= rotl(S[6], i + 1)
    t = sum(S[i] for i in range(13) if i != 6) & M32
    S[6] = (S[6] - t) & M32


# ---- Anahtar planı (SPEC.md §6) -------------------------------------------

def ks_mix(K):
    for i in range(13):
        K[i] = (K[i] * KS_MUL) & M32
        K[i] ^= K[i] >> 16
        K[i] = rotl(K[i], ROT[i])
    step4(K)
    step5(K)
    step6(K)


def schedule(key, R):
    K = load(key)
    n = 0
    out = []

    def uret():
        nonlocal n
        K[0] ^= ((n + 1) * KS_GOLD) & M32
        ks_mix(K)
        ks_mix(K)
        n += 1
        return list(K)

    RK, MK = [], []
    for _ in range(R):
        RK.append(uret())
        MK.append([w | 1 for w in uret()])
    RK.append(uret())
    return RK, MK


# ---- Blok şifre -----------------------------------------------------------

def encrypt(key, block, R, sched=None):
    RK, MK = sched or schedule(key, R)
    S = load(block)
    for r in range(R):
        for i in range(13):
            S[i] ^= RK[r][i]
        for i in range(13):
            S[i] = (S[i] * MK[r][i]) & M32
            S[i] ^= S[i] >> 16
        for i in range(13):
            S[i] = rotl(S[i], ROT[i])
        step4(S)
        step5(S)
        step6(S)
    for i in range(13):
        S[i] ^= RK[R][i]
    return store(S)


def decrypt(key, block, R):
    RK, MK = schedule(key, R)
    S = load(block)
    for i in range(13):
        S[i] ^= RK[R][i]
    for r in reversed(range(R)):
        step6(S)
        inv_step5(S)
        inv_step4(S)
        for i in range(13):
            S[i] = rotr(S[i], ROT[i])
        for i in range(13):
            S[i] ^= S[i] >> 16
            S[i] = (S[i] * mulinv(MK[r][i])) & M32
        for i in range(13):
            S[i] ^= RK[r][i]
    return store(S)


def ctr(key, nonce, counter, data, R):
    out = bytearray()
    sched = schedule(key, R)
    for off in range(0, len(data), 52):
        ks = encrypt(key, nonce + counter.to_bytes(8, "little"), R, sched)
        out += bytes(a ^ b for a, b in zip(data[off:off + 52], ks))
        counter += 1
    return bytes(out)


# ---- tests/test_kat.c ile çapraz kontrol ----------------------------------

def pattern(pat):
    key = bytes(0 if pat == 0 else i if pat == 1 else 0xFF for i in range(52))
    pt = bytes(0 if pat == 0 else 0x80 + i if pat == 1 else 0x80 for i in range(52))
    return key, pt


def main():
    src = (Path(__file__).resolve().parent.parent / "tests" / "test_kat.c").read_text(encoding="utf-8")
    fails = 0
    checks = 0

    for pat, R, ct in re.findall(r'\{\s*(\d),\s*(\d+),\s*"([0-9a-f]{104})"\s*\}', src):
        key, pt = pattern(int(pat))
        got = encrypt(key, pt, int(R))
        checks += 1
        if got.hex() != ct or decrypt(key, got, int(R)) != pt:
            fails += 1
            print(f"HATA: desen {pat} R {R}\n  C  : {ct}\n  Py : {got.hex()}")

    def joined(name):
        m = re.search(r"static void " + name + r"\(void\).*?hex_eq\([^,]+,[^,]+,\s*((?:\"[0-9a-f]+\"\s*)+)\)", src, re.S)
        return "".join(re.findall(r'"([0-9a-f]+)"', m.group(1)))

    b = bytes(52)
    key0 = bytes(52)
    sched = schedule(key0, 16)  # zincir için anahtar planını bir kez hesapla
    for _ in range(10000):
        b = encrypt(key0, b, 16, sched)
    checks += 1
    if b.hex() != joined("test_chain"):
        fails += 1
        print("HATA: zincir")

    key = bytes(range(52))
    nonce = bytes(0xA0 + i for i in range(44))
    got = ctr(key, nonce, 1, bytes(range(100)), 16)
    checks += 1
    if got.hex() != joined("test_ctr"):
        fails += 1
        print("HATA: CTR")

    print(f"Python referansı: {checks - fails}/{checks} KAT vektörü C uygulamasıyla aynı")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
