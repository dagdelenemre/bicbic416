"""
Komut satırı: python -m bicbic416 <komut>

  anahtar-uret          yeni ana anahtar üretir
  log-sifrele [-k DOSYA] standart girdinin her satırını bir kayda çevirir
  log-coz [-k DOSYA]     satırlardaki tüm kayıtları yerinde açar
  hash [DOSYA...]        BicBic-Hash (dosya yoksa standart girdi)

Anahtarlar BICBIC_ANAHTAR ortam değişkeninden (virgülle ayrılmış) veya -k ile verilen
dosyadan (her satırda bir anahtar) okunur. C aracı `bicbic` ile birebir uyumludur.
"""
import sys

from . import TOKEN_RE, DecryptionError, RecordCipher, backend, generate_key, hash_hex


def _cipher(args):
    if len(args) == 2 and args[0] == "-k":
        with open(args[1], encoding="utf-8") as f:
            keys = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
        return RecordCipher(keys)
    if args:
        raise SystemExit("kullanım: python -m bicbic416 log-sifrele|log-coz [-k ANAHTAR_DOSYASI]")
    try:
        return RecordCipher.from_env()
    except ValueError as e:
        raise SystemExit(f"hata: {e}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        print(f"\narka uç: {backend}", file=sys.stderr)
        return 1
    cmd, args = argv[0], argv[1:]
    if cmd == "anahtar-uret":
        key = generate_key()
        print(key)
        print(f"anahtar kimliği: {RecordCipher(key).key_id} — gizli tutun; kaybederseniz loglar açılamaz.",
              file=sys.stderr)
        return 0
    if cmd == "log-sifrele":
        c = _cipher(args)
        for line in sys.stdin:
            print(c.encrypt(line.rstrip("\r\n")), flush=False)
        return 0
    if cmd == "log-coz":
        c = _cipher(args)
        failed = 0

        def repl(m):
            nonlocal failed
            try:
                return c.decrypt(m.group(0))
            except DecryptionError as e:
                failed += 1
                return f"[ÇÖZÜLEMEDİ: {e}]"

        for line in sys.stdin:
            print(TOKEN_RE.sub(repl, line.rstrip("\r\n")))
        if failed:
            print(f"uyarı: {failed} kayıt çözülemedi", file=sys.stderr)
            return 2
        return 0
    if cmd == "hash":
        if not args:
            print(f"{hash_hex(sys.stdin.buffer.read())}  -")
        for path in args:
            with open(path, "rb") as f:
                print(f"{hash_hex(f.read())}  {path}")
        return 0
    print(f"bilinmeyen komut: {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
