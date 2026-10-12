/*
 * bicbic — BicBic416 ile parolalı dosya şifreleme ve BicBic-Hash aracı.
 *
 *   bicbic sifrele [-2] [-r TUR] [-i YINELEME] [-z] <girdi> <cikti>
 *   bicbic coz [-z] <girdi> <cikti>
 *   bicbic bilgi <dosya>
 *   bicbic hash <dosya>...
 *   bicbic anahtar-uret
 *   bicbic log-sifrele [-k ANAHTAR_DOSYASI]   < düz satırlar   > kayıtlar
 *   bicbic log-coz [-k ANAHTAR_DOSYASI]       < kayıtlar       > düz satırlar
 *
 * Parola klavyeden (ekranda görünmeden) sorulur. Otomasyon için BICBIC_PAROLA
 * ortam değişkeni de kullanılabilir (paylaşılan makinelerde önerilmez).
 *
 * UYARI: BicBic416 eğitim amaçlı, kriptanalizden geçmemiş bir şifredir.
 * Gerçekten gizli veriler için kullanmayın.
 */
#if !defined(_WIN32)
#  define _POSIX_C_SOURCE 200809L /* termios, isatty: katı C11 modunda görünür olsun */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bicbic416.h"
#include "bicbic_file.h"
#include "bicbic_record.h"
#include "sha256.h"

#define PW_MAX 1024

#if defined(_WIN32)
#  include <conio.h>
#  include <fcntl.h>
#  include <io.h>
#  include <windows.h>

/* Konsolda yankısız okur; UTF-8'e çevirir (Türkçe karakterli parolalar için). */
static int read_password(const char *prompt, char *out, size_t cap)
{
    fputs(prompt, stderr);
    fflush(stderr);
    if (!_isatty(_fileno(stdin))) {
        if (!fgets(out, (int)cap, stdin)) return -1;
        out[strcspn(out, "\r\n")] = 0;
        return 0;
    }
    wchar_t w[PW_MAX];
    size_t n = 0;
    for (;;) {
        wint_t c = _getwch();
        if (c == L'\r' || c == L'\n') break;
        if (c == 3) { fputs("\n", stderr); exit(130); } /* Ctrl+C */
        if (c == 8) { if (n) n--; continue; }           /* geri sil */
        if (c == 0 || c == 0xE0) { _getwch(); continue; } /* ok/işlev tuşları */
        if (n + 1 < PW_MAX) w[n++] = (wchar_t)c;
    }
    w[n] = 0;
    fputs("\n", stderr);
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
    SecureZeroMemory(w, sizeof w);
    return len > 0 ? 0 : -1;
}
#else
#  include <termios.h>
#  include <unistd.h>

static int read_password(const char *prompt, char *out, size_t cap)
{
    struct termios old, quiet;
    int tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old) == 0;
    fputs(prompt, stderr);
    fflush(stderr);
    if (tty) {
        quiet = old;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }
    char *r = fgets(out, (int)cap, stdin);
    if (tty) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        fputs("\n", stderr);
    }
    if (!r) return -1;
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}
#endif

static void usage(void)
{
    fputs(
        "BicBic416 dosya şifreleme aracı (eğitim amaçlı — gerçek gizli veriler için kullanmayın)\n"
        "\n"
        "Kullanım:\n"
        "  bicbic sifrele [-2] [-r TUR] [-i YINELEME] [-z] <girdi> <cikti>\n"
        "  bicbic coz [-z] <girdi> <cikti>\n"
        "  bicbic bilgi <dosya>\n"
        "  bicbic hash <dosya>...     (dosya yerine - : standart girdi)\n"
        "\n"
        "Seçenekler:\n"
        "  -2           iki katman: BicBic416 + ChaCha20 (biri kırılsa diğeri korur)\n"
        "  -r TUR       tur sayısı, 1..32 (varsayılan 16)\n"
        "  -i YINELEME  parola türetme yineleme sayısı, 1000'in katı (varsayılan 600000;\n"
        "               büyüdükçe parola tahmini zorlaşır, açılış yavaşlar)\n"
        "  -z           çıktı dosyası varsa üzerine yaz\n"
        "\n"
        "Parola ekranda görünmeden sorulur. Betiklerde BICBIC_PAROLA ortam değişkeni\n"
        "kullanılabilir. Dosya değiştirilirse veya parola yanlışsa çözme reddedilir.\n"
        "Çözme, katman sayısını ve ayarları dosyanın kendisinden okur.\n",
        stderr);
}

/* Parola her zaman UTF-8 bayt dizisi olarak türetmeye girer (web sayfasıyla ve
 * klavyeden girilen parolayla aynı anahtarı üretmek için). Windows'ta getenv
 * ANSI kod sayfası (ör. cp1254) döndürdüğünden geniş karakterle okunup çevrilir. */
static int env_password(char *pw)
{
#if defined(_WIN32)
    const wchar_t *w = _wgetenv(L"BICBIC_PAROLA");
    if (!w) return 1;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, pw, PW_MAX, NULL, NULL);
    return n > 0 ? 0 : -1;
#else
    const char *env = getenv("BICBIC_PAROLA");
    if (!env) return 1;
    if (strlen(env) >= PW_MAX) return -1;
    strcpy(pw, env);
    return 0;
#endif
}

static int get_password(char *pw, int confirm)
{
    int e = env_password(pw);
    if (e <= 0)
        return e;
    if (read_password("Parola: ", pw, PW_MAX) != 0) return -1;
    if (pw[0] == 0) {
        fputs("hata: boş parola kabul edilmiyor\n", stderr);
        return -1;
    }
    if (confirm) {
        char again[PW_MAX];
        int ok = read_password("Parola (tekrar): ", again, sizeof again) == 0 &&
                 strcmp(pw, again) == 0;
        wipe(again, sizeof again);
        if (!ok) {
            fputs("hata: parolalar eşleşmiyor\n", stderr);
            return -1;
        }
        if (strlen(pw) < 8)
            fputs("uyarı: 8 karakterden kısa parolalar kolay tahmin edilebilir\n", stderr);
    }
    return 0;
}

/* sha256sum gibi: "<104 onaltılık karakter>  <ad>". "-" standart girdidir. */
static int hash_files(int argc, char **argv)
{
    int status = 0;
    static uint8_t buf[1 << 16];
    for (int i = 0; i < argc; i++) {
        int is_stdin = strcmp(argv[i], "-") == 0;
        FILE *f = is_stdin ? stdin : fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "hata: %s okunamadı\n", argv[i]);
            status = 1;
            continue;
        }
#if defined(_WIN32)
        if (is_stdin) _setmode(_fileno(stdin), _O_BINARY);
#endif
        bb416_hash_ctx c;
        uint8_t out[BB416_HASH_BYTES];
        size_t n;
        bb416_hash_init(&c);
        while ((n = fread(buf, 1, sizeof buf, f)) > 0)
            bb416_hash_update(&c, buf, n);
        int err = ferror(f);
        if (!is_stdin) fclose(f);
        if (err) {
            fprintf(stderr, "hata: %s okunurken hata oluştu\n", argv[i]);
            status = 1;
            continue;
        }
        bb416_hash_final(&c, out);
        for (int b = 0; b < BB416_HASH_BYTES; b++) printf("%02x", out[b]);
        printf("  %s\n", argv[i]);
    }
    return status;
}

/* ---- Log kayıtları (SPEC.md §14) ------------------------------------------
 *
 * Anahtarlar BICBIC_ANAHTAR ortam değişkeninden (virgülle ayrılmış, ilki şifreleme
 * için kullanılır) veya -k ile verilen dosyadan (her satırda bir anahtar) okunur.
 * Birden fazla anahtar, anahtar değiştirildikten sonra eski logları açmak içindir.
 */
#define MAX_KEYS 16

typedef struct {
    bbr_key keys[MAX_KEYS];
    int count;
} keyring;

static int keyring_add(keyring *r, const char *text)
{
    uint8_t master[BBR_KEY_BYTES];
    if (r->count >= MAX_KEYS || bbr_key_from_text(text, master) != BBR_OK)
        return -1;
    bbr_key_init(&r->keys[r->count++], master);
    wipe(master, sizeof master);
    return 0;
}

/* "a, b ,c" veya satır satır listeyi ayrıştırır; boşluklar ve # yorum satırları atlanır. */
static int keyring_parse(keyring *r, char *list, const char *seps)
{
    for (char *tok = strtok(list, seps); tok; tok = strtok(NULL, seps)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        size_t n = strlen(tok);
        while (n && (tok[n - 1] == ' ' || tok[n - 1] == '\t' || tok[n - 1] == '\r')) tok[--n] = 0;
        if (n == 0 || tok[0] == '#') continue;
        if (keyring_add(r, tok) != 0) {
            fputs("hata: geçersiz anahtar (\"bb416k1:\" ile başlamalı; üretmek için: bicbic anahtar-uret)\n",
                  stderr);
            return -1;
        }
    }
    return 0;
}

static int keyring_load(keyring *r, const char *key_file)
{
    r->count = 0;
    if (key_file) {
        FILE *f = fopen(key_file, "rb");
        if (!f) { fprintf(stderr, "hata: %s okunamadı\n", key_file); return -1; }
        char buf[4096];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = 0;
        int rc = keyring_parse(r, buf, "\n");
        wipe(buf, sizeof buf);
        if (rc) return -1;
    } else {
        const char *env = getenv("BICBIC_ANAHTAR");
        if (!env) {
            fputs("hata: anahtar yok. BICBIC_ANAHTAR ortam değişkenini ayarlayın veya -k <dosya> verin\n"
                  "      (yeni anahtar: bicbic anahtar-uret)\n", stderr);
            return -1;
        }
        char *copy = malloc(strlen(env) + 1);
        if (!copy) return -1;
        strcpy(copy, env);
        int rc = keyring_parse(r, copy, ",");
        wipe(copy, strlen(env));
        free(copy);
        if (rc) return -1;
    }
    if (r->count == 0) { fputs("hata: anahtar listesi boş\n", stderr); return -1; }
    return 0;
}

static void keyring_wipe(keyring *r)
{
    for (int i = 0; i < r->count; i++) bbr_key_wipe(&r->keys[i]);
    r->count = 0;
}

/* Satır okur (sonundaki \n ve \r atılır). Uzunluk sınırı yok. NULL = dosya sonu. */
static char *read_line(FILE *f, size_t *len)
{
    size_t cap = 256, n = 0;
    char *s = malloc(cap);
    int c;
    if (!s) return NULL;
    while ((c = fgetc(f)) != EOF && c != '\n') {
        if (n + 1 >= cap) {
            char *t = realloc(s, cap *= 2);
            if (!t) { free(s); return NULL; }
            s = t;
        }
        s[n++] = (char)c;
    }
    if (c == EOF && n == 0) { free(s); return NULL; }
    if (n && s[n - 1] == '\r') n--;
    s[n] = 0;
    *len = n;
    return s;
}

static int is_b64url(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

/* Standart girdinin her satırını bir kayda çevirir. */
static int log_encrypt(const char *key_file)
{
    keyring r;
    if (keyring_load(&r, key_file)) return 1;
    size_t len;
    char *line;
    int status = 0;
    while ((line = read_line(stdin, &len)) != NULL) {
        size_t cap = bbr_text_len(len);
        char *out = malloc(cap);
        if (!out || bbr_encrypt_text(&r.keys[0], (const uint8_t *)line, len, NULL, 0, out, cap) != BBR_OK) {
            fputs("hata: kayıt şifrelenemedi\n", stderr);
            status = 1;
        } else {
            puts(out);
        }
        free(out);
        wipe(line, len);
        free(line);
    }
    fflush(stdout);
    keyring_wipe(&r);
    return status;
}

/* Her satırdaki tüm "bb416r1:..." parçalarını yerinde çözer; gerisini olduğu gibi bırakır.
 * Böylece yalnızca bazı alanları şifrelenmiş log satırları da okunabilir. */
static int log_decrypt(const char *key_file)
{
    keyring r;
    if (keyring_load(&r, key_file)) return 1;
    const size_t P = sizeof BBR_TEXT_PREFIX - 1;
    size_t len;
    char *line;
    long failed = 0;
    while ((line = read_line(stdin, &len)) != NULL) {
        size_t i = 0;
        while (i < len) {
            char *hit = strstr(line + i, BBR_TEXT_PREFIX);
            if (!hit) { fputs(line + i, stdout); break; }
            size_t start = (size_t)(hit - line), end = start + P;
            while (end < len && is_b64url(line[end])) end++;
            fwrite(line + i, 1, start - i, stdout);

            int rc = BBR_ERR_KEY;
            uint8_t kid[BBR_KID_BYTES];
            size_t tlen = end - start, cap = tlen, dlen = 0;
            uint8_t *dec = malloc(cap + 1);
            if (dec && bbr_text_kid(hit, tlen, kid) == BBR_OK) {
                for (int k = 0; k < r.count; k++) {
                    if (memcmp(r.keys[k].kid, kid, BBR_KID_BYTES) == 0) {
                        rc = bbr_decrypt_text(&r.keys[k], hit, tlen, NULL, 0, dec, cap, &dlen);
                        break;
                    }
                }
            } else {
                rc = BBR_ERR_FORMAT;
            }
            if (rc == BBR_OK) {
                fwrite(dec, 1, dlen, stdout);
            } else {
                failed++;
                fprintf(stdout, "[ÇÖZÜLEMEDİ: %s]", bbr_strerror(rc));
            }
            if (dec) { wipe(dec, cap); free(dec); }
            i = end;
        }
        fputc('\n', stdout);
        wipe(line, len);
        free(line);
    }
    fflush(stdout);
    keyring_wipe(&r);
    if (failed) {
        fprintf(stderr, "uyarı: %ld kayıt çözülemedi\n", failed);
        return 2;
    }
    return 0;
}

static int generate_key(void)
{
    uint8_t master[BBR_KEY_BYTES];
    char text[64];
    if (bbr_generate_key(master) != BBR_OK) {
        fputs("hata: rastgele sayı alınamadı\n", stderr);
        return 1;
    }
    bbr_key_to_text(master, text, sizeof text);
    puts(text);
    bbr_key k;
    bbr_key_init(&k, master);
    fprintf(stderr, "anahtar kimliği: %02x%02x%02x%02x — bu anahtarı gizli tutun; "
                    "kaybederseniz loglar açılamaz.\n", k.kid[0], k.kid[1], k.kid[2], k.kid[3]);
    bbr_key_wipe(&k);
    wipe(master, sizeof master);
    wipe(text, sizeof text);
    return 0;
}

int main(int argc, char **argv)
{
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8); /* Türkçe mesajlar konsolda doğru görünsün */
#endif
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "anahtar-uret") == 0)
        return generate_key();
    if (strcmp(cmd, "log-sifrele") == 0 || strcmp(cmd, "log-coz") == 0) {
        const char *key_file = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) key_file = argv[++i];
            else { usage(); return 1; }
        }
#if defined(_WIN32)
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
#endif
        return strcmp(cmd, "log-sifrele") == 0 ? log_encrypt(key_file) : log_decrypt(key_file);
    }
    if (strcmp(cmd, "hash") == 0) {
        if (argc < 3) { usage(); return 1; }
        return hash_files(argc - 2, argv + 2);
    }

    int rounds = BBF_DEFAULT_ROUNDS, overwrite = 0, layers = 1;
    long iters = (long)BBF_DEFAULT_ITERS;
    const char *paths[2] = { NULL, NULL };
    int npaths = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) rounds = atoi(argv[++i]);
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) iters = atol(argv[++i]);
        else if (strcmp(argv[i], "-z") == 0) overwrite = 1;
        else if (strcmp(argv[i], "-2") == 0) layers = 2;
        else if (npaths < 2) paths[npaths++] = argv[i];
        else { usage(); return 1; }
    }

    if (strcmp(cmd, "bilgi") == 0 && npaths == 1) {
        bbf_info info;
        int rc = bbf_read_info(paths[0], &info);
        if (rc != BBF_OK) { fprintf(stderr, "hata: %s\n", bbf_strerror(rc)); return 1; }
        printf("BicBic416 dosyası (biçim sürümü %d)\n"
               "  katmanlar: %s\n"
               "  tur sayısı: %d\n"
               "  PBKDF2 yineleme: %lu\n"
               "  veri boyutu: %llu bayt\n",
               info.version, info.layers == 2 ? "BicBic416 + ChaCha20" : "BicBic416",
               info.rounds, (unsigned long)info.iterations, (unsigned long long)info.data_bytes);
        return 0;
    }

    int enc = strcmp(cmd, "sifrele") == 0, dec = strcmp(cmd, "coz") == 0;
    if ((!enc && !dec) || npaths != 2) { usage(); return 1; }
    if (strcmp(paths[0], paths[1]) == 0) {
        fputs("hata: girdi ve çıktı aynı dosya olamaz\n", stderr);
        return 1;
    }
    if (enc && (rounds < 1 || rounds > 32 || iters < (long)BBF_ITER_UNIT ||
                iters > (long)BBF_MAX_ITERS || iters % (long)BBF_ITER_UNIT)) {
        fprintf(stderr, "hata: %s\n", bbf_strerror(BBF_ERR_PARAM));
        return 1;
    }

    char pw[PW_MAX];
    if (get_password(pw, enc) != 0) { wipe(pw, sizeof pw); return 1; }

    int rc = enc ? bbf_encrypt_file(paths[0], paths[1], pw, rounds, (uint32_t)iters, layers, overwrite)
                 : bbf_decrypt_file(paths[0], paths[1], pw, overwrite);
    wipe(pw, sizeof pw);

    if (rc != BBF_OK) {
        fprintf(stderr, "hata: %s\n", bbf_strerror(rc));
        return rc == BBF_ERR_AUTH ? 2 : 1;
    }
    fprintf(stderr, "%s: %s → %s\n", enc ? "şifrelendi" : "çözüldü", paths[0], paths[1]);
    return 0;
}
