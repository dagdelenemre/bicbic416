/*
 * bicbic — BicBic416 ile parolalı dosya şifreleme aracı.
 *
 *   bicbic sifrele [-r TUR] [-i YINELEME] [-z] <girdi> <cikti>
 *   bicbic coz [-z] <girdi> <cikti>
 *   bicbic bilgi <dosya>
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

#include "bicbic_file.h"
#include "sha256.h"

#define PW_MAX 1024

#if defined(_WIN32)
#  include <conio.h>
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
        "  bicbic sifrele [-r TUR] [-i YINELEME] [-z] <girdi> <cikti>\n"
        "  bicbic coz [-z] <girdi> <cikti>\n"
        "  bicbic bilgi <dosya>\n"
        "\n"
        "Seçenekler:\n"
        "  -r TUR       tur sayısı, 1..32 (varsayılan 16)\n"
        "  -i YINELEME  parola türetme yineleme sayısı (varsayılan 600000;\n"
        "               büyüdükçe parola tahmini zorlaşır, açılış yavaşlar)\n"
        "  -z           çıktı dosyası varsa üzerine yaz\n"
        "\n"
        "Parola ekranda görünmeden sorulur. Betiklerde BICBIC_PAROLA ortam değişkeni\n"
        "kullanılabilir. Dosya değiştirilirse veya parola yanlışsa çözme reddedilir.\n",
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

int main(int argc, char **argv)
{
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8); /* Türkçe mesajlar konsolda doğru görünsün */
#endif
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    int rounds = BBF_DEFAULT_ROUNDS, overwrite = 0;
    long iters = (long)BBF_DEFAULT_ITERS;
    const char *paths[2] = { NULL, NULL };
    int npaths = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) rounds = atoi(argv[++i]);
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) iters = atol(argv[++i]);
        else if (strcmp(argv[i], "-z") == 0) overwrite = 1;
        else if (npaths < 2) paths[npaths++] = argv[i];
        else { usage(); return 1; }
    }

    if (strcmp(cmd, "bilgi") == 0 && npaths == 1) {
        bbf_info info;
        int rc = bbf_read_info(paths[0], &info);
        if (rc != BBF_OK) { fprintf(stderr, "hata: %s\n", bbf_strerror(rc)); return 1; }
        printf("BicBic416 dosyası (sürüm 1)\n  tur sayısı: %d\n  PBKDF2 yineleme: %lu\n"
               "  veri boyutu: %llu bayt\n", info.rounds, (unsigned long)info.iterations,
               (unsigned long long)info.data_bytes);
        return 0;
    }

    int enc = strcmp(cmd, "sifrele") == 0, dec = strcmp(cmd, "coz") == 0;
    if ((!enc && !dec) || npaths != 2) { usage(); return 1; }
    if (strcmp(paths[0], paths[1]) == 0) {
        fputs("hata: girdi ve çıktı aynı dosya olamaz\n", stderr);
        return 1;
    }
    if (enc && (rounds < 1 || rounds > 32 || iters < 1 || iters > (long)BBF_MAX_ITERS)) {
        fprintf(stderr, "hata: %s\n", bbf_strerror(BBF_ERR_PARAM));
        return 1;
    }

    char pw[PW_MAX];
    if (get_password(pw, enc) != 0) { wipe(pw, sizeof pw); return 1; }

    int rc = enc ? bbf_encrypt_file(paths[0], paths[1], pw, rounds, (uint32_t)iters, overwrite)
                 : bbf_decrypt_file(paths[0], paths[1], pw, overwrite);
    wipe(pw, sizeof pw);

    if (rc != BBF_OK) {
        fprintf(stderr, "hata: %s\n", bbf_strerror(rc));
        return rc == BBF_ERR_AUTH ? 2 : 1;
    }
    fprintf(stderr, "%s: %s → %s\n", enc ? "şifrelendi" : "çözüldü", paths[0], paths[1]);
    return 0;
}
