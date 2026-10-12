/*
 * İşletim sisteminin kriptografik rastgele üreteci.
 * Windows: BCryptGenRandom (bcrypt.dll). Linux/macOS/BSD: getentropy veya /dev/urandom.
 * Platforma özel kod yalnızca bu dosyada ve araçtadır; şifre kütüphanesi taşınabilir kalır.
 */
#include "osrand.h"

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>

int os_random(void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len) {
        ULONG chunk = len > 0x10000000u ? 0x10000000u : (ULONG)len;
        if (BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return -1;
        p += chunk;
        len -= chunk;
    }
    return 0;
}

#else
#  include <stdio.h>

int os_random(void *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return -1;
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    return got == len ? 0 : -1;
}
#endif
