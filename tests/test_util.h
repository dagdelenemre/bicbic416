/*
 * Testler için ortak yardımcılar: tekrarlanabilir PRNG ve CHECK makrosu.
 * PRNG (splitmix64) kriptografik DEĞİLDİR; yalnızca test verisi üretir.
 * Tohum komut satırından değiştirilebilir: ./test_x [tohum]
 */
#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define TU_DEFAULT_SEED 0x4249434249433431ULL /* "BICBIC41" */

static uint64_t tu_rng_state = TU_DEFAULT_SEED;
static unsigned long tu_failures = 0;

static inline uint64_t tu_rand64(void)
{
    uint64_t z = (tu_rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline uint32_t tu_rand32(void)
{
    return (uint32_t)(tu_rand64() >> 32);
}

static inline void tu_randbytes(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(tu_rand64() >> 56);
}

/* Başarısızlığı sayar ama testi durdurmaz; ilk 20 hata yazdırılır. */
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond) && tu_failures++ < 20)                                   \
            fprintf(stderr, "%s:%d: CHECK(%s) başarısız\n",                 \
                    __FILE__, __LINE__, #cond);                              \
    } while (0)

static inline void tu_init(const char *name, int argc, char **argv)
{
    if (argc > 1)
        tu_rng_state = strtoull(argv[1], NULL, 0);
    printf("[%s] tohum = 0x%016llX\n", name, (unsigned long long)tu_rng_state);
}

static inline int tu_finish(const char *name)
{
    if (tu_failures) {
        printf("[%s] BAŞARISIZ (%lu hata)\n", name, tu_failures);
        return 1;
    }
    printf("[%s] TAMAM\n", name);
    return 0;
}

#endif /* TEST_UTIL_H */
