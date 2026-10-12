#ifndef BICBIC_OSRAND_H
#define BICBIC_OSRAND_H

#include <stddef.h>
#include <stdint.h>

/* buf'u işletim sisteminin güvenli rastgele baytlarıyla doldurur. 0 = başarılı. */
int os_random(void *buf, size_t len);

#endif
