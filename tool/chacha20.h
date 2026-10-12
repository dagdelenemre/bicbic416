/*
 * ChaCha20 akış şifresi (RFC 8439). İki katmanlı modda BicBic416'nın üstüne
 * ikinci, bağımsız bir şifreleme katmanı olarak kullanılır.
 * Doğruluk: tests/test_chacha20.c, Python `cryptography` (OpenSSL) çıktısıyla karşılaştırır.
 */
#ifndef BICBIC_CHACHA20_H
#define BICBIC_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY_BYTES   32
#define CHACHA20_NONCE_BYTES 12
#define CHACHA20_BLOCK_BYTES 64

/* in ⊕ anahtar akışı → out. counter, ilk 64 baytlık bloğun sayacıdır; her blokta 1 artar.
 * in == out desteklenir. Çağıran, counter + blok sayısının 2^32'yi aşmamasını sağlar. */
void chacha20_xor(const uint8_t key[CHACHA20_KEY_BYTES], const uint8_t nonce[CHACHA20_NONCE_BYTES],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);

#endif
