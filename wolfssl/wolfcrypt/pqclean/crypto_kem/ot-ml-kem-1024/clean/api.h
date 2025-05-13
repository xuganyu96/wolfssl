#ifndef OTMLKEM1024_CLEAN_API_H
#define OTMLKEM1024_CLEAN_API_H

#include <stdint.h>
#include <wolfssl/wolfcrypt/random.h>

#define OTMLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES 3168
#define OTMLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES 1568
#define OTMLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES 1568
#define OTMLKEM1024_CLEAN_CRYPTO_BYTES 32
#define OTMLKEM1024_CLEAN_CRYPTO_ALGNAME "OT-ML-KEM-1024"

int OTMLKEM1024_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk, WC_RNG *rng);
int OTMLKEM1024_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

int OTMLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, WC_RNG *rng);

int OTMLKEM1024_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                            const uint8_t *coins);

int OTMLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, WC_RNG *rng);

int OTMLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
