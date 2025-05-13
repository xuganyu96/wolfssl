#ifndef OTMLKEM768_CLEAN_API_H
#define OTMLKEM768_CLEAN_API_H

#include <stdint.h>
#include <wolfssl/wolfcrypt/random.h>

#define OTMLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES 2400
#define OTMLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES 1184
#define OTMLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#define OTMLKEM768_CLEAN_CRYPTO_BYTES 32
#define OTMLKEM768_CLEAN_CRYPTO_ALGNAME "OT-ML-KEM-768"

int OTMLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

int OTMLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk, WC_RNG *rng);

int OTMLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                           const uint8_t *coins);

int OTMLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, WC_RNG *rng);

int OTMLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
