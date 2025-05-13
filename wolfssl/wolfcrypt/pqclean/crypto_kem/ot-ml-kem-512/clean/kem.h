#ifndef OTMLKEM512_CLEAN_KEM_H
#define OTMLKEM512_CLEAN_KEM_H


#include "params.h"
#include <wolfssl/wolfcrypt/random.h>
#include <stdint.h>

#define OTMLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES KYBER_SECRETKEYBYTES
#define OTMLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES KYBER_PUBLICKEYBYTES
#define OTMLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define OTMLKEM512_CLEAN_CRYPTO_BYTES KYBER_SSBYTES

#define OTMLKEM512_CLEAN_CRYPTO_ALGNAME "ML-KEM-512"

int OTMLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk,
                                                     const uint8_t *coins);

int OTMLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk, WC_RNG *rng);

int OTMLKEM512_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                                 const uint8_t *coins);

int OTMLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk, WC_RNG *rng);

int OTMLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
