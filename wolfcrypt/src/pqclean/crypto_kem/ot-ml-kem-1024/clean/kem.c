#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-1024/clean/indcpa.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-1024/clean/kem.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-1024/clean/params.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-1024/clean/symmetric.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-1024/clean/verify.h>

/*************************************************
 * Name:        OTMLKEM1024_CLEAN_crypto_kem_keypair_derand
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *              - uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
 **
 * Returns 0 (success)
 **************************************************/
int OTMLKEM1024_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    OTMLKEM1024_CLEAN_indcpa_keypair_derand(pk, sk, coins);
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

/*************************************************
 * Name:        OTMLKEM1024_CLEAN_crypto_kem_keypair
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int OTMLKEM1024_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk, WC_RNG *rng) {
    uint8_t coins[2 * KYBER_SYMBYTES];
    wc_RNG_GenerateBlock(rng, coins, 2 * KYBER_SYMBYTES);
    OTMLKEM1024_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);
    return 0;
}

/*************************************************
 * Name:        OTMLKEM1024_CLEAN_crypto_kem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - const uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with KYBER_SYMBYTES random bytes)
 **
 * Returns 0 (success)
 **************************************************/
int OTMLKEM1024_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                            const uint8_t *coins) {
    /* prekey = seed || ind-cpa msg || ind-cpa ciphertext */
    uint8_t prekey[KYBER_SYMBYTES + KYBER_INDCPA_MSGBYTES + KYBER_INDCPA_BYTES];
    hash_g(prekey, coins, KYBER_SYMBYTES); /* fill in seed and ind-cpa msg */

    OTMLKEM1024_CLEAN_indcpa_enc(prekey + (2 * KYBER_SYMBYTES), prekey + KYBER_SYMBYTES, pk,
                                 prekey);

    /* copy ciphertext to output */
    memcpy(ct, prekey + (2 * KYBER_SYMBYTES), KYBER_CIPHERTEXTBYTES);
    hash_h(ss, prekey + KYBER_SYMBYTES, KYBER_INDCPA_MSGBYTES + KYBER_INDCPA_BYTES);
    return 0;
}

/*************************************************
 * Name:        OTMLKEM1024_CLEAN_crypto_kem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int OTMLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, WC_RNG *rng) {
    uint8_t coins[KYBER_SYMBYTES];
    wc_RNG_GenerateBlock(rng, coins, KYBER_SYMBYTES);
    OTMLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss, pk, coins);
    return 0;
}

/*************************************************
 * Name:        OTMLKEM1024_CLEAN_crypto_kem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *ct: pointer to input cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - const uint8_t *sk: pointer to input private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0.
 *
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
int OTMLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t prekey[KYBER_INDCPA_MSGBYTES + KYBER_CIPHERTEXTBYTES];
    memcpy(prekey + KYBER_INDCPA_MSGBYTES, ct, KYBER_CIPHERTEXTBYTES);

    OTMLKEM1024_CLEAN_indcpa_dec(prekey, ct, sk);

    hash_h(ss, prekey, sizeof(prekey));

    return 0;
}
