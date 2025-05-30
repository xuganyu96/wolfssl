/* A port of PQClean's `clean` implementation of HQC
 */
#ifndef PQCLEAN_HQC_H
#define PQCLEAN_HQC_H

#include <wolfssl/wolfcrypt/pqclean/crypto_kem/hqc-128/clean/api.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/hqc-192/clean/api.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/hqc-256/clean/api.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#define PQCLEAN_HQC_LEVEL1_CIPHERTEXT_SIZE                                     \
    PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_HQC_LEVEL3_CIPHERTEXT_SIZE                                     \
    PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_HQC_LEVEL5_CIPHERTEXT_SIZE                                     \
    PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES

#define PQCLEAN_HQC_LEVEL1_PUBLICKEY_SIZE                                      \
    PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_HQC_LEVEL3_PUBLICKEY_SIZE                                      \
    PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_HQC_LEVEL5_PUBLICKEY_SIZE                                      \
    PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES

#define PQCLEAN_HQC_LEVEL1_SECRETKEY_SIZE                                      \
    PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_HQC_LEVEL3_SECRETKEY_SIZE                                      \
    PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_HQC_LEVEL5_SECRETKEY_SIZE                                      \
    PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES

#define PQCLEAN_HQC_LEVEL1_SHAREDSECRET_SIZE PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES
#define PQCLEAN_HQC_LEVEL3_SHAREDSECRET_SIZE PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
#define PQCLEAN_HQC_LEVEL5_SHAREDSECRET_SIZE PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES

#define PQCLEAN_HQC_MAX_SECRETKEY_SIZE PQCLEAN_HQC_LEVEL5_SECRETKEY_SIZE
#define PQCLEAN_HQC_MAX_PUBLICKEY_SIZE PQCLEAN_HQC_LEVEL5_PUBLICKEY_SIZE
#define PQCLEAN_HQC_MAX_CIPHERTEXT_SIZE PQCLEAN_HQC_LEVEL5_CIPHERTEXT_SIZE
#define PQCLEAN_HQC_MAX_SHAREDSECRET_SIZE PQCLEAN_HQC_LEVEL5_SHAREDSECRET_SIZE

typedef struct PQCleanHqcKey {
    /* 1, 3, or 5 */
    int level;
    byte privKey[PQCLEAN_HQC_MAX_SECRETKEY_SIZE];
    byte pubKey[PQCLEAN_HQC_MAX_PUBLICKEY_SIZE];
    /* 1 if secret key is set */
    byte privKeySet;
    /* 1 if public key is set */
    byte pubKeySet;
} PQCleanHqcKey;

/* Public API, copied directly from wolfssl/wolfcrypt/mlkem.h */

WOLFSSL_API int wc_PQCleanHqcKey_Init(PQCleanHqcKey *key);
WOLFSSL_API int wc_PQCleanHqcKey_InitEx(PQCleanHqcKey *key, void *heap,
                                        int devId);
WOLFSSL_API int wc_PQCleanHqcKey_Free(PQCleanHqcKey *key);

WOLFSSL_API int wc_PQCleanHqcKey_SetLevel(PQCleanHqcKey *key, int level);
WOLFSSL_API int wc_PQCleanHqcKey_GetLevel(PQCleanHqcKey *key, int *level);
WOLFSSL_API int wc_PQCleanHqcKey_MakeKey(PQCleanHqcKey *key, WC_RNG *rng);
WOLFSSL_API int wc_PQCleanHqcKey_MakeKeyWithRandom(PQCleanHqcKey *key,
                                                   const byte *rand, int len);

WOLFSSL_API int wc_PQCleanHqcKey_CipherTextSize(PQCleanHqcKey *key,
                                                word32 *len);
WOLFSSL_API int wc_PQCleanHqcKey_SharedSecretSize(PQCleanHqcKey *key,
                                                  word32 *len);

WOLFSSL_API int wc_PQCleanHqcKey_Encapsulate(PQCleanHqcKey *key, byte *ct,
                                             byte *ss, WC_RNG *rng);
WOLFSSL_API int wc_PQCleanHqcKey_EncapsulateWithRandom(PQCleanHqcKey *key,
                                                       byte *ct, byte *ss,
                                                       const byte *rand,
                                                       int len);
WOLFSSL_API int wc_PQCleanHqcKey_Decapsulate(PQCleanHqcKey *key, byte *ss,
                                             const byte *ct, word32 len);

WOLFSSL_API int wc_PQCleanHqcKey_DecodePrivateKey(PQCleanHqcKey *key,
                                                  const byte *in, word32 len);
WOLFSSL_API int wc_PQCleanHqcKey_DecodePublicKey(PQCleanHqcKey *key,
                                                 const byte *in, word32 len);

WOLFSSL_API int wc_PQCleanHqcKey_PrivateKeySize(PQCleanHqcKey *key,
                                                word32 *len);
WOLFSSL_API int wc_PQCleanHqcKey_PublicKeySize(PQCleanHqcKey *key, word32 *len);
WOLFSSL_API int wc_PQCleanHqcKey_EncodePrivateKey(PQCleanHqcKey *key, byte *out,
                                                  word32 len);
WOLFSSL_API int wc_PQCleanHqcKey_EncodePublicKey(PQCleanHqcKey *key, byte *out,
                                                 word32 len);

WOLFSSL_API int wc_PQCleanHqcKey_PublicKeyToDer(PQCleanHqcKey *key, byte *out,
                                                word32 len, int withAlg);
WOLFSSL_API int wc_PQCleanHqcKey_PrivateKeyToDer(PQCleanHqcKey *key, byte *out,
                                                 word32 len);
WOLFSSL_API int wc_PQCleanHqcKey_DerToPrivateKey(PQCleanHqcKey *key, byte *in,
                                                 word32 len);

#endif
