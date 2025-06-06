#ifndef WOLFCRYPT_HQC_H
#define WOLFCRYPT_HQC_H

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef PQCLEAN_HQC
#include <crypto_kem/hqc-128/clean/api.h>
#include <crypto_kem/hqc-192/clean/api.h>
#include <crypto_kem/hqc-256/clean/api.h>
#endif

#ifdef PQCLEAN_HQC
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

#endif /* HAVE_HQC */

#define PQCLEAN_HQC_MAX_SECRETKEY_SIZE PQCLEAN_HQC_LEVEL5_SECRETKEY_SIZE
#define PQCLEAN_HQC_MAX_PUBLICKEY_SIZE PQCLEAN_HQC_LEVEL5_PUBLICKEY_SIZE
#define PQCLEAN_HQC_MAX_CIPHERTEXT_SIZE PQCLEAN_HQC_LEVEL5_CIPHERTEXT_SIZE
#define PQCLEAN_HQC_MAX_SHAREDSECRET_SIZE PQCLEAN_HQC_LEVEL5_SHAREDSECRET_SIZE

typedef struct HqcKey {
    /* 1, 3, or 5 */
    int level;
    byte privKey[PQCLEAN_HQC_MAX_SECRETKEY_SIZE];
    byte pubKey[PQCLEAN_HQC_MAX_PUBLICKEY_SIZE];
    /* 1 if secret key is set */
    byte privKeySet;
    /* 1 if public key is set */
    byte pubKeySet;
} HqcKey;

WOLFSSL_API int wc_HqcKey_Init(HqcKey *key);
WOLFSSL_API int wc_HqcKey_InitEx(HqcKey *key, void *heap, int devId);
WOLFSSL_API int wc_HqcKey_MakeKey(HqcKey *key, WC_RNG *rng);
WOLFSSL_API int wc_HqcKey_SetLevel(HqcKey *key, int level);
WOLFSSL_API int wc_HqcKey_PublicKeySize(HqcKey *key, word32 *pubKeyLen);
WOLFSSL_API int wc_HqcKey_PrivateKeySize(HqcKey *key, word32 *privKeyLen);
WOLFSSL_API int wc_HqcKey_CipherTextSize(HqcKey *key, word32 *ctLen);
WOLFSSL_API int wc_HqcKey_SharedSecretSize(HqcKey *key, word32 *ssLen);
WOLFSSL_API int wc_HqcKey_import_public(HqcKey *key, const byte *data,
                                        word32 len);
WOLFSSL_API int wc_HqcKey_import_private(HqcKey *key, const byte *data,
                                         word32 len);
WOLFSSL_API int wc_HqcKey_export_public_key(HqcKey *key, byte *out, word32 len);
WOLFSSL_API int wc_HqcKey_export_private_key(HqcKey *key, byte *out,
                                             word32 len);
WOLFSSL_API int wc_HqcKey_Encapsulate(HqcKey *key, byte *ct, byte *ss,
                                      WC_RNG *rng);
WOLFSSL_API int wc_HqcKey_Decapsulate(HqcKey *key, byte *ss, const byte *ct,
                                      word32 ctLen);
WOLFSSL_API int wc_HqcKey_Free(HqcKey *key);

#endif /* WOLFCRYPT_HQC_H */
