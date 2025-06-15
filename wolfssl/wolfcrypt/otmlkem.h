#ifndef WOLFCRYPT_OTMLKEM_H
#define WOLFCRYPT_OTMLKEM_H

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#include <crypto_kem/ot-ml-kem-512/clean/api.h>
#include <crypto_kem/ot-ml-kem-768/clean/api.h>
#include <crypto_kem/ot-ml-kem-1024/clean/api.h>

#define PQCLEAN_OTMLKEM_LEVEL1_CIPHERTEXT_SIZE                                     \
    PQCLEAN_OTMLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_OTMLKEM_LEVEL3_CIPHERTEXT_SIZE                                     \
    PQCLEAN_OTMLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_OTMLKEM_LEVEL5_CIPHERTEXT_SIZE                                     \
    PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES

#define PQCLEAN_OTMLKEM_LEVEL1_PUBLICKEY_SIZE                                      \
    PQCLEAN_OTMLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_OTMLKEM_LEVEL3_PUBLICKEY_SIZE                                      \
    PQCLEAN_OTMLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_OTMLKEM_LEVEL5_PUBLICKEY_SIZE                                      \
    PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES

#define PQCLEAN_OTMLKEM_LEVEL1_SECRETKEY_SIZE                                      \
    PQCLEAN_OTMLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_OTMLKEM_LEVEL3_SECRETKEY_SIZE                                      \
    PQCLEAN_OTMLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_OTMLKEM_LEVEL5_SECRETKEY_SIZE                                      \
    PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES

#define PQCLEAN_OTMLKEM_LEVEL1_SHAREDSECRET_SIZE PQCLEAN_OTMLKEM512_CLEAN_CRYPTO_BYTES
#define PQCLEAN_OTMLKEM_LEVEL3_SHAREDSECRET_SIZE PQCLEAN_OTMLKEM768_CLEAN_CRYPTO_BYTES
#define PQCLEAN_OTMLKEM_LEVEL5_SHAREDSECRET_SIZE PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_BYTES

#define PQCLEAN_OTMLKEM_MAX_SECRETKEY_SIZE PQCLEAN_OTMLKEM_LEVEL5_SECRETKEY_SIZE
#define PQCLEAN_OTMLKEM_MAX_PUBLICKEY_SIZE PQCLEAN_OTMLKEM_LEVEL5_PUBLICKEY_SIZE
#define PQCLEAN_OTMLKEM_MAX_CIPHERTEXT_SIZE PQCLEAN_OTMLKEM_LEVEL5_CIPHERTEXT_SIZE
#define PQCLEAN_OTMLKEM_MAX_SHAREDSECRET_SIZE PQCLEAN_OTMLKEM_LEVEL5_SHAREDSECRET_SIZE

typedef struct OtMlKemKey {
    /* 1, 3, or 5 */
    int level;
    byte privKey[PQCLEAN_OTMLKEM_MAX_SECRETKEY_SIZE];
    byte pubKey[PQCLEAN_OTMLKEM_MAX_PUBLICKEY_SIZE];
    /* 1 if secret key is set */
    byte privKeySet;
    /* 1 if public key is set */
    byte pubKeySet;
} OtMlKemKey;

WOLFSSL_API int wc_OtMlKemKey_Init(OtMlKemKey *key);
WOLFSSL_API int wc_OtMlKemKey_InitEx(OtMlKemKey *key, void *heap, int devId);
WOLFSSL_API int wc_OtMlKemKey_MakeKey(OtMlKemKey *key, WC_RNG *rng);
WOLFSSL_API int wc_OtMlKemKey_SetLevel(OtMlKemKey *key, int level);
WOLFSSL_API int wc_OtMlKemKey_PublicKeySize(OtMlKemKey *key, word32 *pubKeyLen);
WOLFSSL_API int wc_OtMlKemKey_PrivateKeySize(OtMlKemKey *key, word32 *privKeyLen);
WOLFSSL_API int wc_OtMlKemKey_CipherTextSize(OtMlKemKey *key, word32 *ctLen);
WOLFSSL_API int wc_OtMlKemKey_SharedSecretSize(OtMlKemKey *key, word32 *ssLen);
WOLFSSL_API int wc_OtMlKemKey_import_public(OtMlKemKey *key, const byte *data,
                                        word32 len);
WOLFSSL_API int wc_OtMlKemKey_import_private(OtMlKemKey *key, const byte *data,
                                         word32 len);
WOLFSSL_API int wc_OtMlKemKey_export_public_key(OtMlKemKey *key, byte *out, word32 len);
WOLFSSL_API int wc_OtMlKemKey_export_private_key(OtMlKemKey *key, byte *out,
                                             word32 len);
WOLFSSL_API int wc_OtMlKemKey_Encapsulate(OtMlKemKey *key, byte *ct, byte *ss,
                                      WC_RNG *rng);
WOLFSSL_API int wc_OtMlKemKey_Decapsulate(OtMlKemKey *key, byte *ss, const byte *ct,
                                      word32 ctLen);
WOLFSSL_API int wc_OtMlKemKey_Free(OtMlKemKey *key);

#endif /* WOLFCRYPT_OTMLKEM_H */
