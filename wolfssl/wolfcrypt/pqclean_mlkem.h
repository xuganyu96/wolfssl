/* A port of PQClean's `clean` implementation of ML-KEM
 */
#ifndef PQCLEAN_MLKEM_H
#define PQCLEAN_MLKEM_H

#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ml-kem-1024/clean/api.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ml-kem-512/clean/api.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ml-kem-768/clean/api.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#define PQCLEAN_MLKEM_LEVEL1_CIPHERTEXT_SIZE PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_MLKEM_LEVEL3_CIPHERTEXT_SIZE PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_MLKEM_LEVEL5_CIPHERTEXT_SIZE PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES

#define PQCLEAN_MLKEM_LEVEL1_PUBLICKEY_SIZE PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_MLKEM_LEVEL3_PUBLICKEY_SIZE PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_MLKEM_LEVEL5_PUBLICKEY_SIZE PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES

#define PQCLEAN_MLKEM_LEVEL1_SECRETKEY_SIZE PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_MLKEM_LEVEL3_SECRETKEY_SIZE PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_MLKEM_LEVEL5_SECRETKEY_SIZE PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES

#define PQCLEAN_MLKEM_MAX_SECRETKEY_SIZE PQCLEAN_MLKEM_LEVEL5_SECRETKEY_SIZE
#define PQCLEAN_MLKEM_MAX_PUBLICKEY_SIZE PQCLEAN_MLKEM_LEVEL5_PUBLICKEY_SIZE
#define PQCLEAN_MLKEM_SEED_SIZE 32
#define PQCLEAN_MLKEM_SS_SIZE 32

typedef struct PQCleanMlKemKey {
    /* 1, 3, or 5 */
    int level;
    /* secret key */
    byte sk[PQCLEAN_MLKEM_MAX_SECRETKEY_SIZE];
    /* public key */
    byte pk[PQCLEAN_MLKEM_MAX_PUBLICKEY_SIZE];
    /* 1 if secret key is set */
    byte sk_set;
    /* 1 if public key is set */
    byte pk_set;
} PQCleanMlKemKey;

WOLFSSL_API int wc_PQCleanMlKemKey_Init(PQCleanMlKemKey *key);
WOLFSSL_API int wc_PQCleanMlKemKey_InitEx(PQCleanMlKemKey *key, int type, void *heap, int devId);
WOLFSSL_API int wc_PQCleanMlKemKey_Free(PQCleanMlKemKey *key);

WOLFSSL_API int wc_PQCleanMlKemKey_MakeKey(PQCleanMlKemKey *key, WC_RNG *rng);
WOLFSSL_API int wc_PQCleanMlKemKey_MakeKeyWithRandom(PQCleanMlKemKey *key,
                                                     const unsigned char *rand, int len);

WOLFSSL_API int wc_PQCleanMlKemKey_CipherTextSize(PQCleanMlKemKey *key, word32 *len);
WOLFSSL_API int wc_PQCleanMlKemKey_SharedSecretSize(PQCleanMlKemKey *key, word32 *len);

WOLFSSL_API int wc_PQCleanMlKemKey_Encapsulate(PQCleanMlKemKey *key, unsigned char *ct,
                                               unsigned char *ss, WC_RNG *rng);
WOLFSSL_API int wc_PQCleanMlKemKey_EncapsulateWithRandom(PQCleanMlKemKey *key, unsigned char *ct,
                                                         unsigned char *ss,
                                                         const unsigned char *rand, int len);
WOLFSSL_API int wc_PQCleanMlKemKey_Decapsulate(PQCleanMlKemKey *key, unsigned char *ss,
                                               const unsigned char *ct, word32 len);

WOLFSSL_API int wc_PQCleanMlKemKey_DecodePrivateKey(PQCleanMlKemKey *key, const unsigned char *in,
                                                    word32 len);
WOLFSSL_API int wc_PQCleanMlKemKey_DecodePublicKey(PQCleanMlKemKey *key, const unsigned char *in,
                                                   word32 len);

WOLFSSL_API int wc_PQCleanMlKemKey_PrivateKeySize(PQCleanMlKemKey *key, word32 *len);
WOLFSSL_API int wc_PQCleanMlKemKey_PublicKeySize(PQCleanMlKemKey *key, word32 *len);
WOLFSSL_API int wc_PQCleanMlKemKey_EncodePrivateKey(PQCleanMlKemKey *key, unsigned char *out,
                                                    word32 len);
WOLFSSL_API int wc_PQCleanMlKemKey_EncodePublicKey(PQCleanMlKemKey *key, unsigned char *out,
                                                   word32 len);

#endif
