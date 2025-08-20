#ifndef WOLFCRYPT_HQC_H
#define WOLFCRYPT_HQC_H

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_HQC

#ifdef HAVE_PQCLEAN
#include <crypto_kem/hqc-128/clean/api.h>
#include <crypto_kem/hqc-192/clean/api.h>
#include <crypto_kem/hqc-256/clean/api.h>

#define HQC_LEVEL1_PRIVKEY_SIZE PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES
#define HQC_LEVEL1_PUBKEY_SIZE PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES
#define HQC_LEVEL1_CIPHERTEXT_SIZE PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define HQC_LEVEL1_SHAREDSECRET_SIZE PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES
#define HQC_LEVEL3_PRIVKEY_SIZE PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES
#define HQC_LEVEL3_PUBKEY_SIZE PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES
#define HQC_LEVEL3_CIPHERTEXT_SIZE PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define HQC_LEVEL3_SHAREDSECRET_SIZE PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
#define HQC_LEVEL5_PRIVKEY_SIZE PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES
#define HQC_LEVEL5_PUBKEY_SIZE PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES
#define HQC_LEVEL5_CIPHERTEXT_SIZE PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define HQC_LEVEL5_SHAREDSECRET_SIZE PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES

#else
#error "No other implementation found"
#endif /* HAVE_PQCLEAN */

#define HQC_MAX_PRIVKEY_SIZE HQC_LEVEL5_PRIVKEY_SIZE
#define HQC_MAX_PUBKEY_SIZE HQC_LEVEL5_PUBKEY_SIZE
#define HQC_MAX_CIPHERTEXT_SIZE HQC_LEVEL5_CIPHERTEXT_SIZE
#define HQC_MAX_SHAREDSECRET_SIZE HQC_LEVEL5_SHAREDSECRET_SIZE

typedef struct HqcKey {
    int level;
    int pubkey_set;
    byte pubkey[HQC_MAX_PUBKEY_SIZE];
    int privkey_set;
    byte privkey[HQC_MAX_PRIVKEY_SIZE];
} HqcKey;

int wc_HqcKey_Init(HqcKey *key);
int wc_HqcKey_Free(HqcKey *key);
int wc_HqcKey_SetLevel(HqcKey *key, int level);
int wc_HqcKey_GetLevel(HqcKey *key, int *level);
int wc_HqcKey_PublicKeySize(HqcKey *key, word32 *len);
int wc_HqcKey_PrivateKeySize(HqcKey *key, word32 *len);
int wc_HqcKey_CiphertextSize(HqcKey *key, word32 *len);
int wc_HqcKey_SharedSecretSize(HqcKey *key, word32 *len);
int wc_HqcKey_MakeKey(HqcKey *key, WC_RNG *rng);
int wc_HqcKey_Encapsulate(HqcKey *key, byte *ct, byte *ss, WC_RNG *rng);
int wc_HqcKey_Decapsulate(HqcKey *key, byte *ss, const byte *ct, word32 len);
int wc_HqcKey_ExportPublicKey(HqcKey *key, byte *buf, word32 len);
int wc_HqcKey_ExportPrivateKey(HqcKey *key, byte *buf, word32 len);
int wc_HqcKey_ImportPublicKey(HqcKey *key, byte *buf, word32 len);
int wc_HqcKey_ImportPrivateKey(HqcKey *key, byte *buf, word32 len);
#endif /* HAVE_HQC */

#endif /* WOLFCRYPT_HQC_H */
