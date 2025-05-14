/* one-time ML-KEM
 *
 * constructed from applying the T_H transformation to the CPA subroutines of Kyber
 * this KEM is suitable only for ephemeral key exchange; security of the scheme degrades
 * exponentially with respect to the number of key re-uses.
 *
 * @inproceedings{DBLP:conf/eurocrypt/Huguenin-Dumittan22,
 *   author       = {Lo{\"{\i}}s Huguenin{-}Dumittan and
 *                   Serge Vaudenay},
 *   editor       = {Orr Dunkelman and
 *                   Stefan Dziembowski},
 *   title        = {On IND-qCCA Security in the {ROM} and Its Applications - {CPA} Security
 *                   Is Sufficient for {TLS} 1.3},
 *   booktitle    = {Advances in Cryptology - {EUROCRYPT} 2022 - 41st Annual International
 *                   Conference on the Theory and Applications of Cryptographic Techniques,
 *                   Trondheim, Norway, May 30 - June 3, 2022, Proceedings, Part {III}},
 *   series       = {Lecture Notes in Computer Science},
 *   volume       = {13277},
 *   pages        = {613--642},
 *   publisher    = {Springer},
 *   year         = {2022},
 *   url          = {https://doi.org/10.1007/978-3-031-07082-2\_22},
 *   doi          = {10.1007/978-3-031-07082-2\_22},
 *   timestamp    = {Tue, 31 May 2022 17:23:11 +0200},
 *   biburl       = {https://dblp.org/rec/conf/eurocrypt/Huguenin-Dumittan22.bib},
 *   bibsource    = {dblp computer science bibliography, https://dblp.org}
 * }
 */
#ifndef OTMLKEM_H
#define OTMLKEM_H

#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-1024/clean/api.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-512/clean/api.h>
#include <wolfssl/wolfcrypt/pqclean/crypto_kem/ot-ml-kem-768/clean/api.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#define OTMLKEM_LEVEL1_CIPHERTEXT_SIZE OTMLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define OTMLKEM_LEVEL3_CIPHERTEXT_SIZE OTMLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define OTMLKEM_LEVEL5_CIPHERTEXT_SIZE OTMLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES

#define OTMLKEM_LEVEL1_PUBLICKEY_SIZE OTMLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define OTMLKEM_LEVEL3_PUBLICKEY_SIZE OTMLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define OTMLKEM_LEVEL5_PUBLICKEY_SIZE OTMLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES

#define OTMLKEM_LEVEL1_SECRETKEY_SIZE OTMLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#define OTMLKEM_LEVEL3_SECRETKEY_SIZE OTMLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define OTMLKEM_LEVEL5_SECRETKEY_SIZE OTMLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES

#define OTMLKEM_MAX_SECRETKEY_SIZE OTMLKEM_LEVEL5_SECRETKEY_SIZE
#define OTMLKEM_MAX_PUBLICKEY_SIZE OTMLKEM_LEVEL5_PUBLICKEY_SIZE
#define OTMLKEM_MAX_CIPHERTEXT_SIZE OTMLKEM_LEVEL5_CIPHERTEXT_SIZE
#define OTMLKEM_SEED_SIZE 64 /* same for all three levels */
#define OTMLKEM_SS_SIZE 32   /* same for all three levels */

typedef struct OneTimeMlKemKey {
    /* 1, 3, or 5 */
    int level;
    byte privKey[OTMLKEM_MAX_SECRETKEY_SIZE];
    byte pubKey[OTMLKEM_MAX_PUBLICKEY_SIZE];
    /* 1 if secret key is set */
    byte privKeySet;
    /* 1 if public key is set */
    byte pubKeySet;
} OneTimeMlKemKey;

/* Public API, copied directly from wolfssl/wolfcrypt/mlkem.h */

WOLFSSL_API int wc_OneTimeMlKemKey_Init(OneTimeMlKemKey *key);
WOLFSSL_API int wc_OneTimeMlKemKey_InitEx(OneTimeMlKemKey *key, void *heap, int devId);
WOLFSSL_API int wc_OneTimeMlKemKey_Free(OneTimeMlKemKey *key);

WOLFSSL_API int wc_OneTimeMlKemKey_SetLevel(OneTimeMlKemKey *key, int level);
WOLFSSL_API int wc_OneTimeMlKemKey_GetLevel(OneTimeMlKemKey *key, int *level);
WOLFSSL_API int wc_OneTimeMlKemKey_MakeKey(OneTimeMlKemKey *key, WC_RNG *rng);
WOLFSSL_API int wc_OneTimeMlKemKey_MakeKeyWithRandom(OneTimeMlKemKey *key, const byte *rand,
                                                     int len);

WOLFSSL_API int wc_OneTimeMlKemKey_CipherTextSize(OneTimeMlKemKey *key, word32 *len);
WOLFSSL_API int wc_OneTimeMlKemKey_SharedSecretSize(OneTimeMlKemKey *key, word32 *len);

WOLFSSL_API int wc_OneTimeMlKemKey_Encapsulate(OneTimeMlKemKey *key, byte *ct, byte *ss,
                                               WC_RNG *rng);
WOLFSSL_API int wc_OneTimeMlKemKey_EncapsulateWithRandom(OneTimeMlKemKey *key, byte *ct, byte *ss,
                                                         const byte *rand, int len);
WOLFSSL_API int wc_OneTimeMlKemKey_Decapsulate(OneTimeMlKemKey *key, byte *ss, const byte *ct,
                                               word32 len);

WOLFSSL_API int wc_OneTimeMlKemKey_DecodePrivateKey(OneTimeMlKemKey *key, const byte *in,
                                                    word32 len);
WOLFSSL_API int wc_OneTimeMlKemKey_DecodePublicKey(OneTimeMlKemKey *key, const byte *in,
                                                   word32 len);

WOLFSSL_API int wc_OneTimeMlKemKey_PrivateKeySize(OneTimeMlKemKey *key, word32 *len);
WOLFSSL_API int wc_OneTimeMlKemKey_PublicKeySize(OneTimeMlKemKey *key, word32 *len);
WOLFSSL_API int wc_OneTimeMlKemKey_EncodePrivateKey(OneTimeMlKemKey *key, byte *out, word32 len);
WOLFSSL_API int wc_OneTimeMlKemKey_EncodePublicKey(OneTimeMlKemKey *key, byte *out, word32 len);

#endif
