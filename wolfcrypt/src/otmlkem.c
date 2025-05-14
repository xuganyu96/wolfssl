#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/otmlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

static int is_valid_level(int level) { return ((level == 1) || (level == 3) || (level == 5)); }

WOLFSSL_API int wc_OneTimeMlKemKey_Init(OneTimeMlKemKey *key) {
    return wc_OneTimeMlKemKey_InitEx(key, NULL, INVALID_DEVID);
}

/* Because keypair data are both allocated on the stack, there is no use of heap
 */
WOLFSSL_API int wc_OneTimeMlKemKey_InitEx(OneTimeMlKemKey *key, void *heap, int devId) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(key, 0, sizeof(OneTimeMlKemKey));
    return 0;
}

WOLFSSL_API int wc_OneTimeMlKemKey_SetLevel(OneTimeMlKemKey *key, int level) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(level)) {
        return BAD_FUNC_ARG;
    }
    key->level = level;
    return 0;
}

WOLFSSL_API int wc_OneTimeMlKemKey_GetLevel(OneTimeMlKemKey *key, int *level) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    *level = key->level;
    return 0;
}

/* This function should never fail */
WOLFSSL_API int wc_OneTimeMlKemKey_Free(OneTimeMlKemKey *key) {
    if (key != NULL) {
        XMEMSET(key, 0, sizeof(OneTimeMlKemKey));
    }
    return 0;
}

WOLFSSL_API int wc_OneTimeMlKemKey_MakeKey(OneTimeMlKemKey *key, WC_RNG *rng) {
    if ((key == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    int wc_err;
    byte seed[OTMLKEM_SEED_SIZE];
    wc_RNG_GenerateBlock(rng, seed, sizeof(seed));
    wc_err = wc_OneTimeMlKemKey_MakeKeyWithRandom(key, seed, sizeof(seed));
    return wc_err;
}

WOLFSSL_API int wc_OneTimeMlKemKey_MakeKeyWithRandom(OneTimeMlKemKey *key, const byte *seed,
                                                     int len) {
    if ((key == NULL) || (seed == NULL) || (len != OTMLKEM_SEED_SIZE)) {
        /* len != OTMLKEM_SEED_SIZE feels redundant */
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    int wc_err, pqclean_err;
    if (key->level == 1) {
        pqclean_err = OTMLKEM512_CLEAN_crypto_kem_keypair_derand(key->pubKey, key->privKey, seed);
    } else if (key->level == 3) {
        pqclean_err = OTMLKEM768_CLEAN_crypto_kem_keypair_derand(key->pubKey, key->privKey, seed);
    } else { /* key->level must be 5 */
        pqclean_err = OTMLKEM1024_CLEAN_crypto_kem_keypair_derand(key->pubKey, key->privKey, seed);
    }
    if (pqclean_err == 0) {
        key->pubKeySet = 1;
        key->privKeySet = 1;
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

WOLFSSL_API int wc_OneTimeMlKemKey_CipherTextSize(OneTimeMlKemKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (key->level == 1) {
        *len = OTMLKEM_LEVEL1_CIPHERTEXT_SIZE;
    } else if (key->level == 3) {
        *len = OTMLKEM_LEVEL3_CIPHERTEXT_SIZE;
    } else { /* key->level must be 5 */
        *len = OTMLKEM_LEVEL5_CIPHERTEXT_SIZE;
    }
    return 0;
}

WOLFSSL_API int wc_OneTimeMlKemKey_SharedSecretSize(OneTimeMlKemKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    *len = OTMLKEM_SS_SIZE;
    return 0;
}

WOLFSSL_API int wc_OneTimeMlKemKey_Encapsulate(OneTimeMlKemKey *key, byte *ct, byte *ss,
                                               WC_RNG *rng) {
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }
    byte seed[OTMLKEM_SEED_SIZE];
    wc_RNG_GenerateBlock(rng, seed, sizeof(seed));
    return wc_OneTimeMlKemKey_EncapsulateWithRandom(key, ct, ss, seed, sizeof(seed));
}

WOLFSSL_API int wc_OneTimeMlKemKey_EncapsulateWithRandom(OneTimeMlKemKey *key, byte *ct, byte *ss,
                                                         const byte *rand, int len) {
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rand == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }
    int wc_err, pqclean_err;
    if (key->level == 1) {
        pqclean_err = OTMLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, key->pubKey, rand);
    } else if (key->level == 3) {
        pqclean_err = OTMLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss, key->pubKey, rand);
    } else { /* key->level == 5 */
        pqclean_err = OTMLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss, key->pubKey, rand);
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

WOLFSSL_API int wc_OneTimeMlKemKey_Decapsulate(OneTimeMlKemKey *key, byte *ss, const byte *ct,
                                               word32 len) {
    if ((key == NULL) || (ss == NULL) || (ct == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (!key->privKeySet) {
        return MISSING_KEY;
    }
    word32 expected_ctlen;
    wc_OneTimeMlKemKey_CipherTextSize(key, &expected_ctlen);
    if (len != expected_ctlen) { /* ciphertext length is incorrect */
        return BUFFER_E;
    }

    int wc_err, pqclean_err;
    if (key->level == 1) {
        pqclean_err = OTMLKEM512_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
    } else if (key->level == 3) {
        pqclean_err = OTMLKEM768_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
    } else { /* key->level == 5 */
        pqclean_err = OTMLKEM1024_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

WOLFSSL_API int wc_OneTimeMlKemKey_DecodePrivateKey(OneTimeMlKemKey *key, const byte *in,
                                                    word32 len) {
    int ret = 0;
    word32 PrivKeyLen = 0;

    if ((key == NULL) || (in == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((ret = wc_OneTimeMlKemKey_PrivateKeySize(key, &PrivKeyLen)) != 0) {
        return ret;
    }
    if (PrivKeyLen != len) {
        return BUFFER_E;
    }
    if (key->privKeySet) {
        WOLFSSL_MSG("OneTimeMlKemKey->privKey is already set");
        return BAD_FUNC_ARG;
    }
    XMEMCPY(key->privKey, in, len);
    key->privKeySet = 1;

    return ret;
}

WOLFSSL_API int wc_OneTimeMlKemKey_DecodePublicKey(OneTimeMlKemKey *key, const byte *in,
                                                   word32 len) {
    int ret = 0;
    word32 pubKeyLen = 0;

    if ((key == NULL) || (in == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((ret = wc_OneTimeMlKemKey_PublicKeySize(key, &pubKeyLen)) != 0) {
        return ret;
    }
    if (pubKeyLen != len) {
        return BUFFER_E;
    }
    if (key->pubKeySet) {
        WOLFSSL_MSG("OneTimeMlKemKey->pubKey is already set");
        return PUBLIC_KEY_E;
    }
    XMEMCPY(key->pubKey, in, len);
    key->pubKeySet = 1;

    return ret;
}

WOLFSSL_API int wc_OneTimeMlKemKey_PrivateKeySize(OneTimeMlKemKey *key, word32 *len) {
    int ret = 0;

    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = OTMLKEM_LEVEL1_SECRETKEY_SIZE;
        break;
    case 3:
        *len = OTMLKEM_LEVEL3_SECRETKEY_SIZE;
        break;
    case 5:
        *len = OTMLKEM_LEVEL5_SECRETKEY_SIZE;
        break;
    default:
        ret = BAD_FUNC_ARG;
        break;
    }

    return ret;
}

WOLFSSL_API int wc_OneTimeMlKemKey_PublicKeySize(OneTimeMlKemKey *key, word32 *len) {
    int ret = 0;

    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = OTMLKEM_LEVEL1_PUBLICKEY_SIZE;
        break;
    case 3:
        *len = OTMLKEM_LEVEL3_PUBLICKEY_SIZE;
        break;
    case 5:
        *len = OTMLKEM_LEVEL5_PUBLICKEY_SIZE;
        break;
    default:
        ret = BAD_FUNC_ARG;
        break;
    }

    return ret;
}

/* Treat PQClean KEM as black boxes; encoding simply means copying bytes from the key obj to the
 * input buffer
 */
WOLFSSL_API int wc_OneTimeMlKemKey_EncodePrivateKey(OneTimeMlKemKey *key, byte *out, word32 len) {
    int ret = 0;
    word32 privKeyLen;

    if ((NULL == key) || (NULL == out))
        return BAD_FUNC_ARG;
    if ((ret = wc_OneTimeMlKemKey_PrivateKeySize(key, &privKeyLen)) != 0) {
        return ret;
    }
    if (len < privKeyLen) {
        return BUFFER_E;
    }
    if (!key->privKeySet) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->privKey, privKeyLen);

    return ret;
}

WOLFSSL_API int wc_OneTimeMlKemKey_EncodePublicKey(OneTimeMlKemKey *key, byte *out, word32 len) {
    int ret = 0;
    word32 pubKeyLen;

    if ((NULL == key) || (NULL == out))
        return BAD_FUNC_ARG;
    if ((ret = wc_OneTimeMlKemKey_PublicKeySize(key, &pubKeyLen)) != 0) {
        return ret;
    }
    if (len < pubKeyLen) {
        return BUFFER_E;
    }
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->pubKey, pubKeyLen);

    return ret;
}
