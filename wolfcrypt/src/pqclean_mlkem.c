#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

static int is_valid_level(int level) { return ((level == 1) || (level == 3) || (level == 5)); }

WOLFSSL_API int wc_PQCleanMlKemKey_Init(PQCleanMlKemKey *key) {
    return wc_PQCleanMlKemKey_InitEx(key, NULL, INVALID_DEVID);
}

/* TODO: For now heap and devId are ignored */
/* TODO: need to incorporate heap/devId */
WOLFSSL_API int wc_PQCleanMlKemKey_InitEx(PQCleanMlKemKey *key, void *heap, int devId) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(key, 0, sizeof(PQCleanMlKemKey));
    return 0;
}

WOLFSSL_API int wc_PQCleanMlKemKey_SetLevel(PQCleanMlKemKey *key, int level) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(level)) {
        return BAD_FUNC_ARG;
    }
    key->level = level;
    return 0;
}

WOLFSSL_API int wc_PQCleanMlKemKey_GetLevel(PQCleanMlKemKey *key, int *level) {
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
WOLFSSL_API int wc_PQCleanMlKemKey_Free(PQCleanMlKemKey *key) {
    if (key != NULL) {
        XMEMSET(key, 0, sizeof(PQCleanMlKemKey));
    }
    return 0;
}

WOLFSSL_API int wc_PQCleanMlKemKey_MakeKey(PQCleanMlKemKey *key, WC_RNG *rng) {
    if ((key == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    int wc_err;
    byte seed[PQCLEAN_MLKEM_SEED_SIZE];
    wc_RNG_GenerateBlock(rng, seed, sizeof(seed));
    wc_err = wc_PQCleanMlKemKey_MakeKeyWithRandom(key, seed, sizeof(seed));
    return wc_err;
}

WOLFSSL_API int wc_PQCleanMlKemKey_MakeKeyWithRandom(PQCleanMlKemKey *key, const byte *seed,
                                                     int len) {
    if ((key == NULL) || (seed == NULL) || (len != PQCLEAN_MLKEM_SEED_SIZE)) {
        /* len != PQCLEAN_MLKEM_SEED_SIZE feels redundant */
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    int wc_err, pqclean_err;
    if (key->level == 1) {
        pqclean_err = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(key->pk, key->sk, seed);
    } else if (key->level == 3) {
        pqclean_err = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(key->pk, key->sk, seed);
    } else { /* key->level must be 5 */
        pqclean_err = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(key->pk, key->sk, seed);
    }
    if (pqclean_err == 0) {
        key->pk_set = 1;
        key->sk_set = 1;
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

WOLFSSL_API int wc_PQCleanMlKemKey_CipherTextSize(PQCleanMlKemKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (key->level == 1) {
        *len = PQCLEAN_MLKEM_LEVEL1_CIPHERTEXT_SIZE;
    } else if (key->level == 3) {
        *len = PQCLEAN_MLKEM_LEVEL3_CIPHERTEXT_SIZE;
    } else { /* key->level must be 5 */
        *len = PQCLEAN_MLKEM_LEVEL5_CIPHERTEXT_SIZE;
    }
    return 0;
}

WOLFSSL_API int wc_PQCleanMlKemKey_SharedSecretSize(PQCleanMlKemKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    *len = PQCLEAN_MLKEM_SS_SIZE;
    return 0;
}

WOLFSSL_API int wc_PQCleanMlKemKey_Encapsulate(PQCleanMlKemKey *key, byte *ct, byte *ss,
                                               WC_RNG *rng) {
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (!key->pk_set) {
        return MISSING_KEY;
    }
    byte seed[PQCLEAN_MLKEM_SEED_SIZE];
    wc_RNG_GenerateBlock(rng, seed, sizeof(seed));
    return wc_PQCleanMlKemKey_EncapsulateWithRandom(key, ct, ss, seed, sizeof(seed));
}

WOLFSSL_API int wc_PQCleanMlKemKey_EncapsulateWithRandom(PQCleanMlKemKey *key, byte *ct, byte *ss,
                                                         const byte *rand, int len) {
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rand == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (!key->pk_set) {
        return MISSING_KEY;
    }
    int wc_err, pqclean_err;
    if (key->level == 1) {
        pqclean_err = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, key->pk, rand);
    } else if (key->level == 3) {
        pqclean_err = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss, key->pk, rand);
    } else { /* key->level == 5 */
        pqclean_err = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss, key->pk, rand);
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

WOLFSSL_API int wc_PQCleanMlKemKey_Decapsulate(PQCleanMlKemKey *key, byte *ss, const byte *ct,
                                               word32 len) {
    if ((key == NULL) || (ss == NULL) || (ct == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    if (!key->sk_set) {
        return MISSING_KEY;
    }
    word32 expected_ctlen;
    wc_PQCleanMlKemKey_CipherTextSize(key, &expected_ctlen);
    if (len != expected_ctlen) { /* ciphertext length is incorrect */
        return BUFFER_E;
    }

    int wc_err, pqclean_err;
    if (key->level == 1) {
        pqclean_err = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, key->sk);
    } else if (key->level == 3) {
        pqclean_err = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, key->sk);
    } else { /* key->level == 5 */
        pqclean_err = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, key->sk);
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

WOLFSSL_API int wc_PQCleanMlKemKey_DecodePrivateKey(PQCleanMlKemKey *key, const byte *in,
                                                    word32 len) {
    return NOT_COMPILED_IN;
}

WOLFSSL_API int wc_PQCleanMlKemKey_DecodePublicKey(PQCleanMlKemKey *key, const byte *in,
                                                   word32 len) {
    return NOT_COMPILED_IN;
}

WOLFSSL_API int wc_PQCleanMlKemKey_PrivateKeySize(PQCleanMlKemKey *key, word32 *len) {
    int ret = 0;

    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = PQCLEAN_MLKEM_LEVEL1_SECRETKEY_SIZE;
        break;
    case 3:
        *len = PQCLEAN_MLKEM_LEVEL3_SECRETKEY_SIZE;
        break;
    case 5:
        *len = PQCLEAN_MLKEM_LEVEL5_SECRETKEY_SIZE;
        break;
    default:
        ret = BAD_FUNC_ARG;
        break;
    }

    return ret;
}

WOLFSSL_API int wc_PQCleanMlKemKey_PublicKeySize(PQCleanMlKemKey *key, word32 *len) {
    int ret = 0;

    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = PQCLEAN_MLKEM_LEVEL1_PUBLICKEY_SIZE;
        break;
    case 3:
        *len = PQCLEAN_MLKEM_LEVEL3_PUBLICKEY_SIZE;
        break;
    case 5:
        *len = PQCLEAN_MLKEM_LEVEL5_PUBLICKEY_SIZE;
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
WOLFSSL_API int wc_PQCleanMlKemKey_EncodePrivateKey(PQCleanMlKemKey *key, byte *out, word32 len) {
    int ret = 0;
    word32 privKeyLen;

    if ((NULL == key) || (NULL == out))
        return BAD_FUNC_ARG;
    if ((ret = wc_PQCleanMlKemKey_PrivateKeySize(key, &privKeyLen)) != 0) {
        return ret;
    }
    if (len < privKeyLen) {
        return BUFFER_E;
    }
    if (!key->sk_set) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->sk, privKeyLen);

    return ret;
}

WOLFSSL_API int wc_PQCleanMlKemKey_EncodePublicKey(PQCleanMlKemKey *key, byte *out, word32 len) {
    int ret = 0;
    word32 pubKeyLen;

    if ((NULL == key) || (NULL == out))
        return BAD_FUNC_ARG;
    if ((ret = wc_PQCleanMlKemKey_PublicKeySize(key, &pubKeyLen)) != 0) {
        return ret;
    }
    if (len < pubKeyLen) {
        return BUFFER_E;
    }
    if (!key->pk_set) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->pk, pubKeyLen);

    return ret;
}
