#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hqc.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef PQCLEAN_HQC
#include <common/randombytes.h>
#endif

int wc_HqcKey_Init(HqcKey *key) {
    return wc_HqcKey_InitEx(key, NULL, INVALID_DEVID);
}

/* public and private keys are stack allocated, no need to use heap */
int wc_HqcKey_InitEx(HqcKey *key, void *heap, int devId) {
    (void)heap;
    (void)devId;
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(key, 0, sizeof(HqcKey));
    return 0;
}

/* Clear all data from key. Similar to Init, but this function will never fail
 */
int wc_HqcKey_Free(HqcKey *key) {
    if (key != NULL) {
        XMEMSET(key, 0, sizeof(HqcKey));
    }
    return 0;
}

/* Return 1 if level is valid */
static int is_valid_level(int level) {
    return (level == 1) || (level == 3) || (level == 5);
}

int wc_HqcKey_SetLevel(HqcKey *key, int level) {
    if ((key == NULL) || !is_valid_level(level)) {
        return BAD_FUNC_ARG;
    }
    key->level = level;
    return 0;
}

int wc_HqcKey_GetLevel(HqcKey *key, int *level) {
    if ((NULL == key) || (NULL == level)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    *level = key->level;
    return 0;
}

int wc_HqcKey_MakeKey(HqcKey *key, WC_RNG *rng) {
    int ret = 0;

    if ((NULL == key) || (NULL == rng))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;

#ifdef PQCLEAN_HQC
    PQCLEAN_set_wc_rng(rng);
    switch (key->level) {
    case 1:
        ret =
            PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(key->pubKey, key->privKey);
        break;
    case 3:
        ret =
            PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(key->pubKey, key->privKey);
        break;
    case 5:
        ret =
            PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(key->pubKey, key->privKey);
        break;
        /* level already validated */
    }
    if (ret == 0) {
        key->pubKeySet = 1;
        key->privKeySet = 1;
        return ret;
    } else {
        return BAD_FUNC_ARG;
    }
#else
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

int wc_HqcKey_CipherTextSize(HqcKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_HQC_LEVEL1_CIPHERTEXT_SIZE;
        break;
    case 3:
        *len = PQCLEAN_HQC_LEVEL3_CIPHERTEXT_SIZE;
        break;
    case 5:
        *len = PQCLEAN_HQC_LEVEL5_CIPHERTEXT_SIZE;
        break;
    }
    return 0;
}

int wc_HqcKey_SharedSecretSize(HqcKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_HQC_LEVEL1_SHAREDSECRET_SIZE;
        break;
    case 3:
        *len = PQCLEAN_HQC_LEVEL3_SHAREDSECRET_SIZE;
        break;
    case 5:
        *len = PQCLEAN_HQC_LEVEL5_SHAREDSECRET_SIZE;
        break;
    }
    return 0;
}

int wc_HqcKey_Encapsulate(HqcKey *key, byte *ct, byte *ss, WC_RNG *rng) {
    int ret = 0;
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }
#ifdef PQCLEAN_HQC
    PQCLEAN_set_wc_rng(rng);
    switch (key->level) {
    case 1:
        ret = PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, key->pubKey);
        break;
    case 3:
        ret = PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ct, ss, key->pubKey);
        break;
    case 5:
        ret = PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss, key->pubKey);
        break;
        /* level already validated */
    }
    if (ret == 0) {
        return ret;
    }
    ret = BAD_FUNC_ARG;
#else
    ret = NOT_COMIPLED_IN;
#endif
    return ret;
}

int wc_HqcKey_Decapsulate(HqcKey *key, byte *ss, const byte *ct, word32 len) {
    int ret = 0;
    word32 ctLen = 0;

    if ((key == NULL) || (ss == NULL) || (ct == NULL))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (!key->privKeySet)
        return MISSING_KEY;
    ret = wc_HqcKey_CipherTextSize(key, &ctLen);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to get HQC ciphertext size");
        return BAD_FUNC_ARG;
    }
    if (len < ctLen) {
        WOLFSSL_MSG_EX("Need %d bytes of ct buf, given %d", ctLen, len);
        return BUFFER_E;
    }

    switch (key->level) {
    case 1:
        ret = PQCLEAN_HQC128_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
        break;
    case 3:
        ret = PQCLEAN_HQC192_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
        break;
    case 5:
        ret = PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
        break;
        /* level already validated */
    }

    if (ret != 0)
        ret = BAD_FUNC_ARG;
    return ret;
}

int wc_HqcKey_import_private(HqcKey *key, const byte *in, word32 len) {
    int ret = 0;
    word32 privKeyLen = 0;
    if ((key == NULL) || (in == NULL))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (key->privKeySet) {
        WOLFSSL_MSG("HQC priv key already set");
        return BAD_FUNC_ARG;
    }
    ret = wc_HqcKey_PrivateKeySize(key, &privKeyLen);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to get HQC private key size");
        return BAD_FUNC_ARG;
    }
    if (privKeyLen != len) {
        WOLFSSL_MSG_EX("Expect %d bytes, given %d bytes", privKeyLen, len);
        return BUFFER_E;
    }

    XMEMCPY(key->privKey, in, len);
    key->privKeySet = 1;

    return ret;
}

int wc_HqcKey_import_public(HqcKey *key, const byte *in, word32 len) {
    int ret = 0;
    word32 pubKeyLen = 0;
    if ((key == NULL) || (in == NULL))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (key->pubKeySet) {
        WOLFSSL_MSG("HQC pub key already set");
        return BAD_FUNC_ARG;
    }
    ret = wc_HqcKey_PublicKeySize(key, &pubKeyLen);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to get HQC public key size");
        return BAD_FUNC_ARG;
    }
    if (pubKeyLen != len) {
        WOLFSSL_MSG_EX("Expect %d bytes, given %d bytes", pubKeyLen, len);
        return BUFFER_E;
    }

    XMEMCPY(key->pubKey, in, len);
    key->pubKeySet = 1;

    return ret;
}

int wc_HqcKey_PrivateKeySize(HqcKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_HQC_LEVEL1_SECRETKEY_SIZE;
        break;
    case 3:
        *len = PQCLEAN_HQC_LEVEL3_SECRETKEY_SIZE;
        break;
    case 5:
        *len = PQCLEAN_HQC_LEVEL5_SECRETKEY_SIZE;
        break;
    }
    return 0;
}

int wc_HqcKey_PublicKeySize(HqcKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_HQC_LEVEL1_PUBLICKEY_SIZE;
        break;
    case 3:
        *len = PQCLEAN_HQC_LEVEL3_PUBLICKEY_SIZE;
        break;
    case 5:
        *len = PQCLEAN_HQC_LEVEL5_PUBLICKEY_SIZE;
        break;
    }
    return 0;
}

int wc_HqcKey_export_private_key(HqcKey *key, byte *out, word32 len) {
    word32 privKeyLen = 0;
    if ((key == NULL) || (out == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }

    if (wc_HqcKey_PrivateKeySize(key, &privKeyLen) != 0) {
        WOLFSSL_MSG("Failed to get HQC privKey size");
        return BAD_FUNC_ARG;
    }
    if (len < privKeyLen) {
        WOLFSSL_MSG_EX("Need %d bytes, given %d bytes", privKeyLen, len);
        return BUFFER_E;
    }
    if (!key->privKeySet) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->privKey, privKeyLen);

    return 0;
}

int wc_HqcKey_export_public_key(HqcKey *key, byte *out, word32 len) {
    word32 pubKeyLen = 0;
    if ((key == NULL) || (out == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }

    if (wc_HqcKey_PublicKeySize(key, &pubKeyLen) != 0) {
        WOLFSSL_MSG("Failed to get HQC pubKey size");
        return BAD_FUNC_ARG;
    }
    if (len < pubKeyLen) {
        WOLFSSL_MSG_EX("Need %d bytes, given %d bytes", pubKeyLen, len);
        return BUFFER_E;
    }
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->pubKey, pubKeyLen);

    return 0;
}

int wc_HqcKey_PublicKeyToDer(HqcKey *key, byte *out, word32 len, int withAlg) {
    (void)key;
    (void)out;
    (void)len;
    (void)withAlg;
    return NOT_COMPILED_IN;
}

int wc_HqcKey_PrivateKeyToDer(HqcKey *key, byte *out, word32 len) {
    (void)key;
    (void)out;
    (void)len;
    return NOT_COMPILED_IN;
}

int wc_HqcKey_DerToPrivateKey(HqcKey *key, byte *in, word32 len) {
    (void)key;
    (void)in;
    (void)len;
    return NOT_COMPILED_IN;
}
