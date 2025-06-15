#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/otmlkem.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#include <common/randombytes.h>

int wc_OtMlKemKey_Init(OtMlKemKey *key) {
    return wc_OtMlKemKey_InitEx(key, NULL, INVALID_DEVID);
}

/* public and private keys are stack allocated, no need to use heap */
int wc_OtMlKemKey_InitEx(OtMlKemKey *key, void *heap, int devId) {
    (void)heap;
    (void)devId;
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(key, 0, sizeof(OtMlKemKey));
    return 0;
}

/* Clear all data from key. Similar to Init, but this function will never fail
 */
int wc_OtMlKemKey_Free(OtMlKemKey *key) {
    if (key != NULL) {
        XMEMSET(key, 0, sizeof(OtMlKemKey));
    }
    return 0;
}

/* Return 1 if level is valid */
static int is_valid_level(int level) {
    return (level == 1) || (level == 3) || (level == 5);
}

int wc_OtMlKemKey_SetLevel(OtMlKemKey *key, int level) {
    if ((key == NULL) || !is_valid_level(level)) {
        return BAD_FUNC_ARG;
    }
    key->level = level;
    return 0;
}

int wc_OtMlKemKey_GetLevel(OtMlKemKey *key, int *level) {
    if ((NULL == key) || (NULL == level)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    *level = key->level;
    return 0;
}

int wc_OtMlKemKey_MakeKey(OtMlKemKey *key, WC_RNG *rng) {
    int ret = 0;

    if ((NULL == key) || (NULL == rng))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;

    PQCLEAN_set_wc_rng(rng);
    switch (key->level) {
    case 1:
        ret =
            PQCLEAN_OTMLKEM512_CLEAN_crypto_kem_keypair(key->pubKey, key->privKey);
        break;
    case 3:
        ret =
            PQCLEAN_OTMLKEM768_CLEAN_crypto_kem_keypair(key->pubKey, key->privKey);
        break;
    case 5:
        ret =
            PQCLEAN_OTMLKEM1024_CLEAN_crypto_kem_keypair(key->pubKey, key->privKey);
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
    return ret;
}

int wc_OtMlKemKey_CipherTextSize(OtMlKemKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_OTMLKEM_LEVEL1_CIPHERTEXT_SIZE;
        break;
    case 3:
        *len = PQCLEAN_OTMLKEM_LEVEL3_CIPHERTEXT_SIZE;
        break;
    case 5:
        *len = PQCLEAN_OTMLKEM_LEVEL5_CIPHERTEXT_SIZE;
        break;
    }
    return 0;
}

int wc_OtMlKemKey_SharedSecretSize(OtMlKemKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_OTMLKEM_LEVEL1_SHAREDSECRET_SIZE;
        break;
    case 3:
        *len = PQCLEAN_OTMLKEM_LEVEL3_SHAREDSECRET_SIZE;
        break;
    case 5:
        *len = PQCLEAN_OTMLKEM_LEVEL5_SHAREDSECRET_SIZE;
        break;
    }
    return 0;
}

int wc_OtMlKemKey_Encapsulate(OtMlKemKey *key, byte *ct, byte *ss, WC_RNG *rng) {
    int ret = 0;
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }
    PQCLEAN_set_wc_rng(rng);
    switch (key->level) {
    case 1:
        ret = PQCLEAN_OTMLKEM512_CLEAN_crypto_kem_enc(ct, ss, key->pubKey);
        break;
    case 3:
        ret = PQCLEAN_OTMLKEM768_CLEAN_crypto_kem_enc(ct, ss, key->pubKey);
        break;
    case 5:
        ret = PQCLEAN_OTMLKEM1024_CLEAN_crypto_kem_enc(ct, ss, key->pubKey);
        break;
        /* level already validated */
    }
    if (ret == 0) {
        return ret;
    }
    ret = BAD_FUNC_ARG;
    return ret;
}

int wc_OtMlKemKey_Decapsulate(OtMlKemKey *key, byte *ss, const byte *ct, word32 len) {
    int ret = 0;
    word32 ctLen = 0;

    if ((key == NULL) || (ss == NULL) || (ct == NULL))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (!key->privKeySet)
        return MISSING_KEY;
    ret = wc_OtMlKemKey_CipherTextSize(key, &ctLen);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to get OT-ML-KEM ciphertext size");
        return BAD_FUNC_ARG;
    }
    if (len < ctLen) {
        WOLFSSL_MSG_EX("Need %d bytes of ct buf, given %d", ctLen, len);
        return BUFFER_E;
    }

    switch (key->level) {
    case 1:
        ret = PQCLEAN_OTMLKEM512_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
        break;
    case 3:
        ret = PQCLEAN_OTMLKEM768_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
        break;
    case 5:
        ret = PQCLEAN_OTMLKEM1024_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
        break;
        /* level already validated */
    }

    if (ret != 0)
        ret = BAD_FUNC_ARG;
    return ret;
}

int wc_OtMlKemKey_import_private(OtMlKemKey *key, const byte *in, word32 len) {
    int ret = 0;
    word32 privKeyLen = 0;
    if ((key == NULL) || (in == NULL))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (key->privKeySet) {
        WOLFSSL_MSG("OT-ML-KEM priv key already set");
        return BAD_FUNC_ARG;
    }
    ret = wc_OtMlKemKey_PrivateKeySize(key, &privKeyLen);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to get OT-ML-KEM private key size");
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

int wc_OtMlKemKey_import_public(OtMlKemKey *key, const byte *in, word32 len) {
    int ret = 0;
    word32 pubKeyLen = 0;
    if ((key == NULL) || (in == NULL))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    if (key->pubKeySet) {
        WOLFSSL_MSG("OT-ML-KEM pub key already set");
        return BAD_FUNC_ARG;
    }
    ret = wc_OtMlKemKey_PublicKeySize(key, &pubKeyLen);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to get OT-ML-KEM public key size");
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

int wc_OtMlKemKey_PrivateKeySize(OtMlKemKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_OTMLKEM_LEVEL1_SECRETKEY_SIZE;
        break;
    case 3:
        *len = PQCLEAN_OTMLKEM_LEVEL3_SECRETKEY_SIZE;
        break;
    case 5:
        *len = PQCLEAN_OTMLKEM_LEVEL5_SECRETKEY_SIZE;
        break;
    }
    return 0;
}

int wc_OtMlKemKey_PublicKeySize(OtMlKemKey *key, word32 *len) {
    if ((NULL == key) || (NULL == len))
        return BAD_FUNC_ARG;
    if (!is_valid_level(key->level))
        return BAD_FUNC_ARG;
    switch (key->level) {
    case 1:
        *len = PQCLEAN_OTMLKEM_LEVEL1_PUBLICKEY_SIZE;
        break;
    case 3:
        *len = PQCLEAN_OTMLKEM_LEVEL3_PUBLICKEY_SIZE;
        break;
    case 5:
        *len = PQCLEAN_OTMLKEM_LEVEL5_PUBLICKEY_SIZE;
        break;
    }
    return 0;
}

int wc_OtMlKemKey_export_private_key(OtMlKemKey *key, byte *out, word32 len) {
    word32 privKeyLen = 0;
    if ((key == NULL) || (out == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }

    if (wc_OtMlKemKey_PrivateKeySize(key, &privKeyLen) != 0) {
        WOLFSSL_MSG("Failed to get OT-ML-KEM privKey size");
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

int wc_OtMlKemKey_export_public_key(OtMlKemKey *key, byte *out, word32 len) {
    word32 pubKeyLen = 0;
    if ((key == NULL) || (out == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }

    if (wc_OtMlKemKey_PublicKeySize(key, &pubKeyLen) != 0) {
        WOLFSSL_MSG("Failed to get OT-ML-KEM pubKey size");
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
