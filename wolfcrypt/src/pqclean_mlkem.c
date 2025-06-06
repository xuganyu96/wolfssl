#include <wolfssl/wolfcrypt/settings.h>
#ifdef PQCLEAN_MLKEM

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/oid_sum.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <common/randombytes.h>

static int is_valid_level(int level) {
    return ((level == 1) || (level == 3) || (level == 5));
}

int wc_PQCleanMlKemKey_Init(PQCleanMlKemKey *key) {
    return wc_PQCleanMlKemKey_InitEx(key, NULL, INVALID_DEVID);
}

/* TODO: For now heap and devId are ignored */
/* TODO: need to incorporate heap/devId */
int wc_PQCleanMlKemKey_InitEx(PQCleanMlKemKey *key, void *heap, int devId) {
    (void)heap;
    (void)devId;
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(key, 0, sizeof(PQCleanMlKemKey));
    return 0;
}

int wc_PQCleanMlKemKey_SetLevel(PQCleanMlKemKey *key, int level) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(level)) {
        return BAD_FUNC_ARG;
    }
    key->level = level;
    return 0;
}

int wc_PQCleanMlKemKey_GetLevel(PQCleanMlKemKey *key, int *level) {
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
int wc_PQCleanMlKemKey_Free(PQCleanMlKemKey *key) {
    if (key != NULL) {
        XMEMSET(key, 0, sizeof(PQCleanMlKemKey));
    }
    return 0;
}

int wc_PQCleanMlKemKey_MakeKey(PQCleanMlKemKey *key, WC_RNG *rng) {
    if ((key == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    int wc_err, pqclean_err;
    PQCLEAN_set_wc_rng(rng);
    if (key->level == 1) {
        pqclean_err = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(key->pubKey,
                                                                key->privKey);
    } else if (key->level == 3) {
        pqclean_err = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(key->pubKey,
                                                                key->privKey);
    } else { /* key->level must be 5 */
        pqclean_err = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(key->pubKey,
                                                                 key->privKey);
    }
    if (pqclean_err == 0) {
        key->pubKeySet = 1;
        key->privKeySet = 1;
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

int wc_PQCleanMlKemKey_CipherTextSize(PQCleanMlKemKey *key, word32 *len) {
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

int wc_PQCleanMlKemKey_SharedSecretSize(PQCleanMlKemKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    *len = PQCLEAN_MLKEM_SS_SIZE;
    return 0;
}

int wc_PQCleanMlKemKey_Encapsulate(PQCleanMlKemKey *key, byte *ct, byte *ss,
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
    int wc_err, pqclean_err;
    PQCLEAN_set_wc_rng(rng);
    if (key->level == 1) {
        pqclean_err = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(
            ct, ss, key->pubKey);
    } else if (key->level == 3) {
        pqclean_err = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(
            ct, ss, key->pubKey);
    } else { /* key->level == 5 */
        pqclean_err = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(
            ct, ss, key->pubKey);
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

int wc_PQCleanMlKemKey_Decapsulate(PQCleanMlKemKey *key, byte *ss,
                                   const byte *ct, word32 len) {
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
    wc_PQCleanMlKemKey_CipherTextSize(key, &expected_ctlen);
    if (len != expected_ctlen) { /* ciphertext length is incorrect */
        return BUFFER_E;
    }

    int wc_err, pqclean_err;
    if (key->level == 1) {
        pqclean_err =
            PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
    } else if (key->level == 3) {
        pqclean_err =
            PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
    } else { /* key->level == 5 */
        pqclean_err =
            PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, key->privKey);
    }
    wc_err = (pqclean_err == 0) ? 0 : WC_FAILURE;
    return wc_err;
}

int wc_PQCleanMlKemKey_DecodePrivateKey(PQCleanMlKemKey *key, const byte *in,
                                        word32 len) {
    int ret = 0;
    word32 PrivKeyLen = 0;

    if ((key == NULL) || (in == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((ret = wc_PQCleanMlKemKey_PrivateKeySize(key, &PrivKeyLen)) != 0) {
        return ret;
    }
    if (PrivKeyLen != len) {
        return BUFFER_E;
    }
    if (key->privKeySet) {
        WOLFSSL_MSG("PQCleanMlKemKey->privKey is already set");
        return BAD_FUNC_ARG;
    }
    XMEMCPY(key->privKey, in, len);
    key->privKeySet = 1;

    return ret;
}

int wc_PQCleanMlKemKey_DecodePublicKey(PQCleanMlKemKey *key, const byte *in,
                                       word32 len) {
    int ret = 0;
    word32 pubKeyLen = 0;

    if ((key == NULL) || (in == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((ret = wc_PQCleanMlKemKey_PublicKeySize(key, &pubKeyLen)) != 0) {
        return ret;
    }
    if (pubKeyLen != len) {
        return BUFFER_E;
    }
    if (key->pubKeySet) {
        WOLFSSL_MSG("PQCleanMlKemKey->pubKey is already set");
        return PUBLIC_KEY_E;
    }
    XMEMCPY(key->pubKey, in, len);
    key->pubKeySet = 1;

    return ret;
}

int wc_PQCleanMlKemKey_PrivateKeySize(PQCleanMlKemKey *key, word32 *len) {
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

int wc_PQCleanMlKemKey_PublicKeySize(PQCleanMlKemKey *key, word32 *len) {
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

/* Treat PQClean KEM as black boxes; encoding simply means copying bytes from
 * the key obj to the input buffer
 */
int wc_PQCleanMlKemKey_EncodePrivateKey(PQCleanMlKemKey *key, byte *out,
                                        word32 len) {
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
    if (!key->privKeySet) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->privKey, privKeyLen);

    return ret;
}

int wc_PQCleanMlKemKey_EncodePublicKey(PQCleanMlKemKey *key, byte *out,
                                       word32 len) {
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
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }
    XMEMCPY(out, key->pubKey, pubKeyLen);

    return ret;
}

/* Copy public key bytes to the output buffer. `len` should contains the
 * capacity of the output buffer at function call, but will be filled with the
 * length of the actual data after return.
 *
 * If `out` is NULL, then `len` will be filled with the expected length
 *
 * Return 0 on success.
 *
 * TODO: this is very similar to EncodePublicKey, maybe it's better to switch
 * into one function
 */
static int export_public(PQCleanMlKemKey *key, byte *out, word32 *len) {
    int ret;
    word32 pubKeyLen;

    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!key->pubKeySet) {
        return MISSING_KEY;
    }

    if ((ret = wc_PQCleanMlKemKey_PublicKeySize(key, &pubKeyLen)) != 0) {
        return ret;
    }

    if (out == NULL) { /* do not write pubkey; only update length */
        *len = pubKeyLen;
        return ret;
    } else if (*len < pubKeyLen) { /* not enough space */
        return BUFFER_E;
    } else {
        memcpy(out, key->pubKey, pubKeyLen);
        *len = pubKeyLen;
    }

    return ret;
}

#ifdef WOLFSSL_HAVE_KEMTLS
/* write the OID sum to `oid`.
 *
 * Return 0 on success
 */
static int get_oid_sum(PQCleanMlKemKey *key, enum Key_Sum *oid) {
    if ((key == NULL) || (oid == NULL)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *oid = ML_KEM_LEVEL1k;
        break;
    case 3:
        *oid = ML_KEM_LEVEL3k;
        break;
    case 5:
        *oid = ML_KEM_LEVEL5k;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    return 0;
}

/* Encode ML-KEM public key according to DER
 *
 * Pass NULL for ouptut to get the size of the encoding
 *
 * Return 0 upon success
 */
int wc_PQCleanMlKemKey_PublicKeyToDer(PQCleanMlKemKey *key, byte *out,
                                      word32 len, int withAlg) {
    int ret;
    byte pubKey[PQCLEAN_MLKEM_MAX_PUBLICKEY_SIZE];
    word32 pubKeyLen = (word32)sizeof(pubKey);
    enum Key_Sum oid; /* actually the OID sum but whatever */

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((ret = get_oid_sum(key, &oid)) < 0) {
        return ret;
    }

    ret = export_public(key, pubKey, &pubKeyLen);
    if (ret == 0) {
        ret = SetAsymKeyDerPublic(pubKey, pubKeyLen, out, len, oid, withAlg);
    }

    return ret;
}

/* Enocde ML-KEM private key according to DER
 *
 * Return 0 upon success
 */
int wc_PQCleanMlKemKey_PrivateKeyToDer(PQCleanMlKemKey *key, byte *out,
                                       word32 len) {
    int ret = 0;
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!key->privKeySet) {
        return MISSING_KEY;
    }
    word32 privKeyLen;
    enum Key_Sum oid;
    if ((ret = wc_PQCleanMlKemKey_PrivateKeySize(key, &privKeyLen)) < 0) {
        return ret;
    }
    if ((ret = get_oid_sum(key, &oid)) < 0) {
        return ret;
    }
    ret = SetAsymKeyDer(key->privKey, privKeyLen, NULL, 0, out, len, oid);

    return ret;
}

static int mapOidToSecLevel(int keyType) {
    switch (keyType) {
    case ML_KEM_LEVEL1k:
        return 1;
    case ML_KEM_LEVEL3k:
        return 3;
    case ML_KEM_LEVEL5k:
        return 5;
    default:
        return BAD_FUNC_ARG;
    }
}

int wc_PQCleanMlKemKey_DerToPrivateKey(const byte *input, word32 *inOutIdx,
                                       PQCleanMlKemKey *key, word32 inSz) {
    WOLFSSL_ENTER("wc_PQCleanMlKemKey_DerToPrivateKey");
    int ret = 0;
    int keytype; /* enum Key_Sum */
    const byte *privKey = NULL;
    const byte *pubKey = NULL;
    word32 privKeyLen = 0, pubKeyLen = 0;

    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        return BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (key->level == 0) {
            /* level not set by caller, decode from DER */
            keytype = ANONk;
            WOLFSSL_MSG_EX("keytype is ANONk");
        } else {
            /* TODO: need to cover the case where key level is set by caller
             * and the DER buffer needs to be parsed with expectation
             */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = DecodeAsymKey_Assign(input, inOutIdx, inSz, &privKey, &privKeyLen,
                                   &pubKey, &pubKeyLen, &keytype);
        WOLFSSL_LEAVE("DecodeAsymKey_Assign", ret);
        if (ret == 0) {
            ret = mapOidToSecLevel(keytype);
            if (ret > 0) {
                ret = wc_PQCleanMlKemKey_SetLevel(key, ret);
            }
        }
    }

    if (ret == 0) {
        /* copy private key to the key object */
        ret = wc_PQCleanMlKemKey_DecodePrivateKey(key, privKey, privKeyLen);
        WOLFSSL_MSG_EX("PQCleanMlKemKey->level is %d, privKeyLen %d",
                       key->level, privKeyLen);
    }

    WOLFSSL_LEAVE("wc_PQCleanMlKemKey_DerToPrivateKey", ret);
    return ret;
}

int wc_PQCleanMlKemKey_get_oid_sum(PQCleanMlKemKey *key, enum Key_Sum *oid) {
    if (key == NULL || oid == NULL) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *oid = ML_KEM_LEVEL1k;
        break;
    case 3:
        *oid = ML_KEM_LEVEL3k;
        break;
    case 5:
        *oid = ML_KEM_LEVEL5k;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    return 0;
}
#endif /* WOLFSSL_HAVE_KEMTLS */

#endif /* PQCLEAN_MLKEM */
