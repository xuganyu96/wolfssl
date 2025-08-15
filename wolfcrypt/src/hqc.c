#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/hqc.h>

#ifdef CLEAN_HQC
#include <common/randombytes.h>
#endif

int wc_HqcKey_Init(HqcKey *key) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(key, 0, sizeof(*key));
    return 0;
}

int wc_HqcKey_Free(HqcKey *key) {
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(key, 0, sizeof(*key));
    return 0;
}

static int is_valid_level(int level) {
    return (level == 1) || (level == 3) || (level == 5);
}

int wc_HqcKey_SetLevel(HqcKey *key, int level) {
    if ((key == NULL) || (!is_valid_level(level))) {
        return BAD_FUNC_ARG;
    }
    key->level = level;
    return 0;
}

int wc_HqcKey_GetLevel(HqcKey *key, int *level) {
    if ((key == NULL) || (level == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    *level = key->level;
    return 0;
}

int wc_HqcKey_PublicKeySize(HqcKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = HQC_LEVEL1_PUBKEY_SIZE;
        break;
    case 3:
        *len = HQC_LEVEL3_PUBKEY_SIZE;
        break;
    case 5:
        *len = HQC_LEVEL5_PUBKEY_SIZE;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    return 0;
}
int wc_HqcKey_PrivateKeySize(HqcKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = HQC_LEVEL1_PRIVKEY_SIZE;
        break;
    case 3:
        *len = HQC_LEVEL3_PRIVKEY_SIZE;
        break;
    case 5:
        *len = HQC_LEVEL5_PRIVKEY_SIZE;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    return 0;
}
int wc_HqcKey_CiphertextSize(HqcKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = HQC_LEVEL1_CIPHERTEXT_SIZE;
        break;
    case 3:
        *len = HQC_LEVEL3_CIPHERTEXT_SIZE;
        break;
    case 5:
        *len = HQC_LEVEL5_CIPHERTEXT_SIZE;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    return 0;
}

int wc_HqcKey_SharedSecretSize(HqcKey *key, word32 *len) {
    if ((key == NULL) || (len == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
    switch (key->level) {
    case 1:
        *len = HQC_LEVEL1_SHAREDSECRET_SIZE;
        break;
    case 3:
        *len = HQC_LEVEL3_SHAREDSECRET_SIZE;
        break;
    case 5:
        *len = HQC_LEVEL5_SHAREDSECRET_SIZE;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    return 0;
}

int wc_HqcKey_MakeKey(HqcKey *key, WC_RNG *rng) {
    if ((key == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level)) {
        return BAD_FUNC_ARG;
    }
#ifdef CLEAN_HQC
    set_wc_rng(rng);

    switch (key->level) {
    case 1:
        PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(key->pubkey, key->privkey);
        break;
    case 3:
        PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(key->pubkey, key->privkey);
        break;
    case 5:
        PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(key->pubkey, key->privkey);
        break;
    default:
        return BAD_FUNC_ARG;
    }
    key->pubkey_set = 1;
    key->privkey_set = 1;
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}

/* Encapsulate a HQC secret.
 *
 * User is responsible for making sure ct and ss have enough capacity.
 *
 * return:
 * BAD_FUNC_ARG     If necessary pointer is NULL; if key->level is invalid; if
 *                  key->pubkey is not set
 */
int wc_HqcKey_Encapsulate(HqcKey *key, byte *ct, byte *ss, WC_RNG *rng) {
    if (!key || !ct || !ss || !rng) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level) || !key->pubkey_set) {
        return BAD_FUNC_ARG;
    }

#ifdef CLEAN_HQC
    set_wc_rng(rng);
    switch (key->level) {
    case 1:
        PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, key->pubkey);
        break;
    case 3:
        PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ct, ss, key->pubkey);
        break;
    case 5:
        PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss, key->pubkey);
        break;
    default:
        return BAD_FUNC_ARG;
    }
#else
    return NOT_COMPILED_IN;
#endif

    return 0;
}

/* User is responsible for ensuring that `ss` has enough capacity to hold shared
 * secret
 */
int wc_HqcKey_Decapsulate(HqcKey *key, byte *ss, const byte *ct, word32 len) {
    int ret;
    word32 ctLen;
    if (!key || !ss || !ct) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level) || !key->privkey_set) {
        WOLFSSL_MSG("HQC key level is invalid, or missing private key");
        return BAD_FUNC_ARG;
    }
    if ((ret = wc_HqcKey_CiphertextSize(key, &ctLen)) < 0) {
        return ret;
    }
    if (ctLen > len) {
        return BUFFER_E;
    }

#ifdef CLEAN_HQC
    switch (key->level) {
    case 1:
        PQCLEAN_HQC128_CLEAN_crypto_kem_dec(ss, ct, key->privkey);
        break;
    case 3:
        PQCLEAN_HQC192_CLEAN_crypto_kem_dec(ss, ct, key->privkey);
        break;
    case 5:
        PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss, ct, key->privkey);
        break;
    default:
        return BAD_FUNC_ARG; /* should not happen! */
    }
#else
    return NOT_COMPILED_IN;
#endif

    return 0;
}

int wc_HqcKey_ExportPublicKey(HqcKey *key, byte *buf, word32 len) {
    if ((key == NULL) || (buf == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!key->pubkey_set) {
        WOLFSSL_MSG("HQC public key not set");
        return BAD_FUNC_ARG;
    }
    word32 cplen;
    int ret = wc_HqcKey_PublicKeySize(key, &cplen);
    if (ret < 0) {
        return ret;
    }
    if (len < cplen) {
        WOLFSSL_MSG_EX("Need %d bytes, found %d bytes", cplen, len);
        return BUFFER_E;
    }
    XMEMCPY(buf, key->pubkey, cplen);
    return 0;
}

int wc_HqcKey_ExportPrivateKey(HqcKey *key, byte *buf, word32 len) {
    if ((key == NULL) || (buf == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (!key->privkey_set) {
        WOLFSSL_MSG("HQC private key not set");
        return BAD_FUNC_ARG;
    }
    word32 cplen;
    int ret = wc_HqcKey_PrivateKeySize(key, &cplen);
    if (ret < 0) {
        return ret;
    }
    if (len < cplen) {
        WOLFSSL_MSG_EX("Need %d bytes, found %d bytes", cplen, len);
        return BUFFER_E;
    }
    XMEMCPY(buf, key->privkey, cplen);
    return 0;
}

/* Copy public key bytes from input buffer to key->pubkey
 *
 * return:
 * BAD_FUNC_ARG if any pointer is NULL, if key's level is not set, or if key's
 *              public key is already set
 * BUFFER_E     if input buffer len does not match expected public key length
 */
int wc_HqcKey_ImportPublicKey(HqcKey *key, byte *buf, word32 len) {
    if (!key || !buf) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level) || key->pubkey_set) {
        return BAD_FUNC_ARG;
    }
    int ret;
    word32 pubKeyLen;
    if ((ret = wc_HqcKey_PublicKeySize(key, &pubKeyLen)) < 0) {
        return ret;
    }
    if (pubKeyLen != len) {
        return BUFFER_E;
    }
    XMEMCPY(key->pubkey, buf, len);
    key->pubkey_set = 1;

    return 0;
}

int wc_HqcKey_ImportPrivateKey(HqcKey *key, byte *buf, word32 len) {
    if (!key || !buf) {
        return BAD_FUNC_ARG;
    }
    if (!is_valid_level(key->level) || key->privkey_set) {
        WOLFSSL_MSG("Invalid level, or private key already set");
        return BAD_FUNC_ARG;
    }
    int ret;
    word32 privKeyLen;
    if ((ret = wc_HqcKey_PrivateKeySize(key, &privKeyLen)) < 0) {
        return ret;
    }
    if (privKeyLen > len) {
        return BUFFER_E;
    }
    XMEMCPY(key->privkey, buf, privKeyLen);
    key->privkey_set = 1;

    return 0;
}
