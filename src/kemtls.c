#include "wolfssl/wolfcrypt/pqclean_mlkem.h"
#include <wolfssl/kemtls.h>
#include <wolfssl/wolfcrypt/logging.h>

static int SendKemTlsClientKemCiphertext(WOLFSSL *ssl) {
    return NOT_COMPILED_IN;
}

int accept_KEMTLS(WOLFSSL *ssl) {
    WOLFSSL_ENTER("accept_KEMTLS");
    int ret = NOT_COMPILED_IN;

    WOLFSSL_LEAVE("accept_KEMTLS", ret);
    return ret;
}

int connect_KEMTLS(WOLFSSL *ssl) {
    WOLFSSL_ENTER("connect_KEMTLS");

    int ret;
    ret = SendKemTlsClientKemCiphertext(ssl);

    WOLFSSL_LEAVE("connect_KEMTLS", ret);
    return ret;
}

/* Handle a peer certificate that contains a PQCleanMlKemKey public key
 *
 * This includes allocating for a PQCleanMlKemKey object, loading the public key
 * from the certificate, allocating for ciphertext/shared secret, and
 * encapsulating
 */
int handle_PQCleanMlKemKey_cert(WOLFSSL *ssl, DecodedCert *cert) {
    WOLFSSL_ENTER("handle_PQCleanMlKemKey_cert");
    int ret, level;

    if (ssl->peerMlKemKey == NULL) {
        ret = AllocKey(ssl, DYNAMIC_TYPE_MLKEM, (void **)&ssl->peerMlKemKey);
    } else if (ssl->peerMlKemKeyPresent) {
        WOLFSSL_MSG("GYX: Reusing peerMlKemKey is not implemented");
        ret = NOT_COMPILED_IN;
    } else {
        WOLFSSL_MSG("GYX: UNREACHABLE!");
        ret = NOT_COMPILED_IN;
    }

    if (ret == 0) {
        if (cert->keyOID == ML_KEM_LEVEL1k) {
            ret = wc_PQCleanMlKemKey_SetLevel(ssl->peerMlKemKey, (level = 1));
        } else if (cert->keyOID == ML_KEM_LEVEL3k) {
            ret = wc_PQCleanMlKemKey_SetLevel(ssl->peerMlKemKey, (level = 3));
        } else if (cert->keyOID == ML_KEM_LEVEL5k) {
            ret = wc_PQCleanMlKemKey_SetLevel(ssl->peerMlKemKey, (level = 5));
        } else {
            /* GYX: UNREACHABLE! */
        }
    }

    if (ret == 0) {
        WOLFSSL_MSG_EX("GYX: pubKeyLen=%d, level=%d", cert->pubKeySize, level);
        ret = wc_PQCleanMlKemKey_DecodePublicKey(
            ssl->peerMlKemKey, cert->publicKey, cert->pubKeySize);
    }

    if (ret == 0) { /* pubKey is good, allocate ciphertext/shared secret */
        ret = wc_PQCleanMlKemKey_CipherTextSize(ssl->peerMlKemKey,
                                                &ssl->kemCiphertextSz);
        if (ret == 0) {
            WOLFSSL_MSG_EX("GYX: ctLen=%d", ssl->kemCiphertextSz);
            ssl->kemCiphertext =
                XMALLOC(ssl->kemCiphertextSz, ssl->heap, DYNAMIC_TYPE_KEMCT);
            if (ssl->kemCiphertext == NULL) {
                /* GYX: need to free PQCleanMlKemKey */
                ret = MEMORY_E;
            }
        }

        ret = wc_PQCleanMlKemKey_SharedSecretSize(ssl->peerMlKemKey,
                                                  &ssl->kemSharedSecretSz);
        if (ret == 0) {
            WOLFSSL_MSG_EX("GYX: ssLen=%d", ssl->kemSharedSecretSz);
            ssl->kemSharedSecret =
                XMALLOC(ssl->kemSharedSecretSz, ssl->heap, DYNAMIC_TYPE_KEMSS);
            if (ssl->kemSharedSecret == NULL) {
                /* GYX: need to free both key and ciphertext */
                ret = MEMORY_E;
            }
        }
    }

    if (ret == 0) { /* pk, ct, ss ready; encapsulate */
        ret = wc_PQCleanMlKemKey_Encapsulate(ssl->peerMlKemKey,
                                             ssl->kemCiphertext,
                                             ssl->kemSharedSecret, ssl->rng);
    }

    if (ret == 0) {
        WOLFSSL_MSG("GYX: handled peer ML-KEM key");
        ssl->peerMlKemKeyPresent = 1;
        ssl->options.haveMlKemAuth = 1;
    }
    WOLFSSL_LEAVE("handle_PQCleanMlKemKey_cert", ret);
    return ret;
}

int handle_PQCleanHqcKey_cert(WOLFSSL *ssl, DecodedCert *cert) {
    return NOT_COMPILED_IN;
}
