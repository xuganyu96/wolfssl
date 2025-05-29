#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/pqclean_mlkem.h"
#include <wolfssl/kemtls.h>
#include <wolfssl/wolfcrypt/logging.h>

/* Construct and send client's KemCiphertext message. The body of the message
 * contains the raw ciphertext, which is generated at ProcessPeerCerts
 */
static int SendKemTlsClientKemCiphertext(WOLFSSL *ssl) {
    WOLFSSL_ENTER("SendKemTlsClientKemCiphertext");
    int ret;

    byte *output; /* output points to the start of the record */
    byte *input;  /* input points to the start of the handshake msg (i.e. the
                     fragment) */
    int sendSz, outputSz;
    enum HandShakeType hsType = client_key_exchange;

    if ((ssl->kemCiphertext == NULL) || (ssl->kemCiphertextSz == 0)) {
        WOLFSSL_MSG("GYX: KEM ciphertext is missing");
        return BAD_FUNC_ARG;
    }

    outputSz = ssl->kemCiphertextSz + MAX_MSG_EXTRA;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0) {
        WOLFSSL_MSG_EX("GYX: output buffer size insufficient, need %d",
                       outputSz);
        return ret;
    }

    output =
        ssl->buffers.outputBuffer.buffer + ssl->buffers.outputBuffer.length;
    input = output + RECORD_HEADER_SZ;
    AddTls13Headers(output, ssl->kemCiphertextSz, hsType, ssl);
    XMEMCPY(input + HANDSHAKE_HEADER_SZ, ssl->kemCiphertext,
            ssl->kemCiphertextSz);
    sendSz = BuildTls13Message(ssl, output, outputSz, input,
                               HANDSHAKE_HEADER_SZ + ssl->kemCiphertextSz,
                               handshake, 1, 0, 0);
    if (sendSz < 0) {
        return BUILD_MSG_ERROR;
    }

    /* GYX: ignore the callback section for now */

    ssl->buffers.outputBuffer.length += sendSz;
    if (ssl->options.groupMessages) {
        WOLFSSL_MSG(
            "GYX: delay sending ClientKemCiphertext because groupMessages");
        WOLFSSL_LEAVE("SendKemTlsClientKemCiphertext", ret);
        return ret;
    }
    ret = SendBuffered(ssl);
    if (ret != 0 && ret != WANT_WRITE) {
        WOLFSSL_LEAVE("SendKemTlsClientKemCiphertext", ret);
        return ret;
    }

    WOLFSSL_LEAVE("SendKemTlsClientKemCiphertext", ret);
    return ret;
}

int accept_KEMTLS(WOLFSSL *ssl) {
    WOLFSSL_ENTER("accept_KEMTLS");
    int ret = NOT_COMPILED_IN;

    WOLFSSL_LEAVE("accept_KEMTLS", ret);
    return ret;
}

/* Handle client workflow in KEMTLS handshake after processing server
 * certificates
 *
 * ssl->error will be assigned OUTSIDE this function; do not assign to
 * ssl->error
 */
int connect_KEMTLS(WOLFSSL *ssl) {
    WOLFSSL_ENTER("connect_KEMTLS");
    int ret;

    if ((ret = SendKemTlsClientKemCiphertext(ssl)) != 0) {
        return ret;
    }
    ssl->options.connectState = CLIENT_KEM_CIPHERTEXT_SENT;
    WOLFSSL_MSG("connectState: CLIENT_KEM_CIPHERTEXT_SENT");

    /* GYX: next we need to handle server's Finished */

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
