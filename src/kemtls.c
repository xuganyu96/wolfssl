#include "wolfssl/internal.h"
#include <wolfssl/kemtls.h>
#include <wolfssl/wolfcrypt/logging.h>

/* Convert TLS mac ID to a hash algorithm ID
 *
 * mac Mac ID to convert
 * returns hash ID on success, or the NONE type.
 *
 * Shamelessly copied from Gonzalez et al.
 */
static WC_INLINE int mac2hash(int mac) {
    int hash;
    switch (mac) {
#ifndef NO_SHA256
    case sha256_mac:
        hash = WC_SHA256;
        break;
#endif

#ifdef WOLFSSL_SHA384
    case sha384_mac:
        hash = WC_SHA384;
        break;
#endif

#ifdef WOLFSSL_TLS13_SHA512
    case sha512_mac:
        hash = WC_SHA512;
        break;
#endif
    default:
        hash = WC_HASH_TYPE_NONE;
    }
    return hash;
}

static void dump_hex(byte *data, word32 len) {
    if (len == 0 || data == NULL)
        return;
    fprintf(stderr, "GYX: Dump (%5d bytes): ", len);

    if (len <= 24) { /* print the whole thing */
        for (word32 i = 0; i < len; i++) {
            fprintf(stderr, "%02x", data[i]);
            if (i + 1 < len) {
                fprintf(stderr, ":");
            }
        }
        fprintf(stderr, "\n");
        return;
    }
    /* print the first and the last a few bytes */
    int prefix_len = 8;
    for (int i = 0; i < prefix_len; i++) {
        fprintf(stderr, "%02x:", data[i]);
    }
    fprintf(stderr, "...");
    for (int i = len - prefix_len; i < len; i++) {
        fprintf(stderr, ":%02x", data[i]);
    }
    fprintf(stderr, "\n");
}

/* Construct and send client's KemCiphertext message, then derive all the
 * secrets that can be derived: dHS, AHS, dAHS, CAHTS, SAHTS, and MasterSecret.
 */
static int SendKemTlsClientKemCiphertext(WOLFSSL *ssl) {
    WOLFSSL_ENTER("SendKemTlsClientKemCiphertext");
    int ret;

    byte *output; /* output points to the start of the record */
    byte *input;  /* input points to the start of the handshake msg (i.e. the
                     fragment) */
    int sendSz, outputSz;
    int hashOutput = 1; /* include client's KemCiphertext in transcript hash */
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
                               handshake, hashOutput, 0, 0);
    if (sendSz < 0) {
        return BUILD_MSG_ERROR;
    }

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

    /* derive authenticated shared secret: implicit authentication */
    WOLFSSL_MSG("GYX: deriving various secrets");
    byte key_dHS[WC_MAX_DIGEST_SIZE]; /* derived handshake secret is the KEM
                                       * shared secret from the key exchange */
    static char derivedLabel[] = "derived";
    word32 labelLen = 7 + 1; /* strlen(label) plus null terminator */
    ret = DeriveKeyMsg(ssl, key_dHS, -1, ssl->arrays->preMasterSecret,
                       (byte *)derivedLabel, labelLen, NULL, 0,
                       ssl->specs.mac_algorithm);
    if (ret != 0) {
        WOLFSSL_MSG_EX("GYX: failed to obtain dHS (err=%d)", ret);
        return ret;
    }
    WOLFSSL_MSG_EX("GYX: mac_algorithm is %d", ssl->specs.mac_algorithm);
    WOLFSSL_MSG_EX("GYX: hash size is %d", ssl->specs.hash_size);
    dump_hex(key_dHS, ssl->specs.hash_size);

    /* ssl->arrays->preMasterSecret is AHS */
    ret = wc_Tls13_HKDF_Extract(ssl->arrays->preMasterSecret, key_dHS,
                                ssl->specs.hash_size, ssl->kemSharedSecret,
                                ssl->kemSharedSecretSz,
                                mac2hash(ssl->specs.mac_algorithm));
    if (ret != 0) {
        WOLFSSL_MSG_EX("GYX: failed to extract preMasterSecret (AHS) (err=%d)",
                       ret);
        return ret;
    }
    WOLFSSL_MSG_EX("GYX: preMasterSecret dump:");
    dump_hex(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);

    ret = DeriveTls13Keys(ssl, update_traffic_key, ENCRYPT_AND_DECRYPT_SIDE, 1);
    if (ret != 0) {
        WOLFSSL_MSG_EX("GYX: failed to derive CAHTS, SAHTS (err=%d)", ret);
        return ret;
    }

    ret = SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE);
    if (ret != 0) {
        WOLFSSL_MSG_EX("GYX: SetKeysSide returned %d", ret);
        return ret;
    }

    ret = DeriveMasterSecret(ssl);
    if (ret != 0) {
        WOLFSSL_MSG_EX("GYX: DeriveMasterSecret returned %d", ret);
        return ret;
    }
    WOLFSSL_MSG("GYX: MasterSecret dump:");
    dump_hex(ssl->arrays->masterSecret, sizeof(ssl->arrays->masterSecret));

    WOLFSSL_LEAVE("SendKemTlsClientKemCiphertext", ret);
    return ret;
}

/* Handle server workflow in KEMTLS handshake after sending a KEM certificate
 *
 * ssl->errror will be assigned outside this function; do not assign to
 * ssl->error
 */
int accept_KEMTLS(WOLFSSL *ssl) {
    WOLFSSL_ENTER("accept_KEMTLS");
    int ret;

    while (ssl->options.clientState < CLIENT_KEM_CIPHERTEXT_DONE) {
        ret = ProcessReply(ssl);
        if (ret != 0) {
            return ret;
        }
    }

    /* GYX: send server finish */
    ret = NOT_COMPILED_IN;

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

    if ((ret = SendTls13Finished(ssl)) != 0) {
        return ret;
    }
    ssl->options.connectState = CLIENT_KEM_FINISHED_SENT;
    WOLFSSL_MSG("connectState: CLIENT_KEM_FINISHED_SENT");

    /* GYX: next we need to handle server's Finished */
    ret = NOT_COMPILED_IN;

    WOLFSSL_LEAVE("connect_KEMTLS", ret);
    return ret;
}

/* Handle client's KemCiphertext.
 *
 * Client ciphertext is decapsulated using server's private key. The shared
 * secret will be stored on the ssl object to be used in Finish. Advance
 * acceptState
 *
 * KemCiphertext should contain raw ciphertext, so input[inOutIdx] should be the
 * begin of the ciphertext. If totalSz does not match the expected ciphertext
 * length then report error.
 */
int DoKemTlsClientKemCiphertext(WOLFSSL *ssl, byte *input, word32 *inOutIdx,
                                word32 totalSz) {
    WOLFSSL_ENTER("DoKemTlsClientKemCiphertext");
    int ret = 0;
    word32 idx = 0; /* read key buffer from beginning */
    word32 ctLen, ssLen;

    /* First allocate for key, then check for ciphertext size */
    WOLFSSL_MSG_EX("GYX: DoKemTlsClientKemCiphertext inOutIdx=%d", *inOutIdx);
    WOLFSSL_MSG_EX("GYX: ssl->buffers.keyType=%d", ssl->buffers.keyType);

    /* decode private key from ssl-buffer, set level, get expected ct size */
    switch (ssl->buffers.keyType) {
    case mlkem_level1_sa_algo:
    case mlkem_level3_sa_algo:
    case mlkem_level5_sa_algo:
        ssl->hsType = DYNAMIC_TYPE_MLKEM;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret == 0) {
            /* DerToPrivateKey will set level, do not set level manually */
            ret = wc_PQCleanMlKemKey_DerToPrivateKey(ssl->buffers.key->buffer,
                                                     &idx, ssl->hsKey,
                                                     ssl->buffers.key->length);
            if (ret != 0)
                WOLFSSL_MSG_EX("%s returned %d",
                               "wc_PQCleanMlKemKey_DecodePrivateKey", ret);
        }
        if (ret == 0) {
            ret = wc_PQCleanMlKemKey_CipherTextSize(ssl->hsKey, &ctLen);
        }
        if (ret == 0) {
            ret = wc_PQCleanMlKemKey_SharedSecretSize(ssl->hsKey, &ssLen);
        }
        break;
    case hqc_level1_sa_algo:
    case hqc_level3_sa_algo:
    case hqc_level5_sa_algo:
        ssl->hsType = DYNAMIC_TYPE_HQC;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret == 0) {
            ret = wc_PQCleanHqcKey_DerToPrivateKey(
                ssl->hsKey, ssl->buffers.key->buffer, ssl->buffers.key->length);
        }
        if (ret == 0) {
            ret = wc_PQCleanHqcKey_CipherTextSize(ssl->hsKey, &ctLen);
        }
        if (ret == 0) {
            ret = wc_PQCleanHqcKey_SharedSecretSize(ssl->hsKey, &ssLen);
        }
        break;
    default:
        ret = BAD_FUNC_ARG;
        WOLFSSL_MSG_EX("GYX: unsupported key type %d", ssl->buffers.keyType);
        return ret;
    }

    if (ret == 0) {
        if (ctLen != totalSz) {
            WOLFSSL_MSG_EX("GYX: expected ctLen=%d, input len=%d", ctLen,
                           totalSz);
            ret = BUFFER_E;
        }
    }

    /* allocate for kemCiphertext and kemSharedSecret */
    if (ret == 0) {
        ssl->kemCiphertext = XMALLOC(ctLen, ssl->heap, DYNAMIC_TYPE_KEMCT);
        if (!ssl->kemCiphertext) {
            ret = MEMORY_E;
        }
        XMEMCPY(ssl->kemCiphertext, input + *inOutIdx, ctLen);
        ssl->kemCiphertextSz = ctLen;
        ssl->kemSharedSecret = XMALLOC(ssLen, ssl->heap, DYNAMIC_TYPE_KEMSS);
        if (!ssl->kemSharedSecret) {
            ret = MEMORY_E;
        }
        ssl->kemSharedSecretSz = ssLen;
    }

    /* decapsulate */
    if (ret == 0) {
        switch (ssl->buffers.keyType) {
        case mlkem_level1_sa_algo:
        case mlkem_level3_sa_algo:
        case mlkem_level5_sa_algo:
            ret = wc_PQCleanMlKemKey_Decapsulate(
                ssl->hsKey, ssl->kemSharedSecret, ssl->kemCiphertext,
                ssl->kemCiphertextSz);
            break;
        case hqc_level1_sa_algo:
        case hqc_level3_sa_algo:
        case hqc_level5_sa_algo:
            ret = wc_PQCleanHqcKey_Decapsulate(ssl->hsKey, ssl->kemSharedSecret,
                                               ssl->kemCiphertext,
                                               ssl->kemCiphertextSz);
            break;
        default:
            WOLFSSL_MSG_EX("GYX: unsupported key type %d",
                           ssl->buffers.keyType);
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        WOLFSSL_MSG("GYX: server-side ciphertext");
        dump_hex(ssl->kemCiphertext, ssl->kemCiphertextSz);
        WOLFSSL_MSG("GYX: server-side shared secret");
        dump_hex(ssl->kemSharedSecret, ssl->kemSharedSecretSz);
        ssl->options.clientState = CLIENT_KEM_CIPHERTEXT_DONE;
        *inOutIdx += totalSz;
    }

    FreeKey(ssl, (int)ssl->hsType, &ssl->hsKey);
    WOLFSSL_LEAVE("DoKemTlsClientKemCiphertext", ret);
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
        WOLFSSL_MSG("GYX: client-side ciphertext");
        dump_hex(ssl->kemCiphertext, ssl->kemCiphertextSz);
        WOLFSSL_MSG("GYX: client-side shared secret");
        dump_hex(ssl->kemSharedSecret, ssl->kemSharedSecretSz);
        ssl->peerMlKemKeyPresent = 1;
        ssl->options.haveMlKemAuth = 1;
    }
    WOLFSSL_LEAVE("handle_PQCleanMlKemKey_cert", ret);
    return ret;
}

int handle_PQCleanHqcKey_cert(WOLFSSL *ssl, DecodedCert *cert) {
    return NOT_COMPILED_IN;
}
