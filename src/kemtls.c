#include <wolfssl/internal.h>
#include <wolfssl/kemtls.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/logging.h>

static byte derivedLabel[] = "derived";
static int derivedLabelLen = 8;
static byte clientFinishedKeyLabel[] = "c finished";
static int clientFinishedKeyLabelLen = 11;
static byte serverFinishedKeyLabel[] = "s finished";
static int serverFinishedKeyLabelLen = 11;

static void dump_hex(byte *data, word32 len) {
#ifdef DEBUG_WOLFSSL
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
    word32 prefix_len = 8;
    for (word32 i = 0; i < prefix_len; i++) {
        fprintf(stderr, "%02x:", data[i]);
    }
    fprintf(stderr, "...");
    for (word32 i = len - prefix_len; i < len; i++) {
        fprintf(stderr, ":%02x", data[i]);
    }
    fprintf(stderr, "\n");
#else
    (void)data;
    (void)len;
#endif
}

/* Derive HS, dHS, AHS, dAHS, MS, client finished key, and server finished key.
 *
 * This function should be called after client/server obtains KEM shared secret
 * for authentication but before sending Finished. Client calls this function
 * right after processing server's KEM public key in DoTls13Certificate. Server
 * calls this function after processing client's KEM ciphertext in
 * DoKemTlsClientKemCiphertext.
 *
 * Return 0 on success
 */
static int deriveKemTlsFinishedSecrets(WOLFSSL *ssl, byte *kemSharedSecret,
                                       word32 kemShareddSecretSz) {
    WOLFSSL_ENTER("deriveKemTlsFinishedSecrets");
    int ret;
    byte derived_key[WC_MAX_DIGEST_SIZE];

    /* HS <- HKDF_extract(dES, ss_e), but I don't care about dES */
    ret = wc_Tls13_HKDF_Extract(
        ssl->arrays->preMasterSecret, NULL, 0, ssl->arrays->preMasterSecret,
        ssl->arrays->preMasterSz, mac2hash(ssl->specs.mac_algorithm));
    if (ret != 0) {
        WOLFSSL_MSG_EX("wc_Tls13_HKDF_Extract returned %d", ret);
        return ret;
    }
    ssl->arrays->preMasterSz = ssl->specs.hash_size;
    // WOLFSSL_MSG("GYX: HS dump");
    // dump_hex(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);

    /* dHS <- HKDF_expand(HS, "derived", NULL) */
    ret = DeriveKeyMsg(ssl, derived_key, -1, ssl->arrays->preMasterSecret,
                       derivedLabel, derivedLabelLen, NULL, 0,
                       ssl->specs.mac_algorithm);
    if (ret != 0) {
        WOLFSSL_MSG_EX("DeriveKeyMsg returned %d", ret);
        return ret;
    }
    // WOLFSSL_MSG("GYX: dHS dump");
    // dump_hex(derived_key, ssl->specs.hash_size);

    /* AHS <- HKDF_extract(dHS, ss_s) */
    ret = wc_Tls13_HKDF_Extract(ssl->arrays->preMasterSecret, derived_key,
                                ssl->specs.hash_size, kemSharedSecret,
                                kemShareddSecretSz,
                                mac2hash(ssl->specs.mac_algorithm));
    if (ret != 0) {
        WOLFSSL_MSG_EX("wc_Tls13_HKDF_Extract returned %d", ret);
        return ret;
    }
    ssl->arrays->preMasterSz = ssl->specs.hash_size;
    // WOLFSSL_MSG("GYX: AHS dump");
    // dump_hex(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);

    /* dAHS <- HKDF_expand(HS, "derived", NULL) */
    ret = DeriveKeyMsg(ssl, derived_key, -1, ssl->arrays->preMasterSecret,
                       derivedLabel, derivedLabelLen, NULL, 0,
                       ssl->specs.mac_algorithm);
    if (ret != 0) {
        WOLFSSL_MSG_EX("DeriveKeyMsg returned %d", ret);
        return ret;
    }
    // WOLFSSL_MSG_EX("GYX: dAHS dump (%d bytes)", ssl->specs.hash_size);
    // dump_hex(derived_key, ssl->specs.hash_size);

    /* MS <- HKDF_extract(dAHS, 0) */
    ret = wc_Tls13_HKDF_Extract(ssl->arrays->masterSecret, NULL, 0, derived_key,
                                ssl->specs.hash_size,
                                mac2hash(ssl->specs.mac_algorithm));
    if (ret != 0) {
        WOLFSSL_MSG_EX("wc_Tls13_HKDF_Extract returned %d", ret);
        return ret;
    }
    WOLFSSL_MSG("GYX: MS dump");
    dump_hex(ssl->arrays->masterSecret, ssl->specs.hash_size);

    /* client_finished_key <- HKDF_expand(MS, "c finished", NULL) */
    ret = DeriveKeyMsg(ssl, ssl->keys.client_write_MAC_secret, -1,
                       ssl->arrays->masterSecret, clientFinishedKeyLabel,
                       clientFinishedKeyLabelLen, NULL, 0,
                       ssl->specs.mac_algorithm);
    if (ret != 0) {
        WOLFSSL_MSG_EX("DeriveKeyMsg (clientFinishedKey) returned %d", ret);
        return ret;
    }
    WOLFSSL_MSG("GYX: clientFinishedKey dump");
    dump_hex(ssl->keys.client_write_MAC_secret, ssl->specs.hash_size);

    /* server_finished_key <- HKDF_expand(MS, "s finished", NULL) */
    ret = DeriveKeyMsg(ssl, ssl->keys.server_write_MAC_secret, -1,
                       ssl->arrays->masterSecret, serverFinishedKeyLabel,
                       serverFinishedKeyLabelLen, NULL, 0,
                       ssl->specs.mac_algorithm);
    if (ret != 0) {
        WOLFSSL_MSG_EX("DeriveKeyMsg (serverFinishedKey) returned %d", ret);
        return ret;
    }
    WOLFSSL_MSG("GYX: serverFinishedKey dump");
    dump_hex(ssl->keys.server_write_MAC_secret, ssl->specs.hash_size);

    WOLFSSL_LEAVE("deriveKemTlsFinishedSecrets", ret);
    return ret;
}

/* Send the Finished message, which contains a single HMAC tag.
 */
static int SendKemTlsFinished(WOLFSSL *ssl) {
    WOLFSSL_ENTER("SendKemTlsFinished");
    int ret;
    int finishedSz = ssl->specs.hash_size;
    byte *output; /* beginning of record */
    byte *input;  /* beginning of fragment/handshake msg */
    byte *secret; /* client or server finished key */
    int headerSz = HANDSHAKE_HEADER_SZ;
    int outputSz, sendSz;

    outputSz = finishedSz + HANDSHAKE_HEADER_SZ + MAX_MSG_EXTRA;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0) {
        WOLFSSL_MSG_EX("CheckAvailableSize(output=%d) returned %d", outputSz,
                       ret);
        return ret;
    }
    output = GetOutputBuffer(ssl);
    input = output + RECORD_HEADER_SZ;
    AddTls13Headers(output, finishedSz, finished, ssl);

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        secret = ssl->keys.client_write_MAC_secret;
    } else {
        secret = ssl->keys.server_write_MAC_secret;
    }

    ret = BuildTls13HandshakeHmac(ssl, secret, input + headerSz, NULL);
    if (ret != 0) {
        WOLFSSL_MSG_EX("BuildTls13HandshakeHmac returned %d", ret);
        return ret;
    }

    sendSz = BuildTls13Message(ssl, output, outputSz, input,
                               headerSz + finishedSz, handshake, 1, 0, 0);
    if (sendSz < 0) {
        WOLFSSL_ERROR_VERBOSE(BUILD_MSG_ERROR);
        return BUILD_MSG_ERROR;
    }
    ssl->buffers.outputBuffer.length += (word32)sendSz;

    /* GYX: unlike TLS 1.3, KEMTLS cannot start sending app data until after
     * DoKemTlsFinished because peer is not explicitly authenticated until after
     * peer's Finished is processed
     */
    if ((ret = SendBuffered(ssl)) != 0) {
        WOLFSSL_MSG_EX("SendBuffered returned %d", ret);
        return ret;
    }
    /* GYX: when client calls SendFinished, handshake is not done, and
     * connectState will be updated outside this function; when server sends
     * Finished, server's done with handshake */
    if (ssl->options.side == WOLFSSL_SERVER_END) {
        ssl->options.handShakeState = HANDSHAKE_DONE;
        ssl->options.handShakeDone = 1;
    } else {
        /* do nothing */
    }
    WOLFSSL_LEAVE("SendKemTlsFinished", ret);
    return ret;
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
    int sendSz, outputSz, inputSz;
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
    inputSz = ssl->kemCiphertextSz + HANDSHAKE_HEADER_SZ;
    sendSz = BuildTls13Message(ssl, output, outputSz, input, inputSz, handshake,
                               hashOutput, 0, 0);
    if (sendSz < 0) {
        return BUILD_MSG_ERROR;
    }
    WOLFSSL_MSG_EX("GYX: fragment=%d, record=%d", inputSz,
                   inputSz + RECORD_HEADER_SZ);
    WOLFSSL_MSG_EX("GYX: outputSz=%d, sendSz=%d", outputSz, sendSz);

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

/* Handle server workflow in KEMTLS handshake after sending a KEM certificate
 *
 * ssl->errror will be assigned outside this function; do not assign to
 * ssl->error
 */
int accept_KEMTLS(WOLFSSL *ssl) {
    WOLFSSL_ENTER("accept_KEMTLS");
    int ret;

    while (ssl->options.clientState < CLIENT_KEM_FINISHED_DONE) {
        ret = ProcessReply(ssl);
        if (ret != 0) {
            return ret;
        }
    }

    ret = SendKemTlsFinished(ssl);
    if (ret != 0) {
        return ret;
    }
    ssl->options.acceptState = KEMTLS_ACCEPT_FINISHED_SENT;
    WOLFSSL_MSG("acceptState: KEMTLS_ACCEPT_FINISHED_SENT");

    /* derive application traffic keys, no need to derive Master Secret: it's
     * already done at DoClientKemCiphertext */
    if ((ret = DeriveTls13Keys(ssl, traffic_key, ENCRYPT_AND_DECRYPT_SIDE, 1)) <
        0) {
        return ret;
    }
    if ((ret = SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE)) < 0) {
        return ret;
    }

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

    if ((ret = SendKemTlsFinished(ssl)) != 0) {
        return ret;
    }
    ssl->options.connectState = CLIENT_KEM_FINISHED_SENT;
    WOLFSSL_MSG("connectState: CLIENT_KEM_FINISHED_SENT");

    /* handle server's Finished */
    while (ssl->options.serverState < SERVER_KEM_FINISHED_DONE) {
        ret = ProcessReply(ssl);
        if (ret != 0) {
            WOLFSSL_MSG_EX("GYX: expect server's finish, got (err=%d)", ret);
            return ret;
        }
    }

    /* derive application traffic keys, no need to derive Master Secret: it's
     * already done at DoClientKemCiphertext */
    if ((ret = DeriveTls13Keys(ssl, traffic_key, ENCRYPT_AND_DECRYPT_SIDE, 1)) <
        0) {
        return ret;
    }
    if ((ret = SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE)) < 0) {
        return ret;
    }

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
            ret =
                wc_HqcKey_DerToPrivateKey(ssl->buffers.key->buffer, &idx,
                                          ssl->hsKey, ssl->buffers.key->length);
        }
        if (ret == 0) {
            ret = wc_HqcKey_CipherTextSize(ssl->hsKey, &ctLen);
        }
        if (ret == 0) {
            ret = wc_HqcKey_SharedSecretSize(ssl->hsKey, &ssLen);
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
            ret =
                wc_HqcKey_Decapsulate(ssl->hsKey, ssl->kemSharedSecret,
                                      ssl->kemCiphertext, ssl->kemCiphertextSz);
            break;
        default:
            WOLFSSL_MSG_EX("GYX: unsupported key type %d",
                           ssl->buffers.keyType);
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = deriveKemTlsFinishedSecrets(ssl, ssl->kemSharedSecret,
                                          ssl->kemSharedSecretSz);
    }

    if (ret == 0) {
        WOLFSSL_MSG("GYX: server-side ciphertext");
        dump_hex(ssl->kemCiphertext, ssl->kemCiphertextSz);
        WOLFSSL_MSG("GYX: server-side shared secret");
        dump_hex(ssl->kemSharedSecret, ssl->kemSharedSecretSz);
        ssl->options.clientState = CLIENT_KEM_CIPHERTEXT_DONE;
        *inOutIdx += totalSz;
        *inOutIdx += ssl->keys.padSz;
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
        ret = deriveKemTlsFinishedSecrets(ssl, ssl->kemSharedSecret,
                                          ssl->kemSharedSecretSz);
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

int handle_HqcKey_cert(WOLFSSL *ssl, DecodedCert *cert) {
    WOLFSSL_ENTER("handle_HqcKey_cert");
    int ret, level;

    if (ssl->peerHqcKey == NULL) {
        ret = AllocKey(ssl, DYNAMIC_TYPE_HQC, (void **)&ssl->peerHqcKey);
    } else if (ssl->peerHqcKeyPresent) {
        WOLFSSL_MSG("GYX: Reusing peerHqcKey is not implemented");
        ret = NOT_COMPILED_IN;
    } else {
        WOLFSSL_MSG("GYX: UNREACHABLE!");
        ret = NOT_COMPILED_IN;
    }

    if (ret == 0) {
        if (cert->keyOID == HQC_LEVEL1k) {
            ret = wc_HqcKey_SetLevel(ssl->peerHqcKey, (level = 1));
        } else if (cert->keyOID == HQC_LEVEL3k) {
            ret = wc_HqcKey_SetLevel(ssl->peerHqcKey, (level = 3));
        } else if (cert->keyOID == HQC_LEVEL5k) {
            ret = wc_HqcKey_SetLevel(ssl->peerHqcKey, (level = 5));
        } else {
            /* GYX: UNREACHABLE! */
        }
    }

    if (ret == 0) {
        WOLFSSL_MSG_EX("GYX: pubKeyLen=%d, level=%d", cert->pubKeySize, level);
        ret = wc_HqcKey_import_public(ssl->peerHqcKey, cert->publicKey,
                                      cert->pubKeySize);
    }

    if (ret == 0) { /* pubKey is good, allocate ciphertext/shared secret */
        ret = wc_HqcKey_CipherTextSize(ssl->peerHqcKey, &ssl->kemCiphertextSz);
        if (ret == 0) {
            WOLFSSL_MSG_EX("GYX: ctLen=%d", ssl->kemCiphertextSz);
            ssl->kemCiphertext =
                XMALLOC(ssl->kemCiphertextSz, ssl->heap, DYNAMIC_TYPE_KEMCT);
            if (ssl->kemCiphertext == NULL) {
                /* GYX: need to free PQCleanMlKemKey */
                ret = MEMORY_E;
            }
        }

        ret = wc_HqcKey_SharedSecretSize(ssl->peerHqcKey,
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
        ret = wc_HqcKey_Encapsulate(ssl->peerHqcKey, ssl->kemCiphertext,
                                    ssl->kemSharedSecret, ssl->rng);
    }

    if (ret == 0) {
        ret = deriveKemTlsFinishedSecrets(ssl, ssl->kemSharedSecret,
                                          ssl->kemSharedSecretSz);
    }

    if (ret == 0) {
        WOLFSSL_MSG("GYX: client-side ciphertext");
        dump_hex(ssl->kemCiphertext, ssl->kemCiphertextSz);
        WOLFSSL_MSG("GYX: client-side shared secret");
        dump_hex(ssl->kemSharedSecret, ssl->kemSharedSecretSz);
        ssl->peerHqcKeyPresent = 1;
        ssl->options.haveHqcAuth = 1;
    }
    WOLFSSL_LEAVE("handle_HqcKey_cert", ret);
    return ret;
}

/* Process Finished
 *
 * @input    (byte *)   start of the handshake message (i.e. record's fragment)
 * @inOutIdx (word32 *) On entry, the index into the message buffer of Finished
 *                      On exit, the index of the byte after the Finished
 *                      message and padding
 * @size     (word32)   length of the Finished message
 *
 * Return 0 on success
 */
int DoKemTlsFinished(WOLFSSL *ssl, const byte *input, word32 *inOutIdx,
                     word32 size, word32 totalSz) {
    WOLFSSL_ENTER("DoKemTlsFinished");
    int ret;
    byte *secret;
    byte mac_cmp[WC_MAX_DIGEST_SIZE];
    word32 mac_cmp_len = 0;

    WOLFSSL_MSG_EX("GYX: inOutIdx=%d size=%d totalSz=%d", *inOutIdx, size,
                   totalSz);

    if (*inOutIdx + size > totalSz) { /* GYX: what is totalSz? */
        return BUFFER_E;
    }

    /* verify with peer's Finished key */
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        secret = ssl->keys.server_write_MAC_secret;
    } else {
        secret = ssl->keys.client_write_MAC_secret;
    }
    ret = BuildTls13HandshakeHmac(ssl, secret, mac_cmp, &mac_cmp_len);
    if (ret != 0) {
        WOLFSSL_MSG_EX("BuildTls13HandshakeHmac returned %d", ret);
        return ret;
    }
    if (mac_cmp_len != size) {
        WOLFSSL_MSG_EX("peer MAC len=%d, verify MAC len=%d", size, mac_cmp_len);
        return BUFFER_ERROR;
    }
    if (XMEMCMP(input + *inOutIdx, mac_cmp, size) != 0) {
        WOLFSSL_MSG("Verify finished error on hashes");
        SendAlert(ssl, alert_fatal, decrypt_error);
        WOLFSSL_ERROR_VERBOSE(VERIFY_FINISHED_ERROR);
        return VERIFY_FINISHED_ERROR;
    }

    *inOutIdx += size + ssl->keys.padSz;
    if (ssl->options.side == WOLFSSL_SERVER_END) {
        /* after server is done processing client's Finished, server is not done
         * with handshake: it still needs to send its own Finished
         */
        ssl->options.clientState = CLIENT_KEM_FINISHED_DONE;
    } else {
        /* after client is done processing server's Finished, client is done
         * with handsha */
        ssl->options.serverState = SERVER_KEM_FINISHED_DONE;
        ssl->options.connectState = KEM_FINISHED_DONE;
        ssl->options.handShakeState = HANDSHAKE_DONE;
        ssl->options.handShakeDone = 1;
    }
    /* GYX: Set up application keys! */
    WOLFSSL_LEAVE("DoKemTlsFinished", ret);
    return ret;
}
