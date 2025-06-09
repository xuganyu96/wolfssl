#ifndef WOLFSSL_KEMTLS_H
#define WOLFSSL_KEMTLS_H

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/signature.h>

WOLFSSL_API int accept_KEMTLS(WOLFSSL *ssl);
WOLFSSL_API int connect_KEMTLS(WOLFSSL *ssl);

WOLFSSL_API int handle_PQCleanMlKemKey_cert(WOLFSSL *ssl, DecodedCert *cert);
WOLFSSL_API int handle_HqcKey_cert(WOLFSSL *ssl, DecodedCert *cert);

WOLFSSL_LOCAL int DoKemTlsClientKemCiphertext(WOLFSSL *ssl, byte *input,
                                              word32 *inOutIdx, word32 totalSz);
WOLFSSL_LOCAL int DoKemTlsFinished(WOLFSSL *ssl, const byte *input, word32 *inOutIdx,
                                   word32 size, word32 totalSz);

#endif /* WOLFSSL_KEMTLS_H */
