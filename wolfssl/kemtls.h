#ifndef WOLFSSL_KEMTLS_H
#define WOLFSSL_KEMTLS_H

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/signature.h>

WOLFSSL_API int accept_KEMTLS(WOLFSSL *ssl);
WOLFSSL_API int connect_KEMTLS(WOLFSSL *ssl);

#endif /* WOLFSSL_KEMTLS_H */
