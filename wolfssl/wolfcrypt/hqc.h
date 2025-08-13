#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_HQC
typedef struct HqcKey {
} HqcKey;

int wc_HqcKey_Init(HqcKey *key);
int wc_HqcKey_Free(HqcKey *key);
int wc_HqcKey_SetLevel(HqcKey *key, int level);
int wc_HqcKey_GetLevel(HqcKey *key, int *level);
int wc_HqcKey_PublicKeySize(HqcKey *key, word32 *len);
int wc_HqcKey_PrivateKeySize(HqcKey *key, word32 *len);
int wc_HqcKey_CiphertextSize(HqcKey *key, word32 *len);
int wc_HqcKey_SharedSecretSize(HqcKey *key, word32 *len);
int wc_HqcKey_MakeKey(HqcKey *key, WC_RNG *rng);
int wc_HqcKey_ExportPublicKey(HqcKey *key, byte *buf, word32 len);
int wc_HqcKey_ExportPrivateKey(HqcKey *key, byte *buf, word32 len);
int wc_HqcKey_GetLevelFromNamedGroup(word16 namedgroup, int *level);
#endif /* HAVE_HQC */
