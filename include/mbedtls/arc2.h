#ifndef MBEDTLS_ARC2_H
#define MBEDTLS_ARC2_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_ARC2_ALT)
#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ARC2_ENCRYPT    1
#define MBEDTLS_ARC2_DECRYPT    0

#define MBEDTLS_ERR_ARC2_INVALID_KEY_LENGTH     -0x0020  /**< Invalid key length. */
#define MBEDTLS_ERR_ARC2_INVALID_INPUT_LENGTH   -0x0022  /**< Invalid data input length. */

typedef struct {
    uint16_t xk_enc[64];
    uint16_t xk_dec[64];
} mbedtls_arc2_context;

void mbedtls_arc2_init(mbedtls_arc2_context *ctx);
void mbedtls_arc2_free(mbedtls_arc2_context *ctx);

int mbedtls_arc2_setkey_enc(mbedtls_arc2_context *ctx,
        const unsigned char *key, size_t key_bitlen);
int mbedtls_arc2_setkey_dec(mbedtls_arc2_context *ctx,
        const unsigned char *key, size_t key_bitlen);
int mbedtls_arc2_encrypt(mbedtls_arc2_context *ctx,
        const unsigned char *input, unsigned char *output);
int mbedtls_arc2_decrypt(mbedtls_arc2_context *ctx,
        const unsigned char *input, unsigned char *output);

int mbedtls_arc2_crypt_ecb(mbedtls_arc2_context *ctx, int mode,
        const unsigned char input[8], unsigned char output[8]);
#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_arc2_crypt_cbc(mbedtls_arc2_context *ctx, int mode,
        size_t length, unsigned char iv[8],
        const unsigned char *input, unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#ifdef __cplusplus
}
#endif
#else  /* MBEDTLS_ARC2_ALT */
#include "arc2_alt.h"
#endif /* MBEDTLS_ARC2_ALT */

#ifdef __cplusplus
extern "C" {
#endif
int mbedtls_arc2_self_test(int verbose);
#ifdef __cplusplus
}
#endif

#endif /* arc2.h */

