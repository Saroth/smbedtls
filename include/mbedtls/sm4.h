#ifndef MBEDTLS_SM4_H
#define MBEDTLS_SM4_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MBEDTLS_SM4_ENCRYPT 1
#define MBEDTLS_SM4_DECRYPT 0

#define MBEDTLS_SM4_KEY_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           SM4 context structure
 */
typedef struct
{
    uint32_t sk[32];            /*!<  SM4 subkeys       */
}
mbedtls_sm4_context;

void mbedtls_sm4_init(mbedtls_sm4_context *ctx);
void mbedtls_sm4_free(mbedtls_sm4_context *ctx);
void mbedtls_sm4_setkey_enc(mbedtls_sm4_context *ctx,
        const unsigned char key[MBEDTLS_SM4_KEY_SIZE], unsigned int keybits);
void mbedtls_sm4_setkey_dec(mbedtls_sm4_context *ctx,
        const unsigned char key[MBEDTLS_SM4_KEY_SIZE], unsigned int keybits);

int mbedtls_sm4_crypt_ecb(mbedtls_sm4_context *ctx, int mode,
        const unsigned char *input, unsigned char *output);
int mbedtls_sm4_crypt_cbc(mbedtls_sm4_context *ctx, int mode, size_t length,
        unsigned char iv[MBEDTLS_SM4_KEY_SIZE],
        const unsigned char *input, unsigned char *output);

int mbedtls_sm4_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif /* sm4.h */
