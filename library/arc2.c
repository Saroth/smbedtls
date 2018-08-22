
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ARC2_C)

#include "mbedtls/arc2.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_ARC2_ALT)

/* 256-entry permutation table, probably derived somehow from pi */
static const unsigned char key_table[256] = {
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
    0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
    0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
    0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
    0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
    0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
    0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
    0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
    0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
    0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
    0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
    0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
    0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
    0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
    0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
    0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
    0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
};

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

void mbedtls_arc2_init(mbedtls_arc2_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_arc2_context));
}

void mbedtls_arc2_free(mbedtls_arc2_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_zeroize(ctx, sizeof(mbedtls_arc2_context));
}

static void mbedtls_arc2_key_schedule(uint16_t xk[64],
        const unsigned char *key, size_t keylen, size_t bits)
{
    unsigned char x, *k = (unsigned char *)xk;
    int i = 0;

    if (keylen > 128) {
        keylen = 128;
    }
    if (bits == 0 || bits > 1024) {
        bits = 1024;
    }

    memcpy(k, key, keylen);
    /* 1: expand input key to 128 bytes */
    x = k[keylen - 1];
    for (; keylen < 128; keylen++, i++) {
        x = key_table[(x + k[i]) & 0xff];
        k[keylen] = x;
    }
    /* 2: reduce effective key size to 'bits' */
    keylen = (bits + 7) >> 3;
    i = 128 - keylen;
    x = key_table[k[i] & (0xff >> (-bits & 0x7))];
    k[i] = x;
    while (i--) {
        x = key_table[k[i + keylen] ^ x];
        k[i] = x;
    }
    /* 3: copy to xkey in little-endian order */
    for (i = 63; i >= 0; i--) {
        xk[i] = (k[2 * i] | (k[2 * i + 1] << 8)) & 0xffff;
    }
}

int mbedtls_arc2_setkey_enc(mbedtls_arc2_context *ctx,
        const unsigned char *key, size_t key_bitlen)
{
    mbedtls_arc2_key_schedule(ctx->xk_enc, key, key_bitlen >> 3, key_bitlen);
    return 0;
}

int mbedtls_arc2_setkey_dec(mbedtls_arc2_context *ctx,
        const unsigned char *key, size_t key_bitlen)
{
    mbedtls_arc2_key_schedule(ctx->xk_dec, key, key_bitlen >> 3, key_bitlen);
    return 0;
}

int mbedtls_arc2_encrypt(mbedtls_arc2_context *ctx,
        const unsigned char input[8], unsigned char output[8])
{
    unsigned int x76, x54, x32, x10, i = 0;

    x76 = (input[7] << 8) + input[6];
    x54 = (input[5] << 8) + input[4];
    x32 = (input[3] << 8) + input[2];
    x10 = (input[1] << 8) + input[0];
    for (; i < 16; i++) {
        x10 = (x10 + (x32 & ~x76) + (x54 & x76)
                + ctx->xk_enc[4 * i + 0]) & 0xffff;
        x10 = ((x10 << 1) | (x10 >> 15)) & 0xffff;
        x32 = (x32 + (x54 & ~x10) + (x76 & x10)
                + ctx->xk_enc[4 * i + 1]) & 0xffff;
        x32 = ((x32 << 2) | (x32 >> 14)) & 0xffff;
        x54 = (x54 + (x76 & ~x32) + (x10 & x32)
                + ctx->xk_enc[4 * i + 2]) & 0xffff;
        x54 = ((x54 << 3) | (x54 >> 13)) & 0xffff;
        x76 = (x76 + (x10 & ~x54) + (x32 & x54)
                + ctx->xk_enc[4 * i + 3]) & 0xffff;
        x76 = ((x76 << 5) | (x76 >> 11)) & 0xffff;
        if (i == 4 || i == 10) {
            x10 += ctx->xk_enc[x76 & 0x3f];
            x32 += ctx->xk_enc[x10 & 0x3f];
            x54 += ctx->xk_enc[x32 & 0x3f];
            x76 += ctx->xk_enc[x54 & 0x3f];
        }
    }
    output[0] = (unsigned char)x10;
    output[1] = (unsigned char)(x10 >> 8);
    output[2] = (unsigned char)x32;
    output[3] = (unsigned char)(x32 >> 8);
    output[4] = (unsigned char)x54;
    output[5] = (unsigned char)(x54 >> 8);
    output[6] = (unsigned char)x76;
    output[7] = (unsigned char)(x76 >> 8);
    return 0;
}

int mbedtls_arc2_decrypt(mbedtls_arc2_context *ctx,
        const unsigned char input[8], unsigned char output[8])
{
    unsigned int x76, x54, x32, x10, t, i = 15;

    x76 = (input[7] << 8) + input[6];
    x54 = (input[5] << 8) + input[4];
    x32 = (input[3] << 8) + input[2];
    x10 = (input[1] << 8) + input[0];
    do {
        t = ((x76 << 11) | (x76 >> 5)) & 0xffff;
        x76 = t - (x10 & ~x54) - (x32 & x54) - ctx->xk_dec[4 * i + 3];
        x76 &= 0xffff;
        t = ((x54 << 13) | (x54 >> 3)) & 0xffff;
        x54 = t - (x76 & ~x32) - (x10 & x32) - ctx->xk_dec[4 * i + 2];
        x54 &= 0xffff;
        t = ((x32 << 14) | (x32 >> 2)) & 0xffff;
        x32 = t - (x54 & ~x10) - (x76 & x10) - ctx->xk_dec[4 * i + 1];
        x32 &= 0xffff;
        t = ((x10 << 15) | (x10 >> 1)) & 0xffff;
        x10 = t - (x32 & ~x76) - (x54 & x76) - ctx->xk_dec[4 * i + 0];
        x10 &= 0xffff;
        if (i == 5 || i == 11) {
            x76 = (x76 - ctx->xk_dec[x54 & 0x3f]) & 0xffff;
            x54 = (x54 - ctx->xk_dec[x32 & 0x3f]) & 0xffff;
            x32 = (x32 - ctx->xk_dec[x10 & 0x3f]) & 0xffff;
            x10 = (x10 - ctx->xk_dec[x76 & 0x3f]) & 0xffff;
        }
    } while (i--);
    output[0] = (unsigned char)x10;
    output[1] = (unsigned char)(x10 >> 8);
    output[2] = (unsigned char)x32;
    output[3] = (unsigned char)(x32 >> 8);
    output[4] = (unsigned char)x54;
    output[5] = (unsigned char)(x54 >> 8);
    output[6] = (unsigned char)x76;
    output[7] = (unsigned char)(x76 >> 8);
    return 0;
}

int mbedtls_arc2_crypt_ecb(mbedtls_arc2_context *ctx, int mode,
        const unsigned char input[8], unsigned char output[8])
{
    if (mode == MBEDTLS_ARC2_ENCRYPT) {
        mbedtls_arc2_encrypt(ctx, input, output);
    }
    else {
        mbedtls_arc2_decrypt(ctx, input, output);
    }

    return( 0 );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_arc2_crypt_cbc(mbedtls_arc2_context *ctx, int mode, size_t length,
        unsigned char iv[8], const unsigned char *input, unsigned char *output)
{
    int i;
    unsigned char temp[8];

    if (length % 8) {
        return (MBEDTLS_ERR_ARC2_INVALID_INPUT_LENGTH);
    }
    if (mode == MBEDTLS_ARC2_DECRYPT) {
        while (length > 0) {
            memcpy(temp, input, 8);
            mbedtls_arc2_crypt_ecb( ctx, mode, input, output );

            for (i = 0; i < 8; i++)
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy(iv, temp, 8);

            input  += 8;
            output += 8;
            length -= 8;
        }
    }
    else {
        while (length > 0) {
            for (i = 0; i < 8; i++) {
                output[i] = (unsigned char)(input[i] ^ iv[i]);
            }

            mbedtls_arc2_crypt_ecb(ctx, mode, output, output);
            memcpy(iv, output, 8);

            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#endif /* !MBEDTLS_ARC2_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * ARC2 tests vectors:
 */
static const unsigned char arc2_test_key[4][16] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, },
};

static const unsigned char arc2_test_pt[4][8] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
};

static const unsigned char arc2_test_ct[4][8] = {
    { 0x1C, 0x19, 0x8A, 0x83, 0x8D, 0xF0, 0x28, 0xB7 },
    { 0x21, 0x82, 0x9C, 0x78, 0xA9, 0xF9, 0xC0, 0x74 },
    { 0x13, 0xDB, 0x35, 0x17, 0xD3, 0x21, 0x86, 0x9E },
    { 0x50, 0xDC, 0x01, 0x62, 0xBD, 0x75, 0x7F, 0x31 },
};

/*
 * Checkup routine
 */
int mbedtls_arc2_self_test( int verbose )
{
    int i, ret = 0;
    unsigned char ibuf[8];
    unsigned char obuf[8];
    mbedtls_arc2_context ctx;

    mbedtls_arc2_init(&ctx);

    for (i = 0; i < 4; i++) {
        mbedtls_arc2_setkey_enc(&ctx, arc2_test_key[i], 128);
        mbedtls_arc2_setkey_dec(&ctx, arc2_test_key[i], 128);

        if (verbose != 0) {
            mbedtls_printf("  ARC2 test #%d (enc): ", i + 1);
        }
        memcpy(ibuf, arc2_test_pt[i], 8);
        mbedtls_arc2_encrypt(&ctx, ibuf, obuf);
        if (memcmp(obuf, arc2_test_ct[i], 8) != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            ret = 1;
            goto exit;
        }
        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }

        if (verbose != 0) {
            mbedtls_printf("  ARC2 test #%d (dec): ", i + 1);
        }
        mbedtls_arc2_decrypt(&ctx, obuf, obuf);
        if (memcmp(obuf, arc2_test_pt[i], 8) != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            ret = 1;
            goto exit;
        }
        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

exit:
    mbedtls_arc2_free(&ctx);

    return ret;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_ARC2_C */
