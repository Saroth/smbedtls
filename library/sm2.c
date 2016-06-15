/*
 * SM2 Encryption alogrithm
 * GM/T 0003-2012 Chinese National Standard:
 *      Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves
 * Refers to: http://www.oscca.gov.cn/
 * Thanks to MbedTLS.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SM2_C)

#include "mbedtls/sm2.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#endif /* MBEDTLS_PLATFORM_C */

void mbedtls_sm2_init(mbedtls_sm2_context *ctx)
{
    mbedtls_ecp_keypair_init(ctx);
}

void mbedtls_sm2_free(mbedtls_sm2_context *ctx)
{
    mbedtls_ecp_keypair_free(ctx);
}

/**
 * SM2 KDF (GM/T 0003-2012 - Part 3: Key Exchange Protocol 5.4.3)
 */
static int mbedtls_sm2_pbkdf2(mbedtls_md_context_t *ctx,
        const unsigned char *password, size_t plen,
        const unsigned char *salt, size_t slen,
        unsigned int iteration_count,
        uint32_t key_length, unsigned char *output)
{
    int ret, j;
    unsigned int i;
    unsigned char md1[MBEDTLS_MD_MAX_SIZE];
    unsigned char work[MBEDTLS_MD_MAX_SIZE];
    unsigned char md_size = mbedtls_md_get_size(ctx->md_info);
    size_t use_len;
    unsigned char *out_p = output;
    unsigned char counter[4];

    memset(counter, 0, 4);
    counter[3] = 1;

    if (iteration_count > 0xFFFFFFFF)
        return (MBEDTLS_ERR_SM2_BAD_INPUT_DATA);

    while (key_length) {
        // U1 ends up in work
        //
        if ((ret = mbedtls_md_starts(ctx)) != 0)
            return ret;
        if ((ret = mbedtls_md_update(ctx, password, plen)) != 0)
            return ret;
        if ((ret = mbedtls_md_update(ctx, salt, slen)) != 0)
            return ret;
        if ((ret = mbedtls_md_update(ctx, counter, 4)) != 0)
            return ret;
        if ((ret = mbedtls_md_finish(ctx, work)) != 0)
            return ret;

        memcpy(md1, work, md_size);

        for (i = 1; i < iteration_count; i++) {
            // U2 ends up in md1
            //
            if ((ret = mbedtls_md_hmac_starts(ctx, password, plen)) != 0)
                return (ret);
            if ((ret = mbedtls_md_hmac_update(ctx, md1, md_size)) != 0)
                return (ret);
            if ((ret = mbedtls_md_hmac_finish(ctx, md1)) != 0)
                return (ret);

            // U1 xor U2
            //
            for (j = 0; j < md_size; j++)
                work[j] ^= md1[j];
        }

        use_len = (key_length < md_size) ? key_length : md_size;
        memcpy(out_p, work, use_len);

        key_length -= (uint32_t)use_len;
        out_p += use_len;

        for (i = 4; i > 0; i--)
            if (++counter[i - 1] != 0)
                break;
    }

    return (0);
}

int mbedtls_sm2_encrypt(mbedtls_sm2_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *len,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 0;
    size_t i;
    mbedtls_mpi k;
#if defined(MBEDTLS_SM2_CHECK_IS_VALID_POINT)
    mbedtls_mpi h;
#endif
    mbedtls_ecp_point point;
    mbedtls_md_context_t md_ctx;
    size_t n, xlen, ylen;
    unsigned char *xym = NULL;

    do {
        /* A1: rand k in [1, n-1] */
        mbedtls_mpi_init(&k);
        n = (ctx->grp.pbits + 7) / 8;
        MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&k, n, f_rng, p_rng));

        /* A2: C1 = [k]G = (x1, y1) */
        mbedtls_ecp_point_init(&point);
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &point, &k, &ctx->grp.G,
                    NULL, NULL));
        output[0] = POINT_CONVERSION_UNCOMPRESSED;
        *len = 1;
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point.X, output + *len,
                    mbedtls_mpi_size(&point.X)));
        *len += mbedtls_mpi_size(&point.X);
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point.Y, output + *len,
                    mbedtls_mpi_size(&point.Y)));
        *len += mbedtls_mpi_size(&point.Y);

#if defined(MBEDTLS_SM2_CHECK_IS_VALID_POINT)
        /* A3: check [h]Pb != O */
        mbedtls_mpi_init(&h);
        mbedtls_mpi_read_binary(&h, (const unsigned char *)"\x01", 1);
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &point, &h, &ctx->Q,
                    NULL, NULL));
        MBEDTLS_MPI_CHK(mbedtls_ecp_is_zero(&point));
#endif /* MBEDTLS_SM2_CHECK_IS_VALID_POINT */

        /* A4: [k]Pb = (x2, y2) */
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &point, &k, &ctx->Q,
                    NULL, NULL));

        /* A5: t = KDF(x2 || y2, klen) */
        xlen = mbedtls_mpi_size(&point.X);
        ylen = mbedtls_mpi_size(&point.Y);
        mbedtls_md_init(&md_ctx);
        MBEDTLS_MPI_CHK(mbedtls_md_setup(&md_ctx,
                    mbedtls_md_info_from_type(MBEDTLS_MD_SM3), 0));
        if ((xym = mbedtls_calloc(1, xlen + ylen + ilen)) == NULL) {
            return MBEDTLS_ERR_SM2_ALLOC_FAILED;
        }
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point.X, xym, xlen));
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point.Y, xym + xlen, ylen));
        MBEDTLS_MPI_CHK(mbedtls_sm2_pbkdf2(&md_ctx, xym, xlen + ylen,
                    NULL, 0, 0, ilen, xym + xlen + ylen));
        for (i = 0; i < ilen; i++) {
            if (*(xym + xlen + ylen + i)) {
                break;
            }
        }
        if (i >= xlen + ylen) {
            continue;
        }

        break;
    } while (0);

    /* A6: C2 = M xor t */
    for (i = 0; i < ilen; i++) {
        output[*len + i] = input[i] ^ *(xym + xlen + ylen + i);
    }
    *len += ilen;

    /* A7: C3 = Hash(x2 || M || y2) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point.X, xym, xlen));
    memmove(xym + xlen, input, ilen);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&point.Y, xym + xlen, ylen));
    mbedtls_md(md_ctx.md_info, xym, xlen + ilen + ylen, output + *len);
    *len += mbedtls_md_get_size(md_ctx.md_info);

cleanup:
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&h);
    mbedtls_ecp_point_free(&point);
    if (xym) {
        mbedtls_free(xym);
    }
    mbedtls_md_free(&md_ctx);

    return (ret);
}

int mbedtls_sm2_decrypt(mbedtls_sm2_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen)
{
    if (ctx || input || ilen || output || olen) {}
    return 0;
}

int mbedtls_sm2_sign(mbedtls_sm2_context *ctx,
        mbedtls_md_type_t md_alg,
        const unsigned char *hash,
        unsigned char *sig,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (ctx || md_alg || hash || sig || f_rng || p_rng) {}
    return 0;
}

int mbedtls_sm2_verify(mbedtls_sm2_context *ctx,
        mbedtls_md_type_t md_alg,
        const unsigned char *sig,
        const unsigned char *hash)
{
    if (ctx || md_alg || sig || hash) {}
    return 0;
}

/*
 * Generate key pair
 */
int mbedtls_sm2_genkey(mbedtls_sm2_context *ctx, mbedtls_ecp_group_id gid,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return (mbedtls_ecp_group_load(&ctx->grp, gid) ||
            mbedtls_ecp_gen_keypair(&ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng));
}

#if defined(MBEDTLS_SELF_TEST)

static const unsigned char sm2_test_plaintext[] = { // "encryption standard"
    0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69,
    0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64,
    0x61, 0x72, 0x64,
};
static const unsigned char sm2_test_prik[] = {
    0x16, 0x49, 0xAB, 0x77, 0xA0, 0x06, 0x37, 0xBD,
    0x5E, 0x2E, 0xFE, 0x28, 0x3F, 0xBF, 0x35, 0x35,
    0x34, 0xAA, 0x7F, 0x7C, 0xB8, 0x94, 0x63, 0xF2,
    0x08, 0xDD, 0xBC, 0x29, 0x20, 0xBB, 0x0D, 0xA0,
};
static const unsigned char sm2_test_pubk[] = {
    0x04,

    0x43, 0x5B, 0x39, 0xCC, 0xA8, 0xF3, 0xB5, 0x08,
    0xC1, 0x48, 0x8A, 0xFC, 0x67, 0xBE, 0x49, 0x1A,
    0x0F, 0x7B, 0xA0, 0x7E, 0x58, 0x1A, 0x0E, 0x48,
    0x49, 0xA5, 0xCF, 0x70, 0x62, 0x8A, 0x7E, 0x0A,

    0x75, 0xDD, 0xBA, 0x78, 0xF1, 0x5F, 0xEE, 0xCB,
    0x4C, 0x78, 0x95, 0xE2, 0xC1, 0xCD, 0xF5, 0xFE,
    0x01, 0xDE, 0xBB, 0x2C, 0xDB, 0xAD, 0xF4, 0x53,
    0x99, 0xCC, 0xF7, 0x7B, 0xBA, 0x07, 0x6A, 0x42,
};
static const unsigned char sm2_test_rand_fix[] = {
    0x4C, 0x62, 0xEE, 0xFD, 0x6E, 0xCF, 0xC2, 0xB9,
    0x5B, 0x92, 0xFD, 0x6C, 0x3D, 0x95, 0x75, 0x14,
    0x8A, 0xFA, 0x17, 0x42, 0x55, 0x46, 0xD4, 0x90,
    0x18, 0xE5, 0x38, 0x8D, 0x49, 0xDD, 0x7B, 0x4F,
};

#define mbedtls_dmp_mpi(_mpi) do {                      \
    mbedtls_printf(" > MPI: %s:", #_mpi);               \
    memset(debug, 0x00, sizeof(debug));                 \
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&_mpi,     \
                debug, mbedtls_mpi_size(&_mpi)));       \
    for (i = 0; i < mbedtls_mpi_size(&_mpi); i++) {     \
        if (i % 32 == 0) {                              \
            mbedtls_printf("\n \t");                    \
        }                                               \
        if (i % 4 == 0) {                               \
            mbedtls_printf(" ");                        \
        }                                               \
        mbedtls_printf("%02X", debug[i] & 0xff);        \
    }                                                   \
    mbedtls_printf(" <\n");                             \
} while (0);

#define mbedtls_dmp(_buf, _len) do {                    \
    mbedtls_printf(" > Dat %s:", #_buf);                \
    for (i = 0; i < _len; i++) {                        \
        if (i % 32 == 0) {                              \
            mbedtls_printf("\n \t");                    \
        }                                               \
        if (i % 4 == 0) {                               \
            mbedtls_printf(" ");                        \
        }                                               \
        mbedtls_printf("%02X",                          \
                *((unsigned char *)&_buf + i) & 0xff);  \
    }                                                   \
    mbedtls_printf(" <\n");                             \
} while (0);

int mbedtls_sm2_self_test(int verbose)
{
    int ret;
    unsigned int i;
    unsigned char debug[1024];
    unsigned char output[1024];
    unsigned int outlen = 0;

    mbedtls_mpi k;
    mbedtls_mpi h;
    mbedtls_ecp_point C1;
    mbedtls_ecp_point C2;
    size_t n;
    mbedtls_sm2_context ctx;
    mbedtls_md_context_t sm3_ctx;
    unsigned char * xy2 = NULL;
    unsigned char * t = NULL;
    unsigned char * C = NULL;
    size_t x2len, y2len, klen;

    mbedtls_printf(" ## SM2 Encryption test\n");
    if (verbose) {}

    mbedtls_printf(" SM2 context init...\n");
    mbedtls_sm2_init(&ctx);
    mbedtls_printf(" load ECP group...\n");
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&ctx.grp,
                MBEDTLS_ECP_DP_SM2P256T1 ));
    mbedtls_printf(" read private key...\n");
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx.d,
                sm2_test_prik, sizeof(sm2_test_prik)));
    mbedtls_printf(" read public key...\n");
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q,
            sm2_test_pubk, sizeof(sm2_test_pubk)));

    mbedtls_dmp_mpi(ctx.grp.P);
    mbedtls_dmp_mpi(ctx.grp.A);
    mbedtls_dmp_mpi(ctx.grp.B);
    mbedtls_dmp_mpi(ctx.grp.G.X);
    mbedtls_dmp_mpi(ctx.grp.G.Y);
    mbedtls_dmp_mpi(ctx.grp.G.Z);
    mbedtls_dmp_mpi(ctx.grp.N);
    mbedtls_dmp_mpi(ctx.d);
    mbedtls_dmp_mpi(ctx.Q.X);
    mbedtls_dmp_mpi(ctx.Q.Y);
    mbedtls_dmp_mpi(ctx.Q.Z);

    do {
        mbedtls_printf(" /* A1: rand k in [1, n-1] */\n");
        n = (ctx.grp.pbits + 7) / 8;
        mbedtls_printf(" random data size: %ld\n", n);
        mbedtls_printf(" read fix random data...\n");
        mbedtls_mpi_init(&k);
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&k,
                    sm2_test_rand_fix, sizeof(sm2_test_rand_fix)));
        mbedtls_dmp_mpi(k);

        mbedtls_printf(" /* A2: C1 = [k]G = (x1, y1) */\n");
        mbedtls_printf(" compute C1...\n");
        mbedtls_ecp_point_init(&C1);
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx.grp, &C1, &k, &ctx.grp.G,
                    NULL, NULL));
        mbedtls_dmp_mpi(C1.X);
        mbedtls_dmp_mpi(C1.Y);
        mbedtls_dmp_mpi(C1.Z);
        output[0] = POINT_CONVERSION_UNCOMPRESSED;
        outlen = 1;
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&C1.X, output + outlen,
                    mbedtls_mpi_size(&C1.X)));
        outlen += mbedtls_mpi_size(&C1.X);
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&C1.Y, output + outlen,
                    mbedtls_mpi_size(&C1.Y)));
        outlen += mbedtls_mpi_size(&C1.Y);
        mbedtls_printf(" get C1:");
        mbedtls_dmp(output, outlen);

        mbedtls_printf(" /* A3: check [h]Pb != O */\n");
        mbedtls_printf(" compute S = [h]Pb...\n");
        mbedtls_ecp_point_init(&C2);
        mbedtls_mpi_init(&h);       // @TODO: h取值
        mbedtls_mpi_read_binary(&h, (const unsigned char *)"\x01", 1);
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx.grp, &C2, &h, &ctx.Q,
                    NULL, NULL));
        mbedtls_printf(" check S is zero...\n");
        MBEDTLS_MPI_CHK(mbedtls_ecp_is_zero(&C2));

        mbedtls_printf(" /* A4: [k]Pb = (x2, y2) */\n");
        mbedtls_printf(" compute C2...\n");
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx.grp, &C2, &k, &ctx.Q,
                    NULL, NULL));
        mbedtls_dmp_mpi(C2.X);
        mbedtls_dmp_mpi(C2.Y);
        mbedtls_dmp_mpi(C2.Z);

        mbedtls_printf(" /* A5: t = KDF(x2 || y2, klen) */\n");
        mbedtls_printf(" sm3 setup...\n");
        mbedtls_md_init(&sm3_ctx);
        MBEDTLS_MPI_CHK(mbedtls_md_setup(&sm3_ctx,
                    mbedtls_md_info_from_type(MBEDTLS_MD_SM3), 0));
        x2len = mbedtls_mpi_size(&C2.X);
        y2len = mbedtls_mpi_size(&C2.Y);
        mbedtls_printf(" calloc space, size:%ld+%ld...\n", x2len, y2len);
        if ((xy2 = mbedtls_calloc(1, x2len + y2len)) == NULL) {
            return MBEDTLS_ERR_SM2_ALLOC_FAILED;
        }
        mbedtls_printf(" get xy2 binary:");
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&C2.X, xy2, x2len));
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&C2.Y, xy2 + x2len, y2len));
        mbedtls_dmp(xy2, x2len + y2len);
        klen = sizeof(sm2_test_plaintext);
        mbedtls_printf(" calloc space, size:%ld...\n", klen);
        if ((t = mbedtls_calloc(1, klen)) == NULL) {
            return MBEDTLS_ERR_SM2_ALLOC_FAILED;
        }
        mbedtls_printf(" compute KDF...\n");
        MBEDTLS_MPI_CHK(mbedtls_sm2_pbkdf2(&sm3_ctx,
                    xy2, x2len + y2len,
                    NULL, 0,
                    0, klen, t));
        mbedtls_dmp(t, klen);
        mbedtls_printf(" check t...\n");
        for (i = 0; i < klen; i++) {
            if (t[i]) {
                break;
            }
        }
        if (i >= x2len + y2len) {
            mbedtls_printf(" empty string! goto step A1.\n");
            continue;
        }

        break;
    } while (1);

    mbedtls_printf(" /* A6: C2 = M xor t */\n");
    for (i = 0; i < klen; i++) {
        output[outlen + i] = sm2_test_plaintext[i] ^ t[i];
    }
    mbedtls_printf(" get C2:");
    mbedtls_dmp(output + outlen, klen);
    outlen += klen;

    mbedtls_printf(" /* A7: C3 = Hash(x2 || M || y2) */\n");
    mbedtls_printf(" calloc space, size:%ld...\n", x2len + klen + y2len);
    if ((C = mbedtls_calloc(1, x2len + klen + y2len)) == NULL) {
        return MBEDTLS_ERR_SM2_ALLOC_FAILED;
    }
    mbedtls_printf(" compute Hash...\n");
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&C2.X, C, x2len));
    memmove(C + x2len, sm2_test_plaintext, klen);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&C2.Y, C + x2len + klen, y2len));
    mbedtls_md(sm3_ctx.md_info, C, x2len + klen + y2len, output + outlen);
    mbedtls_printf(" get C3:");
    mbedtls_dmp(output + outlen, mbedtls_md_get_size(sm3_ctx.md_info));
    outlen += mbedtls_md_get_size(sm3_ctx.md_info);

    mbedtls_printf(" get ciphertext:");
    mbedtls_dmp(output, outlen);

cleanup:
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&h);
    mbedtls_ecp_point_free(&C1);
    mbedtls_ecp_point_free(&C2);
    if (xy2) {
        mbedtls_free(xy2);
        xy2 = NULL;
    }
    if (t) {
        mbedtls_free(t);
        t = NULL;
    }
    if (t) {
        mbedtls_free(t);
        t = NULL;
    }
    mbedtls_md_free(&sm3_ctx);
    mbedtls_sm2_free(&ctx);

    if (ret) {
        mbedtls_printf(" error! return:%d(%#x)\n", ret, -ret);
    }

    return (ret);
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SM2_C */
