#ifndef MBEDTLS_SM2_H
#define MBEDTLS_SM2_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecp.h"
#include "md.h"

#define MBEDTLS_ERR_SM2_BAD_INPUT_DATA  -0x4800     /*!< Bad input parameters to function. */
#define MBEDTLS_ERR_SM2_ALLOC_FAILED    -0x4880     /*!< Memory allocation failed. */
#define MBEDTLS_ERR_SM2_KDF_FAILED      -0x4900     /*!< KDF got empty result. */
#define MBEDTLS_ERR_SM2_DECRYPT_BAD_HASH -0x4980    /*!< Bad C3 in SM2 decrypt */

#define MBEDTLS_SM2_CHECK_IS_VALID_POINT

/**
 *  Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y) */
typedef enum {
    /** the point is encoded as z||x, where the octet z specifies
     *          *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_COMPRESSED = 2,
    /** the point is encoded as z||x||y, where z is the octet 0x02  */
    POINT_CONVERSION_UNCOMPRESSED = 4,
    /** the point is encoded as z||x||y, where the octet z specifies
     *          *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM2 context structure
 */
typedef mbedtls_ecp_keypair mbedtls_sm2_context;

/**
 * \brief          Initialize an SM2 context
 *
 * \param ctx      SM2 context to be initialized
 */
void mbedtls_sm2_init( mbedtls_sm2_context *ctx );

/**
 * \brief          Clear SM2 context
 *
 * \param ctx      SM2 Context to free
 */
void mbedtls_sm2_free( mbedtls_sm2_context *ctx );

/**
 * \brief           Perform SM2 encryption
 *
 * \param ctx       SM2 context
 * \param input     the plaintext to be encrypted
 * \param ilen      the plaintext length
 * \param output    buffer that will hold the plaintext
 * \param olen      will contain the plaintext length
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  ...
 */
int mbedtls_sm2_encrypt( mbedtls_sm2_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Perform SM2 decryption
 *
 * \param ctx       SM2 context
 * \param input     encrypted data
 * \param ilen      the encrypted data length
 * \param output    buffer that will hold the plaintext
 * \param olen      will contain the plaintext length
 *
 * \return          0 if successful,
 *                  ...
 */
int mbedtls_sm2_decrypt( mbedtls_sm2_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen );

/**
 * \brief           Compute SM2 signature of a previously hashed message
 *
 * \param ctx       SM2 context
 * \param md_alg    Algorithm that was used to hash the message
 * \param hash      Message hash
 * \param sig       Buffer that will hold the signature, size must be 64 bytes
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  ...
 */
int mbedtls_sm2_sign( mbedtls_sm2_context *ctx,
        mbedtls_md_type_t md_alg,
        const unsigned char *hash,
        unsigned char *sig,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Verify SM2 signature of a previously hashed message
 *
 * \param ctx       SM2 context
 * \param md_alg    Algorithm that was used to hash the message
 * \param sig       Signature to verify, 64 bytes
 * \param hash      Message hash
 *
 * \return          0 if successful,
 *                  ...
 */
int mbedtls_sm2_verify( mbedtls_sm2_context *ctx,
        mbedtls_md_type_t md_alg,
        const unsigned char *sig,
        const unsigned char *hash );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_sm2_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif /* sm2.h */
