#ifndef MBEDTLS_SM2_C
#define MBEDTLS_SM2_C

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif



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
