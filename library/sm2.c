/*
 * SM2 Encryption alogrithm
 * GM/T 0003-2012 Chinese National Standard refers to: http://www.oscca.gov.cn/ 
 * Thanks to MbedTLS.
 * Thanks to author: goldboar (goldboar@163.com).
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





#if defined(MBEDTLS_SELF_TEST)

int mbedtls_sm2_self_test(int verbose)
{
    return 0;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SM2_C */
