#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_SM2_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_SM2_C and/or MBEDTLS_SM3_C "
           "not defined.\n");
    return (0);
}
#else
#include <string.h>

#include "mbedtls/sm2.h"

int main(void)
{
    mbedtls_printf(" # GM algorithms test in development.\n");

    mbedtls_sm2_self_test(1);

    return (0);
}
#endif /* MBEDTLS_SM2_C */



