#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_X509_CRT_WRITE_C) || \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_ERROR_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_PEM_WRITE_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_X509_CRT_WRITE_C and/or "
            "MBEDTLS_X509_CRT_PARSE_C and/or "
            "MBEDTLS_FS_IO and/or MBEDTLS_SHA256_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_ERROR_C not defined.\n");
    return 0;
}
#else

#include "mbedtls/pkcs12_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USAGE \
    "\n usage: pfx_parse param=<>...\n" \
    "\n acceptable parameters:\n"       \
    "    filename=%%s         \n"       \
    "    password=%%s         \n"       \
    "\n"

struct options {
    const char *filename;       /* filename of the PFX file */
    const char *pwd;
} opt;

static int arg_parse(int argc, char *argv[])
{
    int i;
    char *p, *q;

    memset(&opt, 0, sizeof(opt));

    if (argc <= 1) {
usage:
        mbedtls_printf(USAGE);
        mbedtls_printf("\n");
        return -1;
    }
    for (i = 1; i < argc; i++) {
        p = argv[i];
        if ((q = strchr(p, '=')) == NULL) {
            goto usage;
        }
        *q++ = '\0';

        if (strcmp(p, "filename") == 0) {
            opt.filename = q;
        }
        else if (strcmp(p, "password") == 0) {
            opt.pwd = q;
        }
        else {
            goto usage;
        }
    }
    if (opt.filename == 0 || opt.pwd == 0) {
        goto usage;
    }
    mbedtls_printf("\n");

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    mbedtls_pkcs12_context p12_ctx;
    mbedtls_pk_context pk;
    mbedtls_x509_crt crt;

    if ((ret = arg_parse(argc, argv)) < 0) {
        return 0;
    }

    mbedtls_pkcs12_init(&p12_ctx);
    mbedtls_pk_init(&pk);
    mbedtls_x509_crt_init(&crt);

    mbedtls_printf("  . decrypt PFX file ...");
    ret = mbedtls_pkcs12_decrypt_file(&p12_ctx, opt.filename, opt.pwd);
    if (ret != 0) {
        mbedtls_printf(" failed\n"
                "  !  mbedtls_pkcs12_decrypt_file returned %#x\n\n", -ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

exit:
    mbedtls_pkcs12_free(&p12_ctx);
    mbedtls_pk_free(&pk);
    mbedtls_x509_crt_free(&crt);
#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return ret;
}
#endif /* MBEDTLS_X509_CRT_WRITE_C && MBEDTLS_X509_CRT_PARSE_C &&
          MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_ERROR_C && MBEDTLS_PEM_WRITE_C */

