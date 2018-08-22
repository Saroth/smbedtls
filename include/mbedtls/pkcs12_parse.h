#ifndef MBEDTLS_PKCS12_PARSE_H
#define MBEDTLS_PKCS12_PARSE_H

#include "pk.h"
#include "x509_crt.h"
#include "pkcs12.h"

typedef enum {
    MBEDTLS_BAG_KEY,
    MBEDTLS_BAG_PKCS8_SHROUDED_KEY,
    MBEDTLS_BAG_CERT,
    MBEDTLS_BAG_CRL,
    MBEDTLS_BAG_SECRET,
    MBEDTLS_BAG_SAFE_CONTENTS,
} mbedtls_pkcs12_bag_type;

typedef struct {
    mbedtls_pk_context *pk;
    int cert_id;
    mbedtls_x509_crt *cert;
    mbedtls_asn1_buf friendly_name;
    mbedtls_asn1_buf local_key_id;
    const unsigned char *pwd;
    size_t pwdlen;
} mbedtls_pkcs12_context;

#ifdef __cplusplus
extern "C" {
#endif

void mbedtls_pkcs12_init(mbedtls_pkcs12_context *ctx);
void mbedtls_pkcs12_free(mbedtls_pkcs12_context *ctx);

int mbedtls_pkcs12_decrypt(mbedtls_pkcs12_context *ctx,
        unsigned char *input, size_t inlen,
        const unsigned char *pwd, size_t pwdlen);
int mbedtls_pkcs12_decrypt_file(mbedtls_pkcs12_context *ctx,
        const char *path, const char *pwd);

#ifdef __cplusplus
}
#endif

#endif /* pkcs12_parse.h */

