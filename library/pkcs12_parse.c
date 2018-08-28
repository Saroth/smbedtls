#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/pkcs12_parse.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

int pk_parse_key_pkcs8_encrypted_der(mbedtls_pk_context *pk,
        unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen);

void mbedtls_pkcs12_init(mbedtls_pkcs12_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_pkcs12_context));
}

void mbedtls_pkcs12_free(mbedtls_pkcs12_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->pk) {
        mbedtls_pk_free(ctx->pk);
        mbedtls_free(ctx->pk);
    }
    if (ctx->cert) {
        mbedtls_x509_crt_free(ctx->cert);
        mbedtls_free(ctx->cert);
    }
    if (ctx->friendly_name.p) {
        mbedtls_free(ctx->friendly_name.p);
    }
    if (ctx->local_key_id.p) {
        mbedtls_free(ctx->local_key_id.p);
    }
    mbedtls_zeroize(ctx, sizeof(mbedtls_pkcs12_context));
}

static int mbedtls_pkcs12_verify(mbedtls_pkcs12_context *ctx,
        mbedtls_asn1_buf *contents, mbedtls_asn1_buf *mac_data)
{
    int ret, iterations;
    size_t i, len;
    unsigned char *p, *end, *digest_info;
    mbedtls_asn1_buf mac_alg_oid, mac_digest, mac_salt;
#define PKCS12_MAX_PWDLEN 128
    unsigned char unipwd[PKCS12_MAX_PWDLEN * 2 + 2];
    mbedtls_md_type_t md_type;
    size_t md_size;
    const mbedtls_md_info_t *md_info;
    unsigned char hash_output[MBEDTLS_MD_MAX_SIZE];
    unsigned char hmac_key[MBEDTLS_MD_MAX_SIZE];

    p = mac_data->p;
    end = mac_data->p + mac_data->len;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    digest_info = p;
    p += len;
    if ((ret = mbedtls_asn1_get_alg_null(&digest_info, end, &mac_alg_oid))
            != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if ((ret = mbedtls_oid_get_md_alg(&mac_alg_oid, &md_type)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    mac_digest.tag = *digest_info;
    if ((ret = mbedtls_asn1_get_tag(&digest_info, end, &mac_digest.len,
                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    mac_digest.p = digest_info;
    digest_info += mac_digest.len;
    mac_salt.tag = *p;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &mac_salt.len,
                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    mac_salt.p = p;
    p += mac_salt.len;
    if ((ret = mbedtls_asn1_get_int(&p, end, &iterations)) != 0) {
        return MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT + ret;
    }


    md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }
    md_size = mbedtls_md_get_size(md_info);
    memset(&unipwd, 0, sizeof(unipwd));
    for (i = 0; i < ctx->pwdlen; i++) {
        unipwd[i * 2 + 1] = ctx->pwd[i];
    }
    if ((ret = mbedtls_pkcs12_derivation(hmac_key, md_size, unipwd,
                    ctx->pwdlen * 2 + 2, mac_salt.p, mac_salt.len, md_type,
                    MBEDTLS_PKCS12_DERIVE_MAC_KEY, iterations)) != 0) {
        return ret;
    }
    if ((ret = mbedtls_md_hmac(md_info, hmac_key, md_size,
                    contents->p, contents->len, hash_output)) != 0) {
        return ret;
    }
    if (memcmp(hash_output, mac_digest.p, mac_digest.len)) {
        return MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH;
    }

    return 0;
}

static int mbedtls_pkcs12_parse_pkcs7_safe_contents(unsigned char *input,
        size_t inlen, mbedtls_asn1_buf *safe_contents)
{
    int ret;
    unsigned char *p, *end;
    mbedtls_asn1_buf content_alg_oid, content_param;

    p = input;
    end = p + inlen;
    if ((ret = mbedtls_asn1_get_alg(&p, end,
                    &content_alg_oid, &content_param)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if (inlen < (size_t)(p - input)) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_DATA, &content_alg_oid) != 0) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }
    if (content_param.tag !=
            (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC)) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT
            + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    }
    safe_contents->tag = *content_param.p;
    if ((ret = mbedtls_asn1_get_tag(&content_param.p, end,
                    &safe_contents->len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    safe_contents->p = content_param.p;

    return 0;
}

static int mbedtls_pkcs12_parse_bag_attributes(unsigned char *input,
        size_t inlen, size_t *len, mbedtls_asn1_buf *friendly_name,
        mbedtls_asn1_buf *local_key_id)
{
    int ret;
    size_t i;
    unsigned char *p, *end;
    mbedtls_asn1_buf oid, val;

    p = input;
    end = input + inlen;
    if ((ret = mbedtls_asn1_get_tag(&p, end, len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    *len += p - input;

    if ((ret = mbedtls_asn1_get_alg(&p, end, &oid, &val)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS9_FRIENDLY_NAME, &oid)) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    friendly_name->tag = *val.p;
    if ((ret = mbedtls_asn1_get_tag(&val.p, val.p + val.len, &val.len,
                    MBEDTLS_ASN1_BMP_STRING)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    friendly_name->len = val.len / 2;
    if ((friendly_name->p = mbedtls_calloc(1, friendly_name->len)) == 0) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    for (i = 0; i < friendly_name->len; i++) {
        friendly_name->p[i] = val.p[i * 2 + 1];
    }

    if ((ret = mbedtls_asn1_get_alg(&p, end, &oid, &val)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS9_LOCAL_KEY_ID, &oid)) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    val.tag = *val.p;
    if ((ret = mbedtls_asn1_get_tag(&val.p, val.p + val.len, &val.len,
                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    *local_key_id = val;
    if ((local_key_id->p = mbedtls_calloc(1, local_key_id->len)) == 0) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    memcpy(local_key_id->p, val.p, val.len);
    return 0;
}

static int mbedtls_parse_pkcs7_encrypted_der(mbedtls_x509_crt *crt,
        unsigned char *input, size_t inlen,
        const unsigned char *pwd, size_t pwdlen)
{
    /**
     *  RFC 2315: 10.1 EnvelopedData type
     *
     *  EncryptedContentInfo ::= SEQUENCE {
     *      contentType ContentType,
     *      contentEncryptionAlgorithm
     *          ContentEncryptionAlgorithmIdentifier,
     *      encryptedContent
     *          [0] IMPLICIT EncryptedContent OPTIONAL
     *  }
     *
     *  EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
     *
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *       algorithm      OBJECT IDENTIFIER,
     *       parameters     ANY DEFINED BY algorithm OPTIONAL
     *  }
     */
    int ret;
    size_t len;
    unsigned char *p = input, *end = p + inlen;
    // unsigned char *attr;
    mbedtls_asn1_buf oid, val;
    unsigned char *buf;
    mbedtls_cipher_type_t cipher_alg;
    mbedtls_md_type_t md_alg;

    if ((ret = mbedtls_asn1_get_alg(&p, end, &oid, &val)) != 0) {
        if (ret != MBEDTLS_ERR_ASN1_LENGTH_MISMATCH || val.p + val.len > end) {
            return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
        }
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_DATA, &oid)) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }
    p = oid.p + oid.len;
    if ((ret = mbedtls_asn1_get_alg(&p, end, &oid, &val)) != 0) {
        if (ret != MBEDTLS_ERR_ASN1_LENGTH_MISMATCH || val.p + val.len > end) {
            return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
        }
    }
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }

    if ((buf = mbedtls_calloc(1, len)) == 0) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    if ((ret = mbedtls_oid_get_pkcs12_pbe_alg(&oid, &md_alg,
                    &cipher_alg)) != 0) {
        mbedtls_free(buf);
        return MBEDTLS_ERR_PK_INVALID_ALG + ret;
    }
    if ((ret = mbedtls_pkcs12_pbe(&val, MBEDTLS_PKCS12_PBE_DECRYPT,
                    cipher_alg, md_alg, pwd, pwdlen, p, len, buf)) != 0) {
        mbedtls_free(buf);
        return ret;
    }

    p = buf;
    end = buf + len;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if ((ret = mbedtls_asn1_get_alg(&p, end, &oid, &val)) != 0) {
        if (ret != MBEDTLS_ERR_ASN1_LENGTH_MISMATCH || val.p + val.len > end) {
            return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
        }
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS12_V1_BAG_IDS_CERTIFICATE_BAG, &oid)) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    // attr = p;
    p = val.p;
    if ((ret = mbedtls_asn1_get_alg(&p, end, &oid, &val)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS9_CERTTYPES_X509, &oid)) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    if ((ret = mbedtls_asn1_get_tag(&val.p, end, &val.len,
                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }

    // @NOTE: do not parse attributes here.
    // mbedtls_asn1_buf friendly_name, local_key_id;
    // if ((ret = mbedtls_pkcs12_parse_bag_attributes(attr, end - attr, &len,
    //                 &friendly_name, &local_key_id)) != 0) {
    //     return ret;
    // }

    ret = mbedtls_x509_crt_parse(crt, val.p, val.len);
    mbedtls_free(buf);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int mbedtls_pkcs12_parse_contents(mbedtls_pkcs12_context *ctx,
        mbedtls_asn1_buf *contents)
{
    /**
     *  SafeContents ::= SEQUENCE OF SafeBag
     *
     *  SafeBag ::= SEQUENCE {
     *      bagId          BAG-TYPE.&id ({ PKCS12BagSet })
     *      bagValue       [0] EXPLICIT BAG-TYPE.&Type({ PKCS12BagSet }{ @bagId }),
     *                     bagAttributes  SET OF PKCS12Attribute OPTIONAL
     *  }
     *
     *  PKCS12Attribute ::= SEQUENCE {
     *      attrId      ATTRIBUTE.&id ({ PKCS12AttrSet }),
     *                  attrValues  SET OF ATTRIBUTE.&Type ({ PKCS12AttrSet }{ @attrId })
     *  } -- This type is compatible with the X.500 type 'Attribute'
     *
     *  PKCS12AttrSet ATTRIBUTE ::= {
     *      friendlyName | -- from PKCS #9 [23]
     *      localKeyId,    -- from PKCS #9
     *      ... -- Other attributes are allowed
     *  }
     *
     *  PKCS12BagSet BAG-TYPE ::= {
     *      keyBag |
     *      pkcs8ShroudedKeyBag |
     *      certBag |
     *      crlBag |
     *      secretBag |
     *      safeContentsBag,
     *      ... -- For future extensions
     *  }
     *
     *  friendlyName ATTRIBUTE ::= {
     *      WITH SYNTAX BMPString (SIZE(1..pkcs-9-ub-friendlyName))
     *      EQUALITY MATCHING RULE caseIgnoreMatch
     *      SINGLE VALUE TRUE
     *      ID pkcs-9-at-friendlyName
     *  }
     *
     *  localKeyId ATTRIBUTE ::= {
     *      WITH SYNTAX OCTET STRING
     *      EQUALITY MATCHING RULE octetStringMatch
     *      SINGLE VALUE TRUE
     *      ID pkcs-9-at-localKeyId
     *  }
     *
     *  CertBag ::= SEQUENCE {
     *      certId    BAG-TYPE.&id   ({CertTypes}),
     *      certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
     *  }
     */
    int ret;
    unsigned char *p, *end, *_p;
    size_t len;
    mbedtls_asn1_buf oid, val;

    p = contents->p;
    end = contents->p + contents->len;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    while (p < end) {
        _p = p;
        if ((ret = mbedtls_asn1_get_alg(&_p, end, &oid, &val)) != 0) {
            if (ret != MBEDTLS_ERR_ASN1_LENGTH_MISMATCH
                    || val.p + val.len > end) {
                return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
            }
        }
        len = _p - p;

        if (!MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_DATA, &oid)) {
            ret = mbedtls_pkcs12_parse_pkcs7_safe_contents(p, len, &val);
            if (ret != 0) {
                return ret;
            }
            if ((ret = mbedtls_pkcs12_parse_contents(ctx, &val)) != 0) {
                return ret;
            }
        }
        else if (!MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_ENCRYPTED_DATA, &oid)) {
            ret = mbedtls_asn1_get_tag(&val.p, end, &val.len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            if (ret != 0) {
                return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
            }
            _p = val.p;
            if ((ret = mbedtls_asn1_get_int(&val.p, end,
                            &ctx->cert_id)) != 0) {
                return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
            }
            val.len -= val.p - _p;

            ctx->cert = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
            if (ctx->cert == 0) {
                return MBEDTLS_ERR_PK_ALLOC_FAILED;
            }
            mbedtls_x509_crt_init(ctx->cert);
            if ((ret = mbedtls_parse_pkcs7_encrypted_der(ctx->cert,
                            val.p, val.len, ctx->pwd, ctx->pwdlen)) != 0) {
                return ret;
            }
        }
        else if (!MBEDTLS_OID_CMP(
                    MBEDTLS_OID_PKCS12_V1_BAG_IDS_SHROUDED_KEY_BAG, &oid)) {
            if ((ctx->pk = mbedtls_calloc(1, sizeof(mbedtls_pk_context)))
                    == 0) {
                return MBEDTLS_ERR_PK_ALLOC_FAILED;
            }
            mbedtls_pk_init(ctx->pk);
            if ((ret = pk_parse_key_pkcs8_encrypted_der(ctx->pk,
                            val.p, val.len, ctx->pwd, ctx->pwdlen)) != 0) {
                return ret;
            }
            if (val.p + val.len < end) {
                val.p += val.len;
                if ((ret = mbedtls_pkcs12_parse_bag_attributes(val.p,
                                end - val.p, &val.len, &ctx->friendly_name,
                                &ctx->local_key_id)) != 0) {
                    return ret;
                }
                len += val.len;
            }
        }
        else {
            return MBEDTLS_ERR_PK_INVALID_ALG;
        }

        p += len;
    }

    return 0;
}

int mbedtls_pkcs12_decrypt(mbedtls_pkcs12_context *ctx,
        unsigned char *input, size_t inlen,
        const unsigned char *pwd, size_t pwdlen)
{
    /**
     *  RFC 7292: PFX PDU Syntax:
     *
     *  PFX ::= SEQUENCE {
     *      version     INTEGER { v3(3) }(v3,...),
     *      authSafe    ContentInfo,
     *      macData     MacData OPTIONAL
     *  }
     *
     *  MacData ::= SEQUENCE {
     *      mac         DigestInfo,
     *      macSalt     OCTET STRING,
     *      iterations  INTEGER DEFAULT 1
     *          -- Note: The default is for historical reasons and its
     *          --       use is deprecated.
     *  }
     *
     *  DigestInfo ::= SEQUENCE {
     *      digestAlgorithm DigestAlgorithmIdentifier, (RFC 2315)
     *      digest Digest
     *  }
     *
     *  DigestAlgorithmIdentifier ::= AlgorithmIdentifier (RFC 1422)
     *  Digest ::= OCTET STRING
     */
    int ret;
    size_t len;
    unsigned char *p, *end;
    int version = 0;
    mbedtls_asn1_buf contents, mac_data;

    if (pwdlen == 0)
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    p = input;
    end = input + inlen;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if ((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    if (version != 3) {
        return MBEDTLS_ERR_PK_KEY_INVALID_VERSION;
    }

    if ((ret = mbedtls_pkcs12_parse_pkcs7_safe_contents(p, end - p,
                    &contents)) != 0) {
        return ret;
    }
    p += contents.p - p + contents.len;

    mac_data.tag = *p;
    mac_data.p = p;
    if ((ret = mbedtls_asn1_get_tag(&mac_data.p, end, &mac_data.len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
    }
    ctx->pwd = pwd;
    ctx->pwdlen = pwdlen;
    if ((ret = mbedtls_pkcs12_verify(ctx, &contents, &mac_data)) != 0) {
        return ret;
    }

    return mbedtls_pkcs12_parse_contents(ctx, &contents);
}

#if defined(MBEDTLS_FS_IO)
int mbedtls_pkcs12_decrypt_file(mbedtls_pkcs12_context *ctx,
        const char *path, const char *pwd)
{
    int ret;
    size_t n;
    unsigned char *buf;

    if ((ret = mbedtls_pk_load_file(path, &buf, &n)) != 0) {
        return ret;
    }
    if (pwd == NULL) {
        ret = mbedtls_pkcs12_decrypt(ctx, buf, n,
                (const unsigned char *)"123456", 6);
    }
    else {
        ret = mbedtls_pkcs12_decrypt(ctx, buf, n,
                (const unsigned char *)pwd, strlen(pwd));
    }

    mbedtls_zeroize(buf, n);
    mbedtls_free(buf);
    return ret;
}
#endif /* defined(MBEDTLS_FS_IO) */

#endif /* defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_X509_CRT_PARSE_C) */

