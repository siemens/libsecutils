/** 
* @file key.c
* 
* @brief Key management
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2021
*
* @author David von Oheimb <david.von.oheimb@siemens.com>
*
* This work is licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <errno.h>
#include <stdlib.h> /* for strtoul() */
#include <ctype.h> /* for isspace() */
#include <limits.h> /* for UINT_MAX */
#include <credentials/key.h>
#include <util/log.h>

#include <operators.h>


EVP_PKEY *KEY_new(const char *spec)
{
    return KEY_new_ex(spec, NULL, NULL);
}

EVP_PKEY *KEY_new_ex(const char *spec, OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq)
{
    if(0 is_eq spec)
    {
        LOG(FL_ERR, "null pointer argument");
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
    if (libctx != NULL) {
        LOG(FL_ERR, "libctx not supported by OpenSSL < 3.0");
        return NULL;
    }
    if (propq != NULL) {
        LOG(FL_ERR, "provider property query not supported by OpenSSL < 3.0");
        return NULL;
    }
#endif

    EVP_PKEY *pkey = NULL;
    int type = EVP_PKEY_NONE;
    const char *name = spec;
    int nbits = 0, nid = 0;

    if (CHECK_AND_SKIP_CASE_PREFIX(spec, SECUTILS_RSA_STR)) {
        type = EVP_PKEY_RSA;
        name = SECUTILS_RSA_STR;
    } else if ('0' <= *spec && *spec <= '9') {
        type = EVP_PKEY_RSA;
        name = SECUTILS_RSA_STR;
    } else if (CHECK_AND_SKIP_CASE_PREFIX(spec, SECUTILS_EC_STR)
               && *spec != '\0' && strchr(" -_:", *spec) != NULL) {
        type = EVP_PKEY_EC;
        name = SECUTILS_EC_STR;
    } else {
        spec = name;

        /* Backward compatibility: treat bare EC curve names as EC parameters. */
         int curve_nid = OBJ_sn2nid(spec);
         if (curve_nid == 0)
             curve_nid = EC_curve_nist2nid(spec);
         if (curve_nid != 0) {
             type = EVP_PKEY_EC;
             name = SECUTILS_EC_STR;
         }
#if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_5_0
         else {
             /* For OpenSSL < 3.5, treat everything else as an EC curve name. */
             type = EVP_PKEY_EC;
             name = SECUTILS_EC_STR;
         }
#endif
    }
    if (type != EVP_PKEY_NONE && *spec != '\0' && strchr(" -_:", *spec) != NULL) {
        spec++;
    }
    if (type == EVP_PKEY_RSA) { /* take spec as RSA key length */
        nbits = UTIL_atoint(spec);
        if (nbits < 1024 || 8192 < nbits)
        {
            LOG(FL_ERR, "bad RSA key length specification '%.40s'; must be integer between 1024 and 8192", spec);
            return NULL;
        }
    } else if (type == EVP_PKEY_EC) { /* take spec as ECC curve name */
        if (strcmp(spec, "secp192r1") == 0) {
            LOG(FL_INFO, "using EC curve name prime192v1 instead of secp192r1");
            nid = NID_X9_62_prime192v1;
        } else if(strcmp(spec, "secp256r1") == 0) {
            LOG(FL_INFO, "using EC curve name prime256v1 instead of secp256r1");
            nid = NID_X9_62_prime256v1;
        } else {
            nid = OBJ_sn2nid(spec);
        }
        if (nid == 0) {
            nid = EC_curve_nist2nid(spec);
        }
        if (nid == 0)
        {
            LOG(FL_ERR, "unknown EC curve name %.40s", spec);
            return NULL;
        }
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    (void)name;
    BIGNUM* bn = 0;
    RSA* rsa_key = 0;
    pkey = EVP_PKEY_new();
    if(0 is_eq pkey)
    {
        goto oom;
    }

    if (type == EVP_PKEY_RSA) {
        bn = BN_new();
        rsa_key = RSA_new();
        if(0 is_eq bn or 0 is_eq rsa_key)
        {
            goto oom;
        }

        if(0 is_eq BN_set_word(bn, 0x10001) or /* modulus 65537 */
           0 is_eq RSA_generate_key_ex(rsa_key, nbits, bn, 0))
        {
            LOG(FL_ERR, "cannot generate RSA key with length %d", nbits);
            goto err;
        }
        /* Converting the rsa_key into a PKEY structure so we handle the key just like any other key pair */
        if(0 is_eq EVP_PKEY_assign(pkey, type, rsa_key))
        {
            LOG(FL_ERR, "cannot assign RSA key after key generation");
            goto err;
        }
        rsa_key = 0;
        goto end;
    }
    else
    { /* take spec as ECC curve name, even if no "EC:" prefix given */
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
        if(0 is_eq ec_key)
        {
            LOG(FL_ERR, "failed to create EC group and empty key from curve '%.40s'", spec);
            goto err;
        }
        EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
        /*
         * At this point the EC_KEY object has been set up and associated with the curve - but it is empty.
         *  To generate them using the low level API this can be done as follows
         *  */

        if(0 is_eq EC_KEY_generate_key(ec_key))
        {
            LOG(FL_ERR, "cannot generate EC key with curve type '%.40s'", spec);
            EC_KEY_free(ec_key);
            goto err;
        }
        /* Converting the ec_key into a PKEY structure so we handle the key just like any other key pair */
        if(0 is_eq EVP_PKEY_assign(pkey, type, ec_key))
        {
            LOG(FL_ERR, "cannot assign EC key after key generation");
            goto err;
        }
    }
    goto end;

 oom:
    LOG(FL_ERR, "out of memory during key generation");
 err:
    EVP_PKEY_free(pkey);
    pkey = 0;
    (void)ERR_print_errors(bio_err);
 end:
    RSA_free(rsa_key);
    BN_free(bn);
    return pkey;

#elif OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, name, propq);
    if (ctx == NULL) {
        LOG(FL_ERR, "failed to create key generation context for %.40s (propq=%.100s); algorithm may be unknown or required provider may be unavailable",
            name, propq != NULL ? propq : "(null)");
        goto end;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        LOG(FL_ERR, "failed to prepare generating %.40s key pair (propq=%.100s)",
            name, propq != NULL ? propq : "(null)");
        goto end;
    }

    if (type == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits) <= 0) {
            LOG(FL_ERR, "Failed to set %d RSA bits", nbits);
            goto end;
        }
    } else if (type == EVP_PKEY_EC) {
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
            LOG(FL_ERR, "Failed to set EC curve nid = %d for %.40s", nid, spec);
            goto end;
        }
    } else {
        /* With OpenSSL >= 3.5; attempting to use full name/spec by itself, which may be sufficient, e.g., "ML-DSA-65" */
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        LOG(FL_ERR, "failed generating %.40s key pair", name);
        pkey = NULL;
    }

 end:
    EVP_PKEY_CTX_free(ctx);
    if (pkey == NULL)
        (void)ERR_print_errors(bio_err);
    return pkey;

#else /* 0x10100000L <= OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0 */
    (void)name;
    if (type == EVP_PKEY_RSA) {
        BIGNUM* bn = BN_new();
        RSA* rsa_key = RSA_new();
        pkey = EVP_PKEY_new();
        if(0 is_eq bn or 0 is_eq rsa_key or 0 is_eq pkey)
        {
            LOG(FL_ERR, "out of memory during key generation");
            goto rsa_err;
        }

        if(0 is_eq BN_set_word(bn, 0x10001) or /* modulus 65537 */
           0 is_eq RSA_generate_key_ex(rsa_key, nbits, bn, 0))
        {
            LOG(FL_ERR, "cannot generate RSA key with length %d", nbits);
            goto rsa_err;
        }
        /* Converting the rsa_key into a PKEY structure so we handle the key just like any other key pair */
        if(0 is_eq EVP_PKEY_assign(pkey, type, rsa_key))
        {
            LOG(FL_ERR, "cannot assign RSA key after key generation");
            goto rsa_err;
        }
        BN_free(bn);
        return pkey;

    rsa_err:
        RSA_free(rsa_key);
        BN_free(bn);
        goto err;
    } else { /* taking spec as ECC curve name, even if no "EC:" prefix given */
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
        if(0 is_eq ec_key)
        {
            LOG(FL_ERR, "failed to create EC group and empty key from curve '%.40s'", spec);
            goto ec_err;
        }
        EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
        /*
         * At this point the EC_KEY object has been set up and associated with the curve - but it is empty.
         *  To generate them using the low level API this can be done as follows
         *  */

        if(0 is_eq EC_KEY_generate_key(ec_key))
        {
            LOG(FL_ERR, "cannot generate EC key with curve type '%.40s'", spec);
            goto ec_err;
        }
        /* Converting the ec_key into a PKEY structure so we handle the key just like any other key pair */
        pkey = EVP_PKEY_new();
        if(0 is_eq pkey)
        {
            LOG(FL_ERR, "out of memory during key generation");
            goto ec_err;
        }
        if(0 is_eq EVP_PKEY_assign(pkey, type, ec_key))
        {
            LOG(FL_ERR, "cannot assign EC key after key generation");
            goto ec_err;
        }
        return pkey;

    ec_err:
        EC_KEY_free(ec_key);
    }

 err:
    EVP_PKEY_free(pkey);
    (void)ERR_print_errors(bio_err);
    return NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
}

void KEY_free(EVP_PKEY* pkey)
{
    EVP_PKEY_free(pkey);
}
