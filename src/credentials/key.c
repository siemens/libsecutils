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

#include <credentials/key.h>
#include <util/log.h>

#include <operators.h>

EVP_PKEY* KEY_new(const char* spec)
{
    if(0 is_eq spec)
    {
        LOG(FL_ERR, "null pointer argument");
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L

    BIGNUM* bn = 0;
    RSA* rsa_key = 0;
    EVP_PKEY* pkey = EVP_PKEY_new();
    if(0 is_eq pkey)
    {
        goto oom;
    }

    int type = EVP_PKEY_NONE;
    const char* const RSA_STR = "RSA";
    const char* const EC_STR = "EC";
    if(0 is_eq strncasecmp(spec, RSA_STR, strlen(RSA_STR)))
    {
        spec += strlen(RSA_STR);
        type = EVP_PKEY_RSA;
    }
    else if(0 is_eq strncasecmp(spec, EC_STR, strlen(EC_STR)))
    {
        spec += strlen(EC_STR);
        type = EVP_PKEY_EC;
    }
    if(type is_eq EVP_PKEY_NONE)
    {
        type = ('0' <= spec[0] and spec[0] <= '9') ? EVP_PKEY_RSA : EVP_PKEY_EC;
    }
    else
    {
        if(strchr(" -_:", spec[0]) not_eq 0)
        {
            spec++;
        }
    }

    if(type is_eq EVP_PKEY_RSA)
    { /* take spec as RSA key length */
        int nbits = UTIL_atoint(spec);
        if(nbits < 1024 or 8192 < nbits)
        {
            LOG(FL_ERR, "bad RSA key length specification '%.40s'; must be integer between 1024 and 8192", spec);
            goto err;
        }

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
    { /* take spec as ECC curve name */
        int nid = 0;
        if(0 is_eq strcmp(spec, "secp192r1"))
        {
            LOG(FL_INFO, "using EC curve name prime192v1 instead of secp192r1");
            nid = NID_X9_62_prime192v1;
        }
        else if(0 is_eq strcmp(spec, "secp256r1"))
        {
            LOG(FL_INFO, "using EC curve name prime256v1 instead of secp256r1");
            nid = NID_X9_62_prime256v1;
        }
        else
        {
            nid = OBJ_sn2nid(spec);
        }
        if(nid is_eq 0)
        {
            nid = EC_curve_nist2nid(spec);
        }
        if(0 is_eq nid)
        {
            LOG(FL_ERR, "unknown EC curve name '%.40s'", spec);
            goto err;
        }

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

#else /* OPENSSL_VERSION_NUMBER < 0x10100000L */

    EVP_PKEY* pkey = 0;
    int type = EVP_PKEY_NONE;
    const char* const RSA_STR = "RSA";
    const char* const EC_STR = "EC";
    if(0 is_eq strncasecmp(spec, RSA_STR, strlen(RSA_STR)))
    {
        spec += strlen(RSA_STR);
        type = EVP_PKEY_RSA;
    }
    else if(0 is_eq strncasecmp(spec, EC_STR, strlen(EC_STR)))
    {
        spec += strlen(EC_STR);
        type = EVP_PKEY_EC;
    }
    if(type is_eq EVP_PKEY_NONE)
    {
        type = ('0' <= spec[0] and spec[0] <= '9') ? EVP_PKEY_RSA : EVP_PKEY_EC;
    }
    else
    {
        if(strchr(" -_:", spec[0]) not_eq 0)
        {
            spec++;
        }
    }

    if(type is_eq EVP_PKEY_RSA)
    { /* take spec as RSA key length */
        int nbits = UTIL_atoint(spec);
        if(nbits < 1024 or 8192 < nbits)
        {
            LOG(FL_ERR, "bad RSA key length specification '%.40s'; must be integer between 1024 and 8192", spec);
            goto err;
        }

#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
        pkey = EVP_RSA_gen(nbits);
        if (pkey == NULL) {
            LOG(FL_ERR, "cannot generate RSA key with length %d", nbits);
            goto err;
        }
        return pkey;
#else
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
#endif
    }
    else
    { /* take spec as ECC curve name */
        int nid = 0;
        if(0 is_eq strcmp(spec, "secp192r1"))
        {
            LOG(FL_INFO, "using EC curve name prime192v1 instead of secp192r1");
            nid = NID_X9_62_prime192v1;
        }
        else if(0 is_eq strcmp(spec, "secp256r1"))
        {
            LOG(FL_INFO, "using EC curve name prime256v1 instead of secp256r1");
            nid = NID_X9_62_prime256v1;
        }
        else
        {
            nid = OBJ_sn2nid(spec);
        }
        if(nid is_eq 0)
        {
            nid = EC_curve_nist2nid(spec);
        }
        if(0 is_eq nid)
        {
            LOG(FL_ERR, "unknown EC curve name %.40s", spec);
            goto err;
        }

#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
        pkey = EVP_EC_gen(OSSL_EC_curve_nid2name(nid));
        if (pkey == NULL) {
            LOG(FL_ERR, "cannot generate EC key with curve name %.40s", spec);
            goto err;
        }
        return pkey;
#else
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
#endif
    }

 err:
    EVP_PKEY_free(pkey);
    (void)ERR_print_errors(bio_err);
    return 0;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
}

void KEY_free(EVP_PKEY* pkey)
{
    EVP_PKEY_free(pkey);
}
