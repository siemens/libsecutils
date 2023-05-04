/** 
* @file uta_api.c
* 
* @brief libuta (https://github.com/siemens/libuta) integration for DV and ICV protection
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

#ifdef SECUTILS_USE_UTA 

#include <openssl/sha.h>
#include <uta.h>

#include <storage/uta_api.h>
#include <util/log.h>

#include <operators.h>

#if DVLEN not_eq UTA_LEN_DV_V1
#error DVLEN not_eq UTA_LEN_DV_V1 /* mismatch with uta.h */
#endif


static uta_api_v1_t uta_api = {0}; /* @todo: this api handle is not completely thread safe */


uta_ctx* uta_open(void)
{
    if(uta_init_v1(&uta_api) not_eq UTA_SUCCESS)
    {
        LOG_err("ERROR during uta_init_v1");
        return 0;
    }

    /* Check the maximum output key length */
    size_t len_key_max = uta_api.len_key_max();
    if(TA_OUTLEN > len_key_max)
    {
        LOG(FL_ERR, "TA_OUTLEN %d larger than %lu", TA_OUTLEN, (unsigned long)len_key_max);
        return 0;
    }

    /* Allocate memory for the context */
    uta_context_v1_t* uta_ctx = OPENSSL_malloc(uta_api.context_v1_size());
    if(uta_ctx is_eq 0)
    {
        LOG_err("Out of memory");
        return 0;
    }

    /* Fill in the context */
    if(uta_api.open(uta_ctx) not_eq UTA_SUCCESS)
    {
        LOG_err("ERROR during uta.open");
        OPENSSL_free(uta_ctx);
        return 0;
    }

    return uta_ctx;
}


bool uta_close(uta_ctx* uta_ctx)
{
    if(uta_api.close is_eq 0)
    {
        LOG(FL_WARN, "uta_api not initialized");
    }
    if(uta_ctx is_eq 0)
    {
        LOG(FL_ERR, "uta_ctx argument is 0");
        return false;
    }

    /* Clean up the context */
    bool res = uta_api.close not_eq 0 and uta_api.close(uta_ctx) is_eq UTA_SUCCESS;
    if(not res)
    {
        LOG_err("ERROR during uta.close");
    }

    OPENSSL_free(uta_ctx);
    return res;
}


bool uta_getkey(uta_ctx* uta_ctx, const unsigned char* dv, size_t dvlen, unsigned char* out, size_t outlen)
{
    unsigned char md[SHA256_DIGEST_LENGTH];

    if(uta_api.derive_key is_eq 0)
    {
        LOG(FL_ERR, "uta_api not initialized");
        return false;
    }
    if(uta_ctx is_eq 0)
    {
        LOG(FL_ERR, "uta_ctx argument is 0");
        return false;
    }

    if(0 is_eq out)
    {
        LOG(FL_ERR, "out is 0");
        return false;
    }

    if(0 is_eq dv and 0 not_eq dvlen)
    {
        LOG(FL_ERR, "non consistent input (derivation value) dv is null and dvlen is non-zero");
        return false;
    }

    /* Check if output lenth is as statically expected */
    if(outlen > TA_OUTLEN)
    {
        LOG(FL_ERR, "Requested TA output length %d larger than %d", outlen, TA_OUTLEN);
        return false;
    }

    /* In case the DV does not yet have the needed length, take a hash of it */
    if(dvlen not_eq DVLEN)
    {
#if DVLEN > SHA256_DIGEST_LENGTH
#error Cannot produce DV with length DVLEN larger than SHA256_DIGEST_LENGTH
#endif
        if(0 is_eq SHA256(dv, dvlen, md))
        {
            LOG_err("ERROR during SHA calculation");
            return false;
        }
        dvlen = DVLEN;
        dv = md; /* will use first DVLEN bytes */
    }

    /* Derive key from the trust anchor */
    int scope = 1; /* use device-specific key */
    if(uta_api.derive_key(uta_ctx, out, outlen, dv, dvlen, scope) not_eq UTA_SUCCESS)
    {
        LOG_err("ERROR during uta.derive_key");
        return false;
    }

    return true;
}


bool uta_get_random(uta_ctx* ctx, uint8_t* dst, size_t cnt)
{
    if(uta_api.get_random is_eq 0)
    {
        LOG(FL_ERR, "uta_api not initialized");
        return false;
    }
    if(ctx is_eq 0)
    {
        LOG(FL_ERR, "uta_ctx argument is 0");
        return false;
    }

    if(dst is_eq 0)
    {
        LOG(FL_ERR, "dst is 0");
        return false;
    }

    if(uta_api.get_random(ctx, dst, cnt) not_eq UTA_SUCCESS)
    {
        LOG_err("ERROR during uta.get_random");
        return false;
    }

    return true;
}

#else
typedef int make_iso_compilers_happy_on_empty_translation_unit;
#endif /* defined SECUTILS_USE_UTA  */
