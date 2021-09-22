/** 
* @file crls.c
* 
* @brief Certificate status checking using CRLs
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

#include <string.h>

#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#ifndef SECUTILS_NO_TLS
# include <openssl/ssl.h>
#endif

#include <util/log.h>
#include <certstatus/crls.h>
#include <credentials/store.h>
#include <credentials/verify.h>
#include <connections/conn.h>

#include <operators.h>

X509_CRL* CONN_load_crl_http(const char* url, int timeout,
                             unsigned long max_resp_len, OPTIONAL const char* desc)
{
    severity level = desc is_eq 0 ? LOG_DEBUG: LOG_ERR;
    const char* desc_default = desc is_eq 0 ? "(unknown)" : desc;

    if(timeout < 0)
    {
        timeout = CRL_DOWNLOAD_DEFAULT_TIMEOUT;
    }
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) && !defined(SEC_NO_CRL_DOWNLOAD)
    X509_CRL *crl = (X509_CRL*)CONN_load_ASN1_http(url, timeout, max_resp_len, 0, 0, 0, ASN1_ITEM_rptr(X509_CRL), desc);
    if(crl == NULL)
    {
        LOG(LOG_FUNC_FILE_LINE, level, "did not get CRL for %s", desc_default);
    }
    else
    {
        LOG(FL_DEBUG, "got CRL for %s", desc_default);
    }
    return crl;
#else
    LOG(LOG_FUNC_FILE_LINE, level, "fetching CRLs for %s via HTTP not supported by this build", desc_default);
    return 0;
#endif
}

static void warn_crl(const X509_STORE_CTX* ctx, const X509_CRL * crl)
{
    if(0 is_eq ctx or 0 is_eq crl)
    {
        LOG(FL_ERR, "null argument");
        return;
    }

    const X509_VERIFY_PARAM* vpm = X509_STORE_CTX_get0_param((X509_STORE_CTX*)ctx);
    unsigned long flags = X509_VERIFY_PARAM_get_flags((X509_VERIFY_PARAM*)vpm);
    if((flags bitand X509_V_FLAG_NO_CHECK_TIME) not_eq 0)
    {
        return;
    }
    time_t check_time, *ptime = 0;
    if((flags bitand X509_V_FLAG_USE_CHECK_TIME) not_eq 0)
    {
        check_time = X509_VERIFY_PARAM_get_time(vpm);
        ptime = &check_time;
    }
    const ASN1_TIME* crl_end_time = X509_CRL_get0_nextUpdate(crl);
    const ASN1_TIME* crl_last_update = X509_CRL_get0_lastUpdate(crl);
    char* issuer = X509_NAME_oneline(X509_CRL_get_issuer(crl), 0, 0);
    if(issuer not_eq 0)
    {
        if(crl_end_time not_eq 0 and X509_cmp_time(crl_end_time, ptime) not_eq 1)
        {

            LOG(FL_WARN, "CRL issued by %s is no more valid", issuer);
        }
        if(crl_last_update not_eq 0 and X509_cmp_time(crl_last_update, ptime) not_eq -1)
        {

            LOG(FL_WARN, "CRL issued by %s is not yet valid", issuer);
        }
        OPENSSL_free(issuer);
    }
}

/* like check_cert() of OpenSSL:crypto/x509/x509_vfy.c, may use extra CRLs */
int check_cert_crls(X509_STORE_CTX* ctx, OPTIONAL STACK_OF(X509_CRL) * crls)
{
    int res = -1;
    if(0 is_eq ctx)
    {
        LOG(FL_ERR, "null ctx argument");
        return res;
    }

    X509_STORE* ts = X509_STORE_CTX_get0_store(ctx);
    X509_STORE_CTX* tmp_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_check_revocation_fn check_revocation;
    int cert_idx = X509_STORE_CTX_get_error_depth(ctx);
    X509* cert = sk_X509_value(X509_STORE_CTX_get0_chain(ctx), cert_idx);
    X509* issuer = sk_X509_value(X509_STORE_CTX_get0_chain(ctx), cert_idx+1);
#ifndef SECUTILS_NO_TLS
    int ssl_ex_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    SSL* ssl = X509_STORE_CTX_get_ex_data(ctx, ssl_ex_idx);
#endif
    STACK_OF(X509) *certs;

    if(crls is_eq 0) /* this means local CRLs */
    {
        (void)ERR_set_mark();
    }
    /*
     * Unfortunately, check_revocation() in crypto/x509/x509_vfy.c is static,
     * yet we can get hold of it via X509_STORE_CTX_get_check_revocation().
     */
    if(tmp_ctx is_eq 0
       or not X509_STORE_CTX_init(tmp_ctx, 0, 0, 0)
       or ((check_revocation = X509_STORE_CTX_get_check_revocation(tmp_ctx)) is_eq 0))
    {
        LOG(FL_ERR, "cannot get pointer to check_revocation()");
        goto err;
    }
    X509_STORE_CTX_set0_param(tmp_ctx, 0); /* free tmp_ctx->param */
    if(not X509_STORE_CTX_init(tmp_ctx, ts, 0, 0) /* inherits flags etc. of store */
#ifndef SECUTILS_NO_TLS
       or not X509_STORE_CTX_set_ex_data(tmp_ctx, ssl_ex_idx, ssl)
#endif
       )
    {
        LOG(FL_ERR, "cannot set up tmp_ctx");
        goto err;
    }
    if((certs = sk_X509_new_reserve(0, 2)) is_eq 0
       or (X509_STORE_CTX_set0_verified_chain(tmp_ctx, certs), 0)
       or cert   is_eq 0 or not sk_X509_push(certs, X509_dup(cert))
       or issuer is_eq 0 or not sk_X509_push(certs, X509_dup(issuer)))
    {
        LOG(FL_ERR, "cannot set certs in tmp_ctx");
        goto err;
    }

    X509_VERIFY_PARAM* tmp_vpm = X509_STORE_CTX_get0_param(tmp_ctx);
    if(STORE_CTX_nonfinal(ctx))
    {
        X509_VERIFY_PARAM_set_flags(tmp_vpm, X509_V_FLAG_NONFINAL_CHECK);
    }
    X509_VERIFY_PARAM_clear_flags(tmp_vpm, X509_V_FLAG_CRL_CHECK_ALL);
    X509_STORE_CTX_set0_crls(tmp_ctx, crls);
    {
        STACK_OF(X509_CRL) * tmp_crls = X509_STORE_CTX_get1_crls(tmp_ctx, X509_get_issuer_name(cert));
        X509_CRL *crl;
        while ((crl = sk_X509_CRL_shift(tmp_crls)) != NULL) {
            warn_crl(ctx, crl);
            X509_CRL_free(crl);
        }
        sk_X509_CRL_free(tmp_crls);
    }
    res = (*check_revocation)(tmp_ctx); /* checks only depth 0 */
    X509_STORE_CTX_set0_crls(tmp_ctx, 0);

    if(res is_eq 0)
    {
        int cert_error = X509_STORE_CTX_get_error(tmp_ctx);
        if (cert_error is_eq X509_V_ERR_UNSPECIFIED or
            cert_error is_eq X509_V_ERR_UNABLE_TO_GET_CRL or
            cert_error is_eq X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE or
            cert_error is_eq X509_V_ERR_CRL_SIGNATURE_FAILURE or
            cert_error is_eq X509_V_ERR_CRL_NOT_YET_VALID or
            cert_error is_eq X509_V_ERR_CRL_HAS_EXPIRED or
            cert_error is_eq X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD or
            cert_error is_eq X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD or
            cert_error is_eq X509_V_ERR_OUT_OF_MEM or
            cert_error is_eq X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER or
            cert_error is_eq X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION or
            cert_error is_eq X509_V_ERR_DIFFERENT_CRL_SCOPE or
            cert_error is_eq X509_V_ERR_CRL_PATH_VALIDATION_ERROR or
            cert_error is_eq X509_V_ERR_OCSP_VERIFY_NEEDED)
            /* X509_V_ERR_CERT_REVOKED would be wrong here because it is conclusive */
            res = -1; /* inconclusive */
    }

 err:
    if(crls is_eq 0)
    {
        LOG_certstatus_mark(LOG_FUNC_FILE_LINE, ctx,
                            "cert status checking using local CRLs", res);
    }
    X509_STORE_CTX_free(tmp_ctx);
    return res;
}

#ifndef SEC_NO_CRL_DOWNLOAD

/* adapted from OpenSSL:apps/lib/apps.c */
static const char* get_dp_url(DIST_POINT* dp)
{
    GENERAL_NAMES* gens;
    GENERAL_NAME* gen;
    int i;
    int gtype;
    ASN1_STRING* uri;

    if (dp->distpoint is_eq 0 or dp->distpoint->type not_eq 0)
        return 0;
    gens = dp->distpoint->name.fullname;
    for(i = 0; i < sk_GENERAL_NAME_num(gens); i++)
    {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if(gtype is_eq GEN_URI and ASN1_STRING_length(uri) > 6)
        {
            char* uptr = (char*)ASN1_STRING_get0_data(uri);
            if(strncasecmp(uptr, CONN_http_prefix, strlen(CONN_http_prefix)) is_eq 0
               or strncasecmp(uptr, "file:", 5) is_eq 0)
            {
                return uptr;
            }
        }
    }
    return 0;
}

static int try_cdp(X509_STORE_CTX* ctx, int timeout, const X509* cert,
                   OPTIONAL const char* url, STACK_OF(DIST_POINT) *crldps_done, X509_CRL* delta_crl, bool nonfinal, const char* desc)
{
    X509_STORE* ts = X509_STORE_CTX_get0_store(ctx);
    STACK_OF(X509_CRL) *crls = 0;
    int res = -2; /* no CRL available, thus inconclusive */
    int i;

    for(i = 0; i < sk_DIST_POINT_num(crldps_done); i++)
    {
        const char* cdp_url = get_dp_url(sk_DIST_POINT_value(crldps_done, i));
        if (url not_eq 0 and cdp_url not_eq 0 and strcmp(cdp_url, url) is_eq 0)
        {
            LOG(FL_TRACE, "ignoring duplicate fallback CDP URL: %s", url);
            return res;
        }
    }
    LOG(FL_DEBUG, "retrieving CRL from %s%s%s", desc,
        url not_eq 0 ? ": " : "", url not_eq 0 ? url : "");

    X509_CRL* crl = STORE_fetch_crl(ts, url, timeout, cert, nonfinal ? 0 : desc);
    if (crl is_eq 0)
    {
        return res;
    }
    LOG(FL_TRACE, "successfully downloaded CRL from %s", url not_eq 0 ? url : "URL based on any info in cert");
    UTIL_print_crl(bio_trace, crl);

    crls = sk_X509_CRL_new_null();
    if(crls is_eq 0 or not sk_X509_CRL_push(crls, crl))
    {
        LOG(FL_ERR, "out of memory");
        goto err;
    }
    if (delta_crl not_eq 0)
    {
        if (sk_X509_CRL_push(crls, delta_crl) == 0)
            goto err;
    }
    res = check_cert_crls(ctx, crls);
    if (delta_crl not_eq 0)
    {
        sk_X509_CRL_pop(crls); /* delta_crl */
    }

 err:
    sk_X509_CRL_free(crls);
    X509_CRL_free(crl); /* TODO cache crl instead */
    return res;
}


/* Calls the OpenSSL check_cert() function from crypto/x509/x509_vfy.c */
int check_cert_status_cdps(X509_STORE_CTX* ctx)
{
    /* Not using ctx->get_crl or ctx->lookup_crls because their use in
       check_cert() and get_crl_delta() is not flexible w.r.t. inconclusive */
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    X509* cert = sk_X509_value(chain, X509_STORE_CTX_get_error_depth(ctx));
    X509_STORE* ts = X509_STORE_CTX_get0_store(ctx);
    bool nonfinal = STORE_CTX_nonfinal(ctx);
    const revstatus_access *cdps = STORE_get0_cdps(ts);
    bool use_CDP = (cdps->flags bitand REVSTATUS_IGNORE_CERT_EXT) is_eq 0;
    STACK_OF(DIST_POINT) *delta_crldp =
        use_CDP ? X509_get_ext_d2i(cert, NID_freshest_crl, 0, 0) : 0;
    int n_delta = sk_DIST_POINT_num(delta_crldp);
    STACK_OF(DIST_POINT) *crldp =
        use_CDP ? X509_get_ext_d2i(cert, NID_crl_distribution_points, 0, 0) : 0;
    char* fallback_urls = OPENSSL_strdup(cdps->urls);
    int timeout = cdps->timeout;
    int i;
    int res = -2; /* no CRL available, thus inconclusive */

    (void)ERR_set_mark();
    if(n_delta <= 0 and sk_DIST_POINT_num(crldp) <= 0)
    {
        LOG(FL_DEBUG, use_CDP ? "no HTTP CDP in cert" : "cert CDP use is disabled");
    }

    /* Try downloading any delta CRL */
    /* TODO sufficient to use the first delta CRL found for all CRLs ? */
    X509_CRL* delta_crl = 0;
    for(i = 0; delta_crl is_eq 0 and i < n_delta; i++)
    {
        const char* url = get_dp_url(sk_DIST_POINT_value(crldp, i));
        if(url not_eq 0)
        {
            LOG(FL_DEBUG, "trying to load delta CRL from CDP URL:", url);
            delta_crl = STORE_fetch_crl(ts, url, timeout, cert,
                                        nonfinal ? 0 : "delta CRL via Freshest CRL extension");
        }
    }
    if(n_delta > 0 && delta_crl is_eq 0)
    {
        LOG(FL_ERR, "cannot load any of the %d delta CRLs:", n_delta);
        res = 0; /* TODO should this really be considered an error ? */
        goto end;
    }

    /* Try downloading any base CRL */
    /* TODO sufficient to use the first CRL found ? */
    for(i = 0; res < 0 and i < sk_DIST_POINT_num(crldp); i++)
    {
        res = try_cdp(ctx, timeout, cert, get_dp_url(sk_DIST_POINT_value(crldp, i)),
                      0, delta_crl, nonfinal, "HTTP CDP entry in certificate");
    }

    if (res < 0)
    {
        res = try_cdp(ctx, timeout, cert, 0 /* use implicit url, could be taken from other cert data */,
                      0, 0, nonfinal, "any further info in cert");
    }

    if(res < 0 and fallback_urls is_eq 0)
    {
        LOG(FL_DEBUG, "no fallback CDP URL");
    }
    else
    {
        char* url;
        char* next;
        for(url = fallback_urls; res < 0 and url not_eq 0; url = next)
        {
            next = UTIL_next_item(url); /* must do this here to split string */
            res = try_cdp(ctx, timeout, cert, url, crldp, delta_crl, nonfinal, "fallback URL");
        }
    }

 end:
    X509_CRL_free(delta_crl);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    sk_DIST_POINT_pop_free(delta_crldp, DIST_POINT_free);
    OPENSSL_free(fallback_urls);

    if(res < 0 and verify_cb_cert(ctx, cert, X509_V_ERR_UNABLE_TO_GET_CRL))
    {
        res = 1;
    }
    LOG_certstatus_mark(LOG_FUNC_FILE_LINE, ctx,
                        "cert status checking using CDPs", res);
    return res;
}

#endif /* !defined(SEC_NO_CRL_DOWNLOAD) */
