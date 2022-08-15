/** 
* @file certstatus.c
* 
* @brief Certificate status checking using CRLs and/or OCSP
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

#include <openssl/x509v3.h>
#ifndef SECUTILS_NO_TLS
# include <openssl/ssl.h>
#endif

#include <util/log.h>
#include <credentials/cert.h>
#include <credentials/store.h>
#include <credentials/verify.h>
#include <certstatus/certstatus.h>
#include <certstatus/crls.h>
#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0
# include <certstatus/ocsp.h>
#endif

#include <operators.h>

static int num_CDPs(const X509* cert)
{
    CRL_DIST_POINTS* cdps = X509_get_ext_d2i(cert, NID_crl_distribution_points, 0, 0);
    if(cdps is_eq 0) /* maybe there is still a CDP for delta CRLs */
    {
        cdps = X509_get_ext_d2i(cert, NID_freshest_crl, 0, 0);
    }
    int res = cdps not_eq 0 ? sk_DIST_POINT_num(cdps) : 0;
    CRL_DIST_POINTS_free(cdps);
    return res;
}

static int num_AIAs(const X509* cert)
{
    STACK_OF(OPENSSL_STRING) *aias = X509_get1_ocsp((X509 *)cert);
    int res = aias not_eq 0 ? sk_OPENSSL_STRING_num(aias) : 0;
    X509_email_free(aias);
    return res;
}

void LOG_certstatus_sources(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                            X509_STORE* trust_store, const char* verb, const X509* cert)
{
    const revstatus_access *cdps = STORE_get0_cdps(trust_store);
    const revstatus_access *ocsp = STORE_get0_ocsp(trust_store);
    const bool use_CDP = (cdps->flags bitand REVSTATUS_IGNORE_CERT_EXT) is_eq 0;
    const bool use_AIA = (ocsp->flags bitand REVSTATUS_IGNORE_CERT_EXT) is_eq 0;
    const int n = num_CDPs(cert);
    const int m = num_AIAs(cert);
    LOG(func, file, lineno, level,
        "%s cert having %d%s CDP entr%s and %d%s AIA entr%s "
        "with%s fallback CDP URL(s) and with%s fallback OCSP responder URL(s)",
        verb, n, use_CDP ? "" : " disabled", n == 1 ? "y" : "ies",
        m, use_AIA ? "" : " disabled", m == 1 ? "y" : "ies",
        cdps->urls is_eq 0 ? "out" : "", ocsp->urls is_eq 0 ? "out" : "");
}

void LOG_certstatus_methods(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                            X509_STORE_CTX* ctx, const char* verb, bool check_single)
{
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
    unsigned long flags = X509_VERIFY_PARAM_get_flags(param);
    int check_all = (flags bitand X509_V_FLAG_STATUS_CHECK_ALL) not_eq 0;
    int check_any = (flags bitand X509_V_FLAG_STATUS_CHECK_ANY) not_eq 0;
    int ocsp_stapling = (flags bitand X509_V_FLAG_OCSP_STAPLING) not_eq 0;
    int ocsp_check = (flags bitand X509_V_FLAG_OCSP_CHECK) not_eq 0;
    int ocsp_last = (flags bitand X509_V_FLAG_OCSP_LAST) not_eq 0;
    int crl_check = (flags bitand X509_V_FLAG_CRL_CHECK) not_eq 0;

    const char *desc = STORE_get0_desc(X509_STORE_CTX_get0_store(ctx));
    LOG(func, file, lineno, level, "for%s%s cert status checks%s%s, %s %s%s%s%s%s",
        check_single ? " single" : check_all ? " full" : check_any ? " any" : " leaf",
        STORE_CTX_tls_active(ctx) ? " TLS" : "",
        desc == NULL ? "" : " for ", desc == NULL ? "" : desc,
        verb,
        ocsp_stapling ? "OCSP stapling" : "",
        ocsp_stapling and crl_check ? " then " : "",
        crl_check ? "local CRLs" : "",
        (ocsp_stapling or crl_check) and
        (ocsp_check or crl_check) ? " then " : "",
        ocsp_check ? (crl_check ? (ocsp_last ? "CDPs then OCSP"
                                             : "OCSP then CDPs")
                                : "OCSP")
                   : (crl_check ? "CDPs" :
                      (ocsp_stapling or crl_check) ? "" : "nothing"));
}

void LOG_certstatus_mark(OPTIONAL const char* func, OPTIONAL const char* file, int lineno,
                         X509_STORE_CTX* ctx, const char *desc, int res)
{
    bool nonfinal = STORE_CTX_nonfinal(ctx);
    severity level = nonfinal ? LOG_DEBUG: LOG_ERR;

    if(res <= 0)
    {
        if(nonfinal)
        {
            (void)ERR_pop_to_mark();
        }
        else
        {
            (void)ERR_clear_last_mark();
        }
    }
    if(res is_eq 0)
    {
        LOG(func, file, lineno, level, "%s was negative: cert revoked or rejected", desc);
    }
    else
    {
        if(res < 0)
        {
            LOG(func, file, lineno, LOG_DEBUG, "%s is inconclusive", desc);
        }
        else
        {
            (void)ERR_pop_to_mark();
            LOG(func, file, lineno, LOG_TRACE, "%s was positive: cert appears fine", desc);
        }
    }
}

bool STORE_CTX_nonfinal(const X509_STORE_CTX* ctx)
{
    X509_VERIFY_PARAM* vpm = X509_STORE_CTX_get0_param((X509_STORE_CTX*)ctx);
    unsigned long flags = X509_VERIFY_PARAM_get_flags(vpm);
    return (flags bitand X509_V_FLAG_NONFINAL_CHECK) not_eq 0;
}

#define OCSP_err(ok) \
    ((ok) is_eq -2 ? X509_V_ERR_OCSP_VERIFY_NEEDED /* no OCSP resp available */ : \
     (ok) not_eq 0 ? X509_V_ERR_OCSP_VERIFY_FAILED : X509_V_ERR_CERT_REVOKED)
bool check_cert_revocation(X509_STORE_CTX* ctx, OPTIONAL OCSP_RESPONSE* resp)
{
    X509_STORE* ts = X509_STORE_CTX_get0_store(ctx);
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    X509* cert = sk_X509_value(chain, depth);

    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
    unsigned long flags = X509_VERIFY_PARAM_get_flags(param);
    int check_all = (flags bitand X509_V_FLAG_STATUS_CHECK_ALL) not_eq 0;
    int check_any = (flags bitand X509_V_FLAG_STATUS_CHECK_ANY) not_eq 0;
    int ocsp_stapling = (flags bitand X509_V_FLAG_OCSP_STAPLING) not_eq 0;
    int ocsp_check = (flags bitand X509_V_FLAG_OCSP_CHECK) not_eq 0;
#ifndef SEC_NO_CRL_DOWNLOAD
    int ocsp_last = (flags bitand X509_V_FLAG_OCSP_LAST) not_eq 0;
#endif
    int crl_check = (flags bitand X509_V_FLAG_CRL_CHECK) not_eq 0;
    int ok = 0;

    LOG_cert(FL_DEBUG, "start checking revocation status for", cert);
    CERT_print(cert, bio_trace, X509_FLAG_NO_EXTENSIONS);
    LOG_certstatus_sources(FL_TRACE, ts, "will check", cert);
    LOG_certstatus_methods(FL_DEBUG, ctx, "will try checking", true);
    /* status checking issues will be reported as errors only for last enabled method */
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NONFINAL_CHECK);

    if(ocsp_stapling)
    {
#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0
        int num = sk_X509_num(chain);
        X509* issuer = sk_X509_value(chain, depth < num - 1 ? depth + 1 : num - 1);
        const bool final = not ocsp_check and not crl_check;
        if(final)
        {
            X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_NONFINAL_CHECK);
        }
        if(resp not_eq 0) /* (stapled) OCSP response is available */
        {
            LOG(FL_DEBUG, "try using stapled OCSP response");
            (void)ERR_set_mark();
            ok = check_ocsp_resp(ts, chain, cert, issuer, resp);
            LOG_certstatus_mark(LOG_FUNC_FILE_LINE, ctx, "cert status checking using stapled OCSP response", ok);
        }
        else
        {
            ok = -2; /* no OCSP response available */
        }
        if(ok is_eq 1) /* cert status ok */
        {
            LOG(FL_DEBUG, "succeeded checking revocation status using OCSP stapling");
            return true;
        }
        if(ok is_eq 0  /* cert revoked, thus a clear failure */
           or (ok < 0 /* OCSP stapling was inconclusive */
               and final)) /* is the only check */
        {
            return verify_cb_cert(ctx, cert, OCSP_err(ok));
        }
#endif /* !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0 */
    }
    /* OCSP stapling is disabled or inconclusive */

    if(!check_all and check_any and num_CDPs(cert) is_eq 0 and num_AIAs(cert) is_eq 0)
    {
        LOG_cert(FL_WARN, "skipping revocation check due to missing CDP and AIA entries for", cert);
        return true;
    }


    if(crl_check)
    {
        LOG(FL_DEBUG, "trying local CRLs");
#ifdef SEC_NO_CRL_DOWNLOAD
        crl_check = false;
#endif
        const bool final = not ocsp_check and not crl_check;
        if(final)
        {
            X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_NONFINAL_CHECK);
        }
        ok = check_cert_crls(ctx, 0); /* try locally available CRLs */
        if(ok >= 0 or final)
        {
            if(ok > 0)
            {
                LOG(FL_DEBUG, "succeeded checking revocation status using local CRLs");
            }
            return ok > 0; /* verify_cb_cert() has already been called internally if ok <= 0 */
        }
    }
    /* CRL check is disabled or inconclusive using local CRLs */

#ifndef SEC_NO_CRL_DOWNLOAD
    if(crl_check and ocsp_check and ocsp_last) /* nonfinal CRL check */
    {
        LOG(FL_DEBUG, "trying CRLs from CDPs");
        const bool final = not ocsp_check; /* cannot be true here */
        if(final)
        {
            X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_NONFINAL_CHECK);
        }
        ok = check_cert_status_cdps(ctx);
        if(ok is_eq 1) /* cert status ok */
        {
            LOG(FL_DEBUG, "succeeded checking revocation status using CRLs from CDPs");
            return true;
        }
        crl_check = false; /* do not try CDPs again */
        if(ok is_eq 0 /* CRL-based check gave a clear failure */ or
            /* CRL-based check was inconclusive (ok < 0) and is the last one: */
           (ok < 0 and /* cannot happen here: */ final))
        {
            return false; /* verify_cb_cert() has already been called internally if ok <= 0 */
        }
        /* CRL-based check is inconclusive */
    }
#endif

    if(ocsp_check)
    {
#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0
        int num = sk_X509_num(chain);
        X509* issuer = sk_X509_value(chain, depth < num - 1 ? depth + 1 : num - 1);
        STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(ctx);
        STACK_OF(X509) *sk = sk_X509_new_reserve(0, sk_X509_num(chain)
                                                 + sk_X509_num(untrusted));

        LOG(FL_DEBUG, "trying plain OCSP");
        if(sk is_eq 0
           or not UTIL_sk_X509_add1_certs(sk, chain, 1 /*no self-signed */, 0)
           or not UTIL_sk_X509_add1_certs(sk, untrusted, 1 /*no self-signed */, 1/* no dups */))
        {
            CERTS_free(sk);
            return false;
        }
        const bool final = not crl_check;
        if(final)
        {
            X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_NONFINAL_CHECK);
        }
        ok = check_cert_status_ocsp(ctx, sk, cert, issuer);
        CERTS_free(sk);
        if(ok is_eq 1) /* cert status ok */
        {
            ERR_clear_error();
            /*
               this clears the error queue from any error while fetching CRLs such as:
               OpenSSL:parse_http_line1():crypto/ocsp/ocsp_ht.c:260: ERROR: server response error : Code=404,Reason=Not Found
            */
            LOG(FL_DEBUG, "succeeded checking revocation status using OCSP");
            return true;
        }
        if(ok is_eq 0 or /* cert revoked or unknown, thus a clear failure */
           /* OCSP check was inconclusive (ok < 0) and is the last one: */
           (ok < 0 and final))
        {
            return verify_cb_cert(ctx, cert, OCSP_err(ok));
        }
#endif /* !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0 */
    }
    /* OCSP (including stapling) is disabled or inconclusive */

#ifndef SEC_NO_CRL_DOWNLOAD
    if(crl_check) /* implies at this point: !ocsp_check || !ocsp_last */
    {
        X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_NONFINAL_CHECK);
        LOG(FL_DEBUG, "trying CRLs from CDPs");
        ok = check_cert_status_cdps(ctx);
        if(ok > 0)
        {
            LOG(FL_DEBUG, "succeeded checking revocation status using CRLs from CDPs");
        }
        return ok > 0; /* verify_cb_cert() has already been called internally if ok <= 0 */
    }
#endif

    LOG(FL_WARN, "no cert status checking method is enabled");
    return true;
}

int check_revocation_any_method(X509_STORE_CTX* ctx)
{
    if(0 is_eq ctx)
    {
        LOG(FL_ERR, "null ctx argument");
        return false;
    }

    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    int i;
    int last = 0;
    int num = sk_X509_num(chain);
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
    unsigned long flags = X509_VERIFY_PARAM_get_flags(param);
    int check_all = (flags bitand X509_V_FLAG_STATUS_CHECK_ALL) not_eq 0;
    int check_any = (flags bitand X509_V_FLAG_STATUS_CHECK_ANY) not_eq 0;
    int ocsp_stapling = (flags bitand X509_V_FLAG_OCSP_STAPLING) not_eq 0;

    LOG_certstatus_methods(FL_DEBUG, ctx, "will try checking", false);
    if(check_all or check_any)
    {
        last = num - 1;
    }
    else
    {
        /* If checking CRL paths this is not the EE certificate */
        if(X509_STORE_CTX_get0_parent_ctx(ctx))
        {
            LOG(FL_DEBUG, "skipping revocation check while validating a CRL");
            return true;
        }
        last = 0;
    }
    for(i = 0; i <= last; i++)
    {
        X509* cert = sk_X509_value(chain, i); /* check i-th cert in chain */

        if(i is_eq last and X509_check_issued(cert, cert) is_eq X509_V_OK)
        {
            LOG_cert(FL_DEBUG, "skipping revocation check for self-issued last", cert);
            break;
        }
        X509_STORE_CTX_set_error_depth(ctx, i);

#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0
        /* First consider OCSP stapling if ssl is set, then any other method */
        if(ocsp_stapling and STORE_CTX_tls_active(ctx) and
           i is_eq 0 /* only for TLS server cert; OCSP multi-stapling is not supported */)
        {
        /* We were called from ssl_verify_cert_chain() at state TLS_ST_CR_CERT.
           Stapled OCSP response becomes available only at TLS_ST_CR_CERT_STATUS
           and ocsp_stapling_cb() is called even later, at TLS_ST_CR_SRVR_DONE.
           What we can do here is to defer status checking of the current cert.
           This will then be performed by ocsp_stapling_cb(). */
            LOG(FL_DEBUG, "deferring status check for leaf cert to prefer OCSP stapling");
            continue;
        }

        if(not check_cert_revocation(ctx, 0))
        {
            return false;
        }
#else /* defined(OPENSSL_NO_OCSP) || OPENSSL_VERSION_NUMBER < OPENSSL_V_1_1_0 */
        if ((flags bitand X509_V_FLAG_OCSP_CHECK) not_eq 0 or
            (flags bitand X509_V_FLAG_OCSP_LAST) not_eq 0 or ocsp_stapling)
        {
            if((flags bitand X509_V_FLAG_CRL_CHECK) is_eq 0)
            {
                LOG(FL_ERR, "Sorry, this build does not support OCSP");
                LOG_cert(FL_ERR, "verification unsuccessful for", cert);
                return false;
            }
            LOG(FL_WARN, "Sorry, this build does not support OCSP. Using CRLs only");
        }
        if((flags bitand X509_V_FLAG_CRL_CHECK) not_eq 0)
        {
            const revstatus_access *cdps = STORE_get0_cdps(X509_STORE_CTX_get0_store(ctx));
            bool use_CDP = (cdps->flags bitand REVSTATUS_IGNORE_CERT_EXT) is_eq 0;
            if (use_CDP)
                X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NONFINAL_CHECK);
            int res = check_cert_crls(ctx, 0); /* try locally available CRLs */
            X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_NONFINAL_CHECK);
            if(res is_eq 0 or (res is_eq -1 and check_cert_status_cdps(ctx) not_eq 1))
            {
                return false;
            }
        }
#endif /* !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0 */

        chain = X509_STORE_CTX_get0_chain(ctx); /* for some reason need again */

    }
    return true;
}


/*
 * @brief Function to check certificate revocation of a certificate and its
 * issuer at depth determined by X509_STORE_CTX error_depth
 * @param ctx pointer to X509 store context
 * @return X509_V_OK (0) on success
 *         X509_V_ERR_ (>0) error code on failure
 */
static int check_local_cert_crls(X509_STORE_CTX* ctx)
{
    if(0 is_eq ctx)
    {
        LOG(FL_ERR, "null parameter ctx");
        return X509_V_ERR_UNSPECIFIED;
    }

    X509_STORE_CTX* tmp_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_check_revocation_fn check_revocation;
    int cert_idx = X509_STORE_CTX_get_error_depth(ctx);
    X509* cert = sk_X509_value(X509_STORE_CTX_get0_chain(ctx), cert_idx);
    X509* issuer = sk_X509_value(X509_STORE_CTX_get0_chain(ctx), cert_idx+1);
    int ssl_ex_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    SSL* ssl = X509_STORE_CTX_get_ex_data(ctx, ssl_ex_idx);
    STACK_OF(X509) *certs;
    int ret = X509_V_ERR_UNSPECIFIED;

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
    if(not X509_STORE_CTX_init(tmp_ctx, X509_STORE_CTX_get0_store(ctx),
                               0, 0) /* inherits flags etc. of store */
       or not X509_STORE_CTX_set_ex_data(tmp_ctx, ssl_ex_idx, ssl))
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
    X509_VERIFY_PARAM_clear_flags(tmp_vpm, X509_V_FLAG_CRL_CHECK_ALL);
    X509_VERIFY_PARAM_set_flags(tmp_vpm, X509_V_FLAG_NONFINAL_CHECK | X509_V_FLAG_NO_CHECK_TIME);
    int res = (*check_revocation)(tmp_ctx); /* checks only depth 0 */

    if(res is_eq 0)
    {
        ret = X509_STORE_CTX_get_error(tmp_ctx);
    }
    else
    {
        ret = X509_V_OK;
    }

 err:
    X509_STORE_CTX_free(tmp_ctx);
    return ret;
}

static bool crl_time_valid(const X509_CRL* crl, const X509_VERIFY_PARAM* vpm)
{
    time_t check_time, *ptime = 0;
    const ASN1_TIME* crl_end_time;
    const ASN1_TIME* crl_last_update;
    unsigned long flags = X509_VERIFY_PARAM_get_flags((X509_VERIFY_PARAM*)vpm);

    if((flags bitand X509_V_FLAG_USE_CHECK_TIME) not_eq 0)
    {
        check_time = X509_VERIFY_PARAM_get_time(vpm);
        ptime = &check_time;
    }
    crl_end_time = X509_CRL_get0_nextUpdate(crl);
    crl_last_update = X509_CRL_get0_lastUpdate(crl);

    if ((crl_end_time not_eq 0 and X509_cmp_time(crl_end_time, ptime) not_eq 1) or
        (crl_last_update not_eq 0 and X509_cmp_time(crl_last_update, ptime) not_eq -1))
    {
        return false;
    }

    return true;
}

int check_revocation_local_only_method(X509_STORE_CTX* ctx)
{
    if(0 is_eq ctx)
    {
        LOG(FL_ERR, "null parameter ctx");
        return 0;
    }

    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    int i = 0;
    const int last = sk_X509_num(chain) - 1;

    for(i = 0; i <= last; i++)
    {
        X509* cert = sk_X509_value(chain, i);
        if(i is_eq last and X509_check_issued(cert, cert) is_eq X509_V_OK)
        {
            LOG_cert(FL_DEBUG, "skipping revocation check for self-issued last", cert);
            break;
        }

        STACK_OF(X509_CRL)* crls = X509_STORE_CTX_get1_crls(ctx, X509_get_issuer_name(cert));
        if(not crls or 0 is_eq sk_X509_CRL_num(crls) or 0 is_eq sk_X509_CRL_value(crls, 0))
        {
            char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
            if (0 not_eq issuer)
            {
                LOG(FL_ERR, "Local CRL for %s certificate %s not found",
                    (i + 1 is_eq last) ? "root" : "issuing", issuer);
                OPENSSL_free(issuer);
            }
            return 0;
        }

        if(true not_eq crl_time_valid(sk_X509_CRL_value(crls, 0), X509_STORE_CTX_get0_param(ctx)))
        {
            char* issuer = X509_NAME_oneline(X509_CRL_get_issuer(sk_X509_CRL_value(crls, 0)), 0, 0);
            if(issuer not_eq 0)
            {
                LOG(FL_WARN, "CRL issued by %s is not valid in time", issuer);
                OPENSSL_free(issuer);
            }
        }

        sk_X509_CRL_pop_free(crls, X509_CRL_free);

        X509_STORE_CTX_set_error_depth(ctx, i);
        int res = check_local_cert_crls(ctx);

        if(X509_V_OK not_eq res)
        {
            verify_cb_cert(ctx, cert, res);
            return 0;
        }
        chain = X509_STORE_CTX_get0_chain(ctx); /* for some reason need again */
    }
    return 1;
}
