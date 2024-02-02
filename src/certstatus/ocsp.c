/** 
* @file ocsp.c
* 
* @brief Certificate status checking using OCSP (optionally with stapling)
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

#include <util/log.h>

#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0

# include <openssl/ocsp.h>

# include <certstatus/ocsp.h>
# include <certstatus/crls.h>
# include <credentials/cert.h>
# include <credentials/store.h>
# include <credentials/verify.h>
# include <connections/http.h>
# ifndef SECUTILS_NO_TLS
#  include <connections/tls.h>
# endif

# include <operators.h>

OCSP_RESPONSE* CONN_load_OCSP_http(const char* url, int timeout,
                                   const OCSP_REQUEST* req,
                                   OPTIONAL const char* desc)
{
    if(timeout < 0)
    {
        timeout = OCSP_DEFAULT_TIMEOUT;
    }
    return (OCSP_RESPONSE*)
        CONN_load_ASN1_http(url, timeout, 0, "application/ocsp-request",
                            (const ASN1_VALUE*)req, ASN1_ITEM_rptr(OCSP_REQUEST),
                            ASN1_ITEM_rptr(OCSP_RESPONSE), desc);
}

/* Maximum leeway in validity period: default 5 minutes */
# define MAX_OCSP_VALIDITY_LEEWAY (5 * 60)

/* adapted from ocsp_main() of ocsp.c */
int check_ocsp_resp(X509_STORE* ts, STACK_OF(X509) *untrusted,
                    X509* cert, X509* issuer, OCSP_RESPONSE* resp)
{
    X509_VERIFY_PARAM* bak_vpm = 0;
    OCSP_BASICRESP* br = 0;
    OCSP_CERTID* id = 0;
    int status, reason, res = -1; /* inconclusive */
    ASN1_GENERALIZEDTIME* rev;
    ASN1_GENERALIZEDTIME* thisupd;
    ASN1_GENERALIZEDTIME* nextupd;

    if(resp is_eq 0)
    {
        return res;
    }

    if(bio_trace not_eq 0)
    {
        BIO_puts(bio_trace, "OCSP response:\n");
        BIO_puts(bio_trace, "======================================\n");
        OCSP_RESPONSE_print(bio_trace, resp, 0); /* unfortunately uses PEM_write_bio_X509() to print also base64-encoded cert blob  */
        BIO_puts(bio_trace, "======================================\n");
        BIO_flush(bio_trace);
    }

    status = OCSP_response_status(resp);
    if(status not_eq OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
        LOG(FL_ERR, "OCSP responder error: %s (code %d)",
                   OCSP_response_status_str(status), status);
        goto end;
    }

    if((br = OCSP_response_get1_basic(resp)) is_eq 0)
    {
        LOG(FL_ERR, "error getting OCSP basic response");
        goto end;
    }

    {
        /* must not do revocation checking on OCSP responder cert chain */
        const X509_STORE_CTX_check_revocation_fn bak_fn =
            X509_STORE_get_check_revocation(ts);
        X509_STORE_set_check_revocation(ts, 0);

        /* must not do host/ip/email checking on OCSP responder cert chain */
        X509_VERIFY_PARAM* ts_vpm = X509_STORE_get0_param(ts);
        if(not (bak_vpm = X509_VERIFY_PARAM_new())
           or not X509_VERIFY_PARAM_inherit(bak_vpm, ts_vpm) /* copy ts_vpm */
           or not X509_VERIFY_PARAM_set1_host(ts_vpm, 0, 0)
           or not X509_VERIFY_PARAM_set1_ip(ts_vpm, 0, 0)
           or not X509_VERIFY_PARAM_set1_email(ts_vpm, 0, 0)
           or not X509_VERIFY_PARAM_clear_flags(ts_vpm, X509_V_FLAG_CRL_CHECK)
           or not X509_VERIFY_PARAM_set_flags(ts_vpm, X509_V_FLAG_NONFINAL_CHECK))
        {
            goto end;
        }

        res = OCSP_basic_verify(br, untrusted, ts, 0 /* verify_flags */);

        if(not X509_STORE_set1_param(ts, bak_vpm) and res > 0)
        {
            res = -1;
        }
        X509_STORE_set_check_revocation(ts, bak_fn);
    }
    if(res <= 0)
    {
        res = -1; /* inconclusive */
        goto end;
    }

    res = -1;
    if((id = OCSP_cert_to_id(0, cert, issuer)) is_eq 0)
    {
        LOG(FL_ERR, "cannot obtain cert ID for OCSP");
        goto end;
    }
    if(not OCSP_resp_find_status(br, id,
                                 &status, &reason, &rev, &thisupd, &nextupd))
    {
        LOG(FL_ERR, "OCSP status not found");
        goto end;
    }

    /* TODO: OCSP_check_validity() should respect -attime: vpm->check_time */
    if(not OCSP_check_validity(thisupd, nextupd, MAX_OCSP_VALIDITY_LEEWAY, -1))
    {
        LOG(FL_ERR, "OCSP status times invalid");
        goto end;
    }
    else
    {
        switch (status)
        {
        case V_OCSP_CERTSTATUS_GOOD:
            LOG_cert(FL_TRACE, "OCSP status: good for", cert);
            res = 1;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            LOG(FL_ERR, "OCSP status: revoked, reason=%s",
                       reason not_eq -1 ? OCSP_crl_reason_str(reason) : "");
            res = 0;
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            LOG(FL_ERR, "OCSP status: unknown");
            res = 0; /* fatal: cert producer may have bypassed the CA! */
            break;
        default:
            LOG(FL_ERR, "OCSP status invalid (value %d)", status);
            res = -1; /* inconclusive */
            break;
        }
    }

 end:
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(br);
    X509_VERIFY_PARAM_free(bak_vpm);
    return res;
}

/* adapted from get_ocsp_resp_from_responder() of OpenSSL:apps/s_server.c */
/*
 * Get an OCSP_RESPONSE from a responder URL for the given cert and issuer.
 * This is a simplified version. It examines certificates each time and makes
 * one OCSP responder query for each request. A full version would store details
 * such as the OCSP certificate IDs and minimize the number of OCSP responses
 * by caching them until they were considered "expired".
 */
static OCSP_RESPONSE* get_ocsp_resp(X509* cert, X509* issuer,
                                    X509_EXTENSIONS* exts,
                                    const char* url, int timeout, bool nonfinal)
{
    OCSP_REQUEST* req = 0;
    OCSP_CERTID* id_copy, *id = 0;
    int res;
    OCSP_RESPONSE* resp = 0;
    OCSP_BASICRESP* br = 0;
    int i;

    if(cert is_eq 0 or issuer is_eq 0 or url is_eq 0)
    {
        LOG(FL_ERR, "0 argument");
        return 0;
    }

    if((req = OCSP_REQUEST_new()) is_eq 0
        or (id_copy = id = OCSP_cert_to_id(0, cert, issuer)) is_eq 0
        or (not OCSP_request_add0_id(req, id)))
    {
        goto end;
    }
    id = 0;
    if(not OCSP_request_add1_nonce(req, 0, -1))
    {
        goto end;
    }

    /* Add any extensions to the request */
    for(i = 0; i < sk_X509_EXTENSION_num(exts); i++)
    {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        if(not OCSP_REQUEST_add_ext(req, ext, -1))
        {
            goto end;
        }
    }

    resp = CONN_load_OCSP_http(url, timeout, req, nonfinal ? 0 : "OCSP response");
    if(resp is_eq 0)
    {
        LOG(FL_ERR, "error querying OCSP responder");
        goto end;
    }

    if((br = OCSP_response_get1_basic(resp)) is_eq 0)
    {
        LOG(FL_ERR, "error getting OCSP basic response");
        goto end;
    }
    if((res = OCSP_check_nonce(req, br)) <= 0)
    {
        LOG(FL_ERR, res is_eq -1 ? "no nonce in OCSP response" : "nonce verification error");
        goto end;
    }
    if(not OCSP_resp_find_status(br, id_copy, 0, 0, 0, 0, 0))
    {
        LOG(FL_ERR, "no OCSP status found matching cert ID in request");
        goto end;
    }

 end:
    OCSP_CERTID_free(id);
    OCSP_REQUEST_free(req);
    OCSP_BASICRESP_free(br);
    return resp;
}

static int try_ocsp(X509_STORE_CTX* ctx, STACK_OF(X509) *untrusted, X509* cert, X509* issuer, int timeout,
                    const char* url, STACK_OF(OPENSSL_STRING) *ocsps, const char* desc)
{
    X509_STORE* ts = X509_STORE_CTX_get0_store(ctx);
    bool nonfinal = STORE_CTX_nonfinal(ctx);
    int res = -2; /* no OCSP response available, thus inconclusive */

    if (url is_eq 0)
    {
        return res;
    }

    int i;
    for(i = 0; i < sk_OPENSSL_STRING_num(ocsps); i++)
    {
        const char* ocsp_url = sk_OPENSSL_STRING_value(ocsps, i);
        if (ocsp_url not_eq 0 and strcmp(ocsp_url, url) is_eq 0)
        {
            LOG(FL_TRACE, "ignoring duplicate fallback OCSP URL: %s", url);
            return res;
        }
    }

    LOG(FL_DEBUG, "consulting %s: %s", desc, url);
    OCSP_RESPONSE* resp = get_ocsp_resp(cert, issuer, 0, url, timeout, nonfinal);
    if(resp not_eq 0)
    {
        res = check_ocsp_resp(ts, untrusted, cert, issuer, resp);
        OCSP_RESPONSE_free(resp); /* TODO cache resp instead */
    }
    return res;
}

int check_cert_status_ocsp(X509_STORE_CTX* ctx, STACK_OF(X509) *untrusted,
                           X509* cert, X509* issuer)
{
    X509_STORE* ts = X509_STORE_CTX_get0_store(ctx);
    const revstatus_access *ocsp = STORE_get0_ocsp(ts);
    bool use_AIA = (ocsp->flags bitand REVSTATUS_IGNORE_CERT_EXT) is_eq 0;
    STACK_OF(OPENSSL_STRING) *ocsps = use_AIA ? X509_get1_ocsp(cert) : 0;
    char* fallback_urls = OPENSSL_strdup(ocsp->urls);
    int timeout = ocsp->timeout;
    int i;
    int res = -2; /* no OCSP response available, thus inconclusive */

    (void)ERR_set_mark();
    if(sk_OPENSSL_STRING_num(ocsps) <= 0 and fallback_urls is_eq 0)
    {
        LOG(FL_DEBUG, "AIA %s and no fallback OCSP responder URL",
            use_AIA ? "not in cert" : "disabled");
        goto end;
    }

    for(i = 0; res < 0 and i < sk_OPENSSL_STRING_num(ocsps); i++)
    {
        res = try_ocsp(ctx, untrusted, cert, issuer, timeout,
                       sk_OPENSSL_STRING_value(ocsps, i), NULL, "OCSP responder from AIA");
    }
    char* url;
    char* next;
    for(url = fallback_urls; res < 0 and url not_eq 0; url = next)
    {
        next = UTIL_next_item(url); /* must do this here to split string */
        res = try_ocsp(ctx, untrusted, cert, issuer, timeout, url, ocsps, "fallback OCSP responder");
    }

 end:
    X509_email_free(ocsps); /* sk_OPENSSL_STRING_pop_free(ocsps, OPENSSL_free) */
    OPENSSL_free(fallback_urls);

    LOG_certstatus_mark(LOG_FUNC_FILE_LINE, ctx, "cert status checking using plain OCSP", res);
    return res;
}

# ifndef SECUTILS_NO_TLS
int ocsp_stapling_cb(SSL* ssl, OPTIONAL STACK_OF(X509) *untrusted)
{
    X509_STORE* ts = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    X509* cert = sk_X509_value(chain, 0); /* multi-stapling is not supported */
    const unsigned char* resp_der;
    long resp_der_len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp_der);
    OCSP_RESPONSE* resp = 0;
    X509_STORE_CTX* ctx = 0;
    int ret = -1; /* tls_process_initial_server_flight reports
                     return code < 0 as internal error: malloc failure */

    LOG_cert(FL_TRACE, "checking OCSP stapling for", cert);
    CERT_print(cert, bio_trace, X509_FLAG_NO_EXTENSIONS);
    if(resp_der is_eq 0)
    {
        LOG(FL_DEBUG, "no OCSP response has been stapled\n");
    }
    else
    {
        LOG_cert(FL_DEBUG, "OCSP response stapled for", cert);
        resp = d2i_OCSP_RESPONSE(0, &resp_der, resp_der_len);
        if(resp is_eq 0)
        {
            LOG(FL_ERR, "error parsing stapled OCSP response");
            /* well, this is likely not an internal error (malloc failure) */
            BIO_dump_indent(bio_trace,
#  if OPENSSL_VERSION_NUMBER < 0x30000000L
                            (char *)
#  endif
                            resp_der, (int)resp_der_len, 4);
            BIO_flush(bio_trace);
            goto end;
        }
    }

    ctx = X509_STORE_CTX_new();/* needed for further checking and diagnostics */
    if(ctx is_eq 0 or not X509_STORE_CTX_init(ctx,
                                              ts /* inherit trust store with parameters */,
                                              0 /* cert */, untrusted))
    {
        goto end;
    }
    X509_STORE_CTX_set0_verified_chain(ctx, X509_chain_up_ref(chain));
    X509_STORE_CTX_set_error_depth(ctx, 0);
    ret = check_cert_revocation(ctx, resp);

 end:
    X509_STORE_CTX_free(ctx);
    OCSP_RESPONSE_free(resp);
    return ret;
}
# endif /* !defined(SECUTILS_NO_TLS) */

#endif /* !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0 */
