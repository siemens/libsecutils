/** 
* @file http.c
* 
* @brief HTTP client for ASN.1 structures, needed for CRL fetching and OCSP
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

#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)

# include <util/log.h>
# include "secutils/operators.h"
# include <connections/http.h>
# include <connections/conn.h>
# ifndef SECUTILS_NO_TLS
#  include <connections/tls.h>
# endif

# include <openssl/asn1.h>
# if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
#  undef OPENSSL_NO_DEPRECATED_3_0
# endif
# include <openssl/ocsp.h>

/* TODO replace this all by new API in http.h of OpenSSL 3.0 */

static int REQ_CTX_i2d(OCSP_REQ_CTX* rctx, const char* content_type,
                            const ASN1_VALUE* req, const ASN1_ITEM* it)
{
    BIO* mem = OCSP_REQ_CTX_get0_mem_bio(rctx);
    const char* const crlf = "\r\n";
    const int crlf_len = strlen(crlf);
    int reqlen = ASN1_item_i2d((ASN1_VALUE*)req, 0, it);
    char lenbuf[20];

    if((size_t)snprintf(lenbuf, sizeof(lenbuf), "%d", reqlen) >= sizeof(lenbuf)
        or not OCSP_REQ_CTX_add1_header(rctx, "Content-Type", content_type)
        or not OCSP_REQ_CTX_add1_header(rctx, "Content-Length", lenbuf)
        or BIO_write(mem, "\r\n", crlf_len) not_eq crlf_len)
        /*
         * for adding the crlf at the end of the header cannot use
         * not OCSP_REQ_CTX_add1_header(rctx, "", 0)
         * due to bug/limitation in case strlen(name) == 0
         */
        {
            return 0;
        }

    if(ASN1_item_i2d_bio(it, mem, (ASN1_VALUE*)req) <= 0)
    {
        return 0;
    }
    /*
     * At this point, rctx->state == OHS_HTTP_HEADER.
     * So OCSP_REQ_CTX_nbio() will add a needless extra crlf.
     * This could be avoided by
     *   rctx->state = OHS_ASN1_WRITE_INIT;
     * but we do not have access to decls from OpenSSL crypto/ocsp/ocsp_lcl.h
     */
    return 1;
}

static OCSP_REQ_CTX* REQ_CTX_new(BIO* bio, const char* host, const char* path,
                                 const char* content_type, const ASN1_VALUE* req,
                                 const ASN1_ITEM* it, int maxline, unsigned long max_resp_len)
{
    OCSP_REQ_CTX* rctx = OCSP_REQ_CTX_new(bio, maxline);

    if(rctx is_eq 0)
    {
        LOG(FL_ERR, "out of memory");
        return 0;
    }

    if(not OCSP_REQ_CTX_http(rctx, req not_eq 0 ? "POST" : "GET", path)
        or (host not_eq 0 and not OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        or not OCSP_REQ_CTX_add1_header(rctx, "Pragma", "no-cache")
        or (req not_eq 0 and not REQ_CTX_i2d(rctx, content_type, req, it)))
    {
        OCSP_REQ_CTX_free(rctx);
        LOG(FL_ERR, "cannot initialize HTTP request");
        return 0;
    }
    OCSP_set_max_response_length(rctx, max_resp_len);
    return rctx;
}

/*
 * Exchange ASN.1 request and response via HTTP on any BIO
 * returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
 * 1: success and then provides the received message via the *resp argument
 * This indirectly calls ERR_clear_error()
 */
/* adapted from query_responder() in OpenSSL:apps/ocsp.c */
static int CONN_ASN1_http(BIO* bio, const char* host, const char* path,
                          unsigned long max_resp_len,
                          time_t max_time, const char* content_type,
                          const ASN1_VALUE* req, const ASN1_ITEM* req_it,
                          ASN1_VALUE** resp, const ASN1_ITEM* resp_it)
{
    int rv = -4, rc, sending = 1;
    int blocking = max_time is_eq 0;
    ASN1_VALUE* const pattern = (ASN1_VALUE*)-1;
    OCSP_REQ_CTX* rctx = REQ_CTX_new(bio, host, path, content_type,
                                     req, req_it, -1/* was: 1024 */, max_resp_len);

    if(rctx is_eq 0)
    {
        return rv;
    }
    /*
     * Would be better to extend OCSP_REQ_CTX_nbio() and
     * thus OCSP_REQ_CTX_nbio_d2i() to include this retry behavior
     */
    *resp = pattern; /* used for detecting parse errors */
    do {
        rc = OCSP_REQ_CTX_nbio_d2i(rctx, resp, resp_it);
        /* returns 1 on success, 0 on error, -1 on BIO_should_retry */
        if(rc not_eq -1)
        {
            rv = 1;
            if(rc is_eq 0) /* an error occurred */
            {
                if(sending and not blocking)
                {
                    rv = -3; /* send error */
                }
                else
                {
                    if(*resp is_eq pattern)
                    {
                        rv = -2;/* receive error */
                    }
                    else
                    {
                        rv = -1; /* parse error */
                    }
                }
                *resp = 0;
            }
            break;
        }
        /* else BIO_should_retry was true */
        sending = 0;
        if(not blocking)
        {
            rv = CONN_wait(bio, (int)(max_time - time(0)));
            if(rv <= 0) /* error or timeout */
            {
                if(rv < 0) /* error */
                {
                    rv = -4;
                }
                *resp = 0;
                break;
            }
        }
    }
    while(rc is_eq -1); /* BIO_should_retry was true */

    OCSP_REQ_CTX_free(rctx);
    return rv;
}

/* adapted from load_cert_crl_http() in OpenSSL:apps/lib/apps.c */
ASN1_VALUE* CONN_load_ASN1_http(const char* url, int req_timeout,
                                unsigned long max_resp_len,
                                OPTIONAL const char* content_type,
                                OPTIONAL const ASN1_VALUE* req,
                                OPTIONAL const ASN1_ITEM* req_it,
                                const ASN1_ITEM* res_it, OPTIONAL const char* desc)
{
    char* host = 0;
    char* port = 0;
    char* path = 0;
    int use_ssl;
    BIO* cbio = 0;
    time_t max_time = req_timeout > 0 ? time(0) + req_timeout : 0;
    int rv = -4; /* other error */
    ASN1_VALUE* res = 0;
    severity level = desc is_eq 0 ? LOG_DEBUG: LOG_ERR;

    if(desc is_eq 0)
    {
        desc = "ASN.1 item";
    }
    if(url is_eq 0)
    {
        LOG(FL_ERR, "null URL argument for downloading %s", desc);
        return 0;
    }
    if(not OCSP_parse_url(url, &host, &port, &path, &use_ssl))
    {
        LOG(FL_ERR, "cannot parse URL: '%s' for downloading %s", url, desc);
        goto err;
    }
    LOG(FL_TRACE, "trying to download %s via %s", desc, url);
    cbio = CONN_new(host, port);
    if(cbio is_eq 0)
    {
        goto err;
    }
    if(use_ssl is_eq 1)
    {
# ifndef SECUTILS_NO_TLS
        SSL_CTX* ssl_ctx = TLS_CTX_new(0/* ssl_ctx */, 1/* client */, 0/* truststore */,
                                       0/* untrusted */, 0/* creds */,
                                       0/* ciphers */, -1/* security_level */,
                                       0/* verify_cb */);
        if(ssl_ctx is_eq 0)
        {
            LOG(FL_ERR, "error creating trivial SSL context");
            goto err;
        }
        cbio = CONN_set1_TLS(cbio, ssl_ctx);
        SSL_CTX_free(ssl_ctx);
        if(cbio is_eq 0)
        {
            LOG(FL_ERR, "error attaching trivial SSL context");
            goto err;
        }
# else
        LOG(FL_ERR, "TLS is not enabled in this build");
        goto err;
# endif /* !defined(SECUTILS_NO_TLS) */
    }

    if((rv = CONN_connect(cbio, req_timeout)) <= 0)
    {
        rv = rv is_eq -1 ? -5 : rv;
        goto err;
    }

    rv = CONN_ASN1_http(cbio, host, path, max_resp_len,
                        max_time, content_type, req, req_it, &res, res_it);

 err:
    BIO_free_all(cbio);
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    if(rv not_eq 1)
    {
        LOG(LOG_FUNC_FILE_LINE, level, "%s loading %s from '%s'",
            rv is_eq -5 ? "connect error" :
            rv is_eq  0 ? "timeout" :
            rv is_eq -1 ? "parse error" :
            rv is_eq -2 ? "receive error" :
            rv is_eq -3 ? "send error" : "other error",
            desc, url);
        if(rv is_eq -5 and ERR_peek_error() is_eq 0)
        {
            LOG(LOG_FUNC_FILE_LINE, level, "server has disconnected%s",
                use_ssl ? " violating the protocol" : ", maybe because it requires TLS");
        }
        (void)ERR_print_errors(bio_err);
    }
    return res;
}

#endif /* !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) */
