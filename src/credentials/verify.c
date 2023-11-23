/** 
* @file verify.c
* 
* @brief Certificate verification
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

#include <credentials/cert.h>
#include <credentials/store.h>
#include <credentials/verify.h>
#include <certstatus/crls.h>
#include <util/log.h>
#include <storage/uta_api.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <operators.h>


bool STORE_CTX_tls_active(const X509_STORE_CTX* ctx)
{
#ifndef SECUTILS_NO_TLS
    return X509_STORE_CTX_get_ex_data((X509_STORE_CTX*)ctx, SSL_get_ex_data_X509_STORE_CTX_idx()) not_eq 0;
#else
    return false;
#endif
}

int CREDENTIALS_print_cert_verify_cb(int ok, X509_STORE_CTX* store_ctx)
{
    if(ok is_eq 0 and store_ctx not_eq 0)
    {
        int cert_error = X509_STORE_CTX_get_error(store_ctx);
        const char *error_str = X509_verify_cert_error_string(cert_error);
        int depth = X509_STORE_CTX_get_error_depth(store_ctx);
        X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);
        X509_CRL *crl = X509_STORE_CTX_get0_current_crl(store_ctx);
        X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(store_ctx);
        unsigned long flags = X509_VERIFY_PARAM_get_flags(param);
        bool nonfinal = (flags bitand X509_V_FLAG_NONFINAL_CHECK) not_eq 0;
        X509_STORE* ts = X509_STORE_CTX_get0_store(store_ctx);
        const char* expected = 0;

        /* Not yet valid certificates are OK */
        if(cert_error == X509_V_ERR_CERT_NOT_YET_VALID)
        {
            LOG(LOG_FUNC_FILE_LINE, LOG_WARNING, "Accepting not yet valid certificate");
            ok = 1;
        }
        else if((flags bitand X509_V_FLAG_ALLOW_EXPIRED_NONROOT_CERTS) not_eq 0
           and cert_error is_eq X509_V_ERR_CERT_HAS_EXPIRED)
        {
            LOG(LOG_FUNC_FILE_LINE, LOG_WARNING, "Accepting expired non-root certificate");
            ok = 1;
        }

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#define X509_V_ERR_OCSP_CERT_UNKNOWN 75  /* Certificate wasn't recognized by the OCSP responder */
#endif
        bool crl_error = false;
        bool certstatus_error = false;
        switch(cert_error)
        {
            case X509_V_ERR_UNABLE_TO_GET_CRL:
            case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
            case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            case X509_V_ERR_CRL_NOT_YET_VALID:
            case X509_V_ERR_CRL_HAS_EXPIRED:
            case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
            case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
            case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
            case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
            case X509_V_ERR_DIFFERENT_CRL_SCOPE:
            case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
                crl_error = true;
                /* fall thru */
            case X509_V_ERR_CERT_REVOKED:
            case X509_V_ERR_OCSP_VERIFY_NEEDED:
            case X509_V_ERR_OCSP_VERIFY_FAILED:
            case X509_V_ERR_OCSP_CERT_UNKNOWN:
                certstatus_error = true;
                break;
            case X509_V_ERR_HOSTNAME_MISMATCH:
            case X509_V_ERR_IP_ADDRESS_MISMATCH:
                /* Unfortunately there is no OpenSSL API function for retrieving the
                   hostname/ip entries in X509_VERIFY_PARAM. So we use ts->ex_data.
                   This works for names we set ourselves but not verify_hostname. */
                expected = STORE_get0_host(ts);
                break;
            case X509_V_ERR_INVALID_PURPOSE:
                /* TODO assign, if possible: expected = ...; */
                break;
            default:
                break;
        }

#ifndef SECUTILS_NO_TLS
        bool checking_ocsp = nonfinal and not certstatus_error;
        BIO* sbio = STORE_get0_tls_bio(ts);
        if(sbio not_eq 0 /* OSSL_CMP_PKIMESSAGE_http_perform() with TLS is active */
           and false is_eq STORE_CTX_tls_active(store_ctx) /* ssl_add_cert_chain() or check_cert_revocation() is active */
           and not certstatus_error and not checking_ocsp)
        {
            return ok; /* avoid printing spurious errors */
        }
#endif

#if OPENSSL_VERSION_NUMBER < 0x10101000L
        if(cert_error is_eq X509_V_ERR_OCSP_VERIFY_NEEDED)
        {
            error_str = "OCSP verification needed";
        }
        else if(cert_error is_eq X509_V_ERR_OCSP_VERIFY_FAILED)
        {
            error_str = "OCSP verification failed";
        }
#endif
        if(crl_error and nonfinal)
        {
            LOG(LOG_FUNC_FILE_LINE, nonfinal ? LOG_DEBUG : LOG_ERR,
                "CRL check unsuccessful at depth=%d error=%d (%s)",
                depth, cert_error, error_str);
            if(crl not_eq 0)
            {
                UTIL_print_crl(bio_trace, crl);
            }
        }
        else
        {
            bool crl_path_err = X509_STORE_CTX_get0_parent_ctx(store_ctx) not_eq 0;
            severity level = nonfinal ? LOG_DEBUG: LOG_ERR;
            BIO* bio = nonfinal ? bio_trace : bio_err;
            LOG(LOG_FUNC_FILE_LINE, level, "%s at depth=%d error=%d (%s%s%s)",
                depth < 0 ? "signature verification" :
                crl_path_err ? "CRL path validation" : "certificate verification",
                depth, cert_error, error_str, expected not_eq 0 ? "; expected: " : "",
                expected not_eq 0 ? expected : "");
            LOG_cert(LOG_FUNC_FILE_LINE, level, "verification unsuccessful for", cert);
            CERT_print(cert, bio, X509_FLAG_NO_EXTENSIONS);
            if(certstatus_error)
            {
                LOG_certstatus_sources(FL_ERR, ts, "have checked", cert);
                LOG_certstatus_methods(FL_DEBUG, store_ctx, "have tried checking", true);
            }
            else
            {
                switch(cert_error)
                {
                    case X509_V_ERR_CERT_UNTRUSTED:
                    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
                    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
                    case X509_V_ERR_STORE_LOOKUP:
                        LOG(LOG_FUNC_FILE_LINE, level, "\nuntrusted certs used for chain building:");
                        CERTS_print(X509_STORE_CTX_get0_untrusted(store_ctx), bio);
                        LOG(LOG_FUNC_FILE_LINE, level, "\ntrusted certs used as trust anchors:");
                        UTIL_print_store_certs(bio, X509_STORE_CTX_get0_store(store_ctx));
                        break;
                    default:
                        break;
                }
            }
        }
    }
    return ok;
}

bool verify_cb_cert(X509_STORE_CTX* store_ctx, X509* cert, int err)
{
    X509_STORE_CTX_verify_cb verify_cb = X509_STORE_CTX_get_verify_cb(store_ctx);

    X509_STORE_CTX_set_error(store_ctx, err);
    X509_STORE_CTX_set_current_cert(store_ctx, cert);
    return verify_cb != 0 and (*verify_cb)(0, store_ctx) != 0;
}

int CREDENTIALS_verify_cert(OPTIONAL ossl_unused uta_ctx* uta_ctx, X509* cert,
                            OPTIONAL const STACK_OF(X509) * untrusted_certs, X509_STORE* trust_store)
{
    int result = -1;
    X509_STORE_CTX* store_ctx = 0;

    if(0 is_eq cert)
    {
        LOG(FL_ERR, "null pointer to cert");
        return result;
    }

    if(0 is_eq trust_store)
    {
        LOG(FL_ERR, "null pointer to trust store");
        return result;
    }

    char* name = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    if(name is_eq 0)
    {
        LOG(FL_ERR, "failed to get certificate subject name");
        return result;
    }
    const char *desc = STORE_get0_desc(trust_store);
    LOG(FL_DEBUG, "attempting to verify certificate%s%s with subject %s",
        desc == NULL ? "" : " for ", desc == NULL ? "" : desc, name);

    if(0 is_eq(store_ctx = X509_STORE_CTX_new()))
    {
        LOG(FL_ERR, "out of memory allocating verification context");
        goto end;
    }

    if(0 is_eq X509_STORE_CTX_init(store_ctx, trust_store, cert, (STACK_OF(X509)*)untrusted_certs))
    {
        LOG(FL_ERR, "cannot initialize verification context");
        goto err;
    }
    X509_STORE_CTX_set_verify_cb(store_ctx, CREDENTIALS_print_cert_verify_cb);

#if OPENSSL_VERSION_NUMBER < 0x10101080L
    /*
     * This workaround is needed only for old OpenSSL versions < 1.1.1h where
     * the fix of https://github.com/openssl/openssl/issues/1418 is not present:
     */
    if(X509_check_issued(cert, cert)) /* self-signed */
    {
        X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(store_ctx), X509_V_FLAG_PARTIAL_CHAIN);
    }
#endif

#ifdef USE_CRLS /* TODO */
    X509_STORE_CTX_set0_crls(store_ctx, crls);
#endif

    result = X509_verify_cert(store_ctx);
err: ;
    const char* str = X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx));
    const char* const verb = "have tried checking";
    if(result > 0)
    {
        LOG(FL_TRACE, "successfully verified certificate with subject '%s'", name);
        LOG_certstatus_methods(FL_TRACE, store_ctx, verb, false);
    }
    else if(result < 0)
    {
        LOG(FL_ERR, "error while verifying certificate with subject '%s': %s", name, str);
        LOG_certstatus_methods(FL_ERR, store_ctx, verb, false);
    }
    else /* result == 0 */
    {
        (void)ERR_print_errors(bio_err);
        BIO_flush(bio_err);
        LOG(FL_WARN, "rejecting certificate with subject '%s'; error='%s'", name, str);
        LOG_certstatus_methods(FL_WARN, store_ctx, verb, false);
    }

    X509_STORE_CTX_free(store_ctx);
 end:
    OPENSSL_free(name);
    return result;
}
