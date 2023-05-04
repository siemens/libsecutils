/** 
* @file tls.c
* 
* @brief Secure communication using SSL/TLS
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

#include <util/util.h> /* needed for config and version compatibility decls */

#ifndef SECUTILS_NO_TLS

#include <openssl/x509v3.h>

#include <connections/tls.h>
#include <connections/conn.h>
#include <credentials/credentials.h>
#include <credentials/store.h>
#include <credentials/verify.h>
#include <util/log.h>
#ifndef OPENSSL_NO_OCSP
#include <certstatus/certstatus.h>
#include <certstatus/ocsp.h>
#endif

#include <operators.h>

bool TLS_init(void)
{
/* initialize OpenSSL's SSL lib */
#if OPENSSL_VERSION_NUMBER < 0x10100003L
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
#else
    if(not SSL_library_init())
    {
        LOG(FL_FATAL, "OpenSSL initialization failed");
        return false;
    }
#endif
    return true;
}


SSL_CTX* TLS_CTX_new(OPTIONAL SSL_CTX* ssl_ctx,
                     int client, OPTIONAL X509_STORE* truststore,
                     OPTIONAL const STACK_OF(X509) * untrusted,
                     OPTIONAL const CREDENTIALS* creds,
                     OPTIONAL const char* ciphers, int security_level,
                     OPTIONAL X509_STORE_CTX_verify_cb verify_cb)
{
    SSL_CTX* ctx = ssl_ctx;
    SSL_CTX* res = 0;
    X509_VERIFY_PARAM* vpm = 0;

    if(ssl_ctx is_eq 0)
    {
        /* allocate new client/server context struture */
        ctx = SSL_CTX_new(client  > 0 ? TLS_client_method() :
                          client == 0 ? TLS_server_method() : TLS_method());
        if(ctx is_eq 0)
        {
            LOG_err("SSL_CTX_new() failed. Likely forgot to call TLS_init()");
            goto end;
        }
    }

    /* set allowed cipher list and security level if provided, else use default */
    if(ciphers not_eq 0)
    {
        if(not SSL_CTX_set_cipher_list(ctx, ciphers))
        {
            LOG(FL_ERR, "could not set cipher list '%s'", ciphers);
            goto end;
        }
        if(security_level < 0)
        {
            if(strcmp(ciphers, STRONG_CIPHER_SUITES) is_eq 0)
            {
                security_level = STRONG_SECURITY_LEVEL;
            }
            else if(strstr(ciphers, INTEGRITY_ONLY_CIPHER_SUITES_MARK) not_eq 0)
            {
                security_level = INTEGRITY_ONLY_SECURITY_LEVEL;
            }
            else if(strstr(ciphers, HIGH_CIPHER_SUITES_MARK) not_eq 0)
            {
                security_level = HIGH_SECURITY_LEVEL;
            }
            /* else use default OPENSSL_TLS_SECURITY_LEVEL */
        }
    }
    if(security_level >= 0)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        SSL_CTX_set_security_level(ctx, security_level);
#else
        LOG_warn("OpenSSL <1.1 does not support setting the TLS security level");
#endif
    }

    /* set store of trusted certificates, CRLs, verification parameters etc.
     * if provided, else do not verify peer */
    if(truststore not_eq 0)
    {
        vpm = X509_STORE_get0_param((X509_STORE*)truststore);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER bitor SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
        SSL_CTX_set1_cert_store(ctx, truststore);

#ifndef OPENSSL_NO_OCSP
# if OPENSSL_VERSION_NUMBER >= 0x1010001fL
        if(X509_VERIFY_PARAM_get_flags(vpm) bitand X509_V_FLAG_OCSP_STAPLING)
        {
            SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
            SSL_CTX_set_tlsext_status_cb(ctx, ocsp_stapling_cb);
            /* untrusted certs may help chain building verifying stapled OCSP responses */
            SSL_CTX_set_tlsext_status_arg(ctx, (STACK_OF(X509) *)untrusted);
        }
# endif
#endif
    }

    /* set own credentials if supplied, else no authentication to the peer */
    if(creds not_eq 0)
    {
        EVP_PKEY* pkey = CREDENTIALS_get_pkey(creds);
        X509* cert = CREDENTIALS_get_cert(creds);
        STACK_OF(X509) * chain = CREDENTIALS_get_chain(creds);
        if(pkey not_eq 0 and cert not_eq 0)
        {
            /* verify that the key matches the cert already here;
             * not using SSL_CTX_check_private_key
             * because it gives poor and sometimes misleading diagnostics */
            if(0 is_eq X509_check_private_key(cert, pkey))
            {
                LOG_err("private key does not match the certificate in the TLS credentials");
                goto end;
            }
            /* set certificate and related private key */
            if(SSL_CTX_use_certificate(ctx, cert) not_eq 1)
            {
                LOG_err("could not set TLS cert");
                goto end;
            }
            if(SSL_CTX_use_PrivateKey(ctx, pkey) not_eq 1)
            {
                LOG_err("could not set TLS private key");
                goto end;
            }

            if(not SSL_CTX_set1_chain(ctx, chain/* may be null */))
            {
                LOG_err("could not set TLS cert chain");
                goto end;
            }
            int i; /* untrusted certs may be useful to augment the own chain */
            for(i = 0; i < sk_X509_num(untrusted); i++)
            {
                if(not SSL_CTX_add1_chain_cert(ctx, sk_X509_value(untrusted, i)))
                {
                    LOG_err("could not add untrusted cert to TLS cert chain");
                    goto end;
                }
            }

            LOG_debug("trying to build cert chain for own TLS cert");
            unsigned long bak_flags;
            if(truststore not_eq 0)
            {
                bak_flags = X509_VERIFY_PARAM_get_flags(vpm);
                /* disable any cert status/revocation checking etc. */
                X509_VERIFY_PARAM_clear_flags(vpm,
                                              compl(X509_V_FLAG_USE_CHECK_TIME
                                                bitor X509_V_FLAG_NO_CHECK_TIME));
                X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NONFINAL_CHECK);
            }
            int ret = SSL_CTX_build_cert_chain(ctx,
                                               SSL_BUILD_CHAIN_FLAG_UNTRUSTED bitor
                                               SSL_BUILD_CHAIN_FLAG_NO_ROOT);
            if(truststore not_eq 0)
            {
                /* restore any cert status/revocation checking etc. */
                X509_VERIFY_PARAM_set_flags(vpm, bak_flags);
                X509_VERIFY_PARAM_clear_flags(vpm, X509_V_FLAG_NONFINAL_CHECK);
            }
            if(ret)
            {
                LOG_debug("succeeded building cert chain for own TLS cert");
            }
            else
            {
                LOG_warn("could not build chain for own TLS cert");
                (void)ERR_print_errors(bio_err); /* better would be to print only new entries */
                if(not SSL_CTX_set1_chain(ctx, chain/* may be null */))
                {
                    LOG_err("could not set default TLS cert chain");
                    goto end;
                }
            }
        }
    }

/* set various TLS options using sensible defaults */
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
    unsigned long context_options =
#else
    long context_options = SSL_OP_SINGLE_DH_USE
                           bitor SSL_OP_SINGLE_ECDH_USE
                           /* Do not allow outdated SSl/TLS protocol versions: */
                           bitor SSL_OP_NO_SSLv2 bitor SSL_OP_NO_SSLv3 bitor SSL_OP_NO_TLSv1 bitor SSL_OP_NO_TLSv1_1
                           bitor SSL_OP_NO_COMPRESSION
# if 0x10101000L <= OPENSSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER < 0x101010bfL
                           /* Disable TLS renegotiation as workaround for CVE-2021-3449 in OpenSSL 1.1.1 before patch 'k' */
                           /* BSI TR-02102-2 also recommends to use either RFC5746 compliant renegotiation or reject renegotiation
                              initiated by the client. Thus for the sake of simplicity and to lower the attack surface, we 
                              completely disable renegotiation. */
                           bitor SSL_OP_NO_RENEGOTIATION
# endif
                           bitor (long)
#endif
        SSL_OP_ALL; /*!< bug workarounds */
    SSL_CTX_set_options(ctx, context_options);

    /* Do not allow outdated SSl/TLS protocol versions: */
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
    if(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) <= 0)
    {
        LOG_err("could not set the minimal protocol version");
        goto end;
    }
#else
        LOG_warn("OpenSSL <1.1 does not support setting minimal protocol version");
#endif
    /* The flag SSL_MODE_AUTO_RETRY will cause read/write operations to
       only return after the handshake and successful completion. */
    (void)SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    res = ctx;

end:
    /* deallocate context again in case of errors */
    if(0 is_eq ssl_ctx and 0 is_eq res)
    {
        SSL_CTX_free(ctx);
    }
    return res;
}


void TLS_CTX_free(OPTIONAL SSL_CTX* ctx)
{
    SSL_CTX_free(ctx);
}

SSL* TLS_connect(SSL_CTX* ctx, const char* host, OPTIONAL const char* port, int timeout) /* @todo improve/complete this function */
{
    BIO* conn;
    SSL *ssl = 0, *res = 0;

    /* check parameters */
    if(0 is_eq ctx)
    {
        return 0;
    }
    char* host_str = CONN_get_host(host);
    if(host not_eq 0 and host_str is_eq 0)
    {
        return 0;
    }

    /* allocate intermediate connection structure */
    conn = CONN_new(host, port);
    if(0 is_eq conn)
    {
        goto err;
    }

    /* establish connection at BIO level */
    if(CONN_connect(conn, timeout) <= 0)
    {
        goto err;
    }

    /* set up TLS host name / IP address verification */
    X509_STORE* ts = SSL_CTX_get_cert_store(ctx);
    if(ts not_eq 0 and not STORE_set1_host_ip(ts, host, host))
    {
        goto err;
    }

    /* allocate SSL/TLS structure */
    ssl = SSL_new(ctx);
    if(0 is_eq ssl)
    {
        goto err;
    }
    /* link it with BIO connection */
    SSL_set_bio(ssl, conn, conn);

    /* set the server name indication ClientHello extension */
    if(host_str not_eq 0 and host_str[0] < '0' and host_str[0] > '9' /* no IPc4 address */
       and not SSL_set_tlsext_host_name(ssl, host_str))
    {
        goto err;
    }

    /* advance the connection to TLS */
    if(SSL_connect(ssl) <= 0)
    {
        goto err;
    }
    res = ssl;

err:
    OPENSSL_free(host_str);
    /* release the intermediate connection structure */
    CONN_free(conn);
    /* on error, release the SSL/TLS structure */
    if(0 is_eq res)
    {
        TLS_drop(ssl);
    }
    return res;
}


BIO* CONN_new_accept(const char* port) /*!< for servers; @todo */
{
    if(port is_eq 0)
    {
        return 0;
    }

    return 0;
}


#if 0
SSL* TLS_accept(SSL_CTX* ctx, BIO* conn) /*!< for servers; @todo */
{
    if(ctx is_eq 0 or conn is_eq 0)
    {
        return 0;
    }

    return 0;
}
#endif


bool CONN_free(OPTIONAL BIO* conn) /*!< for servers; @todo */
{
    return BIO_free(conn);
}


void TLS_drop(OPTIONAL SSL* tls)
{
    SSL_free(tls);
}

#else
typedef int make_iso_compilers_happy_on_empty_translation_unit;
#endif /* !defined(SECUTILS_NO_TLS) */
