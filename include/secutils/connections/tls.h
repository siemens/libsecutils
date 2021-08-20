/** 
* @file tls.h
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

#ifndef SECUTILS_TLS_H_
#define SECUTILS_TLS_H_

static const char* const STRONG_CIPHER_SUITES = "ECDHE-ECDSA-AES256-GCM-SHA384";

#ifndef SECUTILS_NO_TLS

#define OPENSSL_NO_SRP /* TODO remove after deprecation fix in OpenSSL 3.0-alpha */
#include <openssl/ssl.h>

#include "../credentials/credentials.h"
#include "../util/util.h" /* for OpenSSL version compatibility decls */

#if OPENSSL_VERSION_NUMBER < 0x10100004L
#define X509_STORE_up_ref(x) ((x)->references++)
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10101006L
#define SSL_library_init() OPENSSL_init_ssl(0, NULL)
#endif

static const char* const INTEGRITY_ONLY_CIPHER_SUITES = "NULL-SHA256:ECDHE-ECDSA-NULL-SHA";
static const char* const INTEGRITY_ONLY_CIPHER_SUITES_MARK = "NULL-";
static const char* const HIGH_CIPHER_SUITES = "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH";
static const char* const HIGH_CIPHER_SUITES_MARK = "HIGH";

static const int INTEGRITY_ONLY_SECURITY_LEVEL = 0;
static const int HIGH_SECURITY_LEVEL = 2;
static const int STRONG_SECURITY_LEVEL = 3;

/*!*****************************************************************************
 * @brief initialize the SSL/TLS library
 *
 * @return true on success, else false
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
bool TLS_init(void);


/*!*****************************************************************************
 * @brief set up an SSL/TLS context for client or server
 *
 * @note ssl_ctx, truststore, untrusted, creds, and/or ciphers may be null and are not consumed
 * @param ssl_ctx (optional) pointer to ssl context to be modified, or 0 to create new one
 * @param client which mode to use - for client: 1, for server: 0, both: -1. Not used if ssl_ctx != 0
 * @param truststore (optional) trusted certificates, CRLs, verification parameters etc.
 * @param untrusted (optional) intermediate certs that may be helpful while
 * building the chain for the TLS client cert and verifying stapled OCSP responses
 * @param creds (optional) credentials for own authentication to the peer
 * @param ciphers (optional) specification of enabled ciphers
 * @param security_level the desired TLS security level of -1 for automatic:
 * If the ciphers are "ECDHE-ECDSA-AES256-GCM-SHA384", the security level is set to 3.
 * Else if the ciphers contain "NULL-" (i.e., integrity-only), the security level is set to 0.
 * Else if the ciphers contain "HIGH", the security level is set to 2.
 * Else the OpenSSL default (typically, OPENSSL_TLS_SECURITY_LEVEL == 1) is used.
 * @param verify_cb (optional) cert validation callback, see 'man SSL_CTX_set_verify'
 * @return pointer to a new SSL/TLS context, or null on error
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
SSL_CTX* TLS_CTX_new(OPTIONAL SSL_CTX* ssl_ctx,
                     int client, OPTIONAL X509_STORE* truststore,
                     OPTIONAL const STACK_OF(X509) * untrusted,
                     OPTIONAL const CREDENTIALS* creds,
                     OPTIONAL const char* ciphers, int security_level,
                     OPTIONAL X509_STORE_CTX_verify_cb verify_cb);

/*!*****************************************************************************
 * @brief release SSL/TLS context
 *
 * @param ctx (optional) pointer to SSL/TLS context
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
void TLS_CTX_free(OPTIONAL SSL_CTX* ctx);


/*!*****************************************************************************
 * @brief TLS client connect
 *
 * @param ctx SSL/TLS context, typically obtained using TLS_CTX_new()
 * @param host the host name or IP address, which may be given as a URL, of the server to connect to
 * @note host name checking is enabled for the given host name or IP address
 * @param port (optional) the port number, given as string, to connect to
 * @note The host parameter may contain a ':' followed by a port specification.
 * In this case the port parameter must be null or contain the same string.
 * @param timeout number of seconds the HTTP transaction may take, or 0 for infinite
 * @return pointer to a new SSL/TLS structure, or null on error
 *******************************************************************************/
SSL* TLS_connect(SSL_CTX* ctx, const char* host, OPTIONAL const char* port, int timeout);


/*!*****************************************************************************
 * @brief get TLS server BIO
 *
 * @param port the port number, given as string, to listen on
 * @return pointer connection BIO to use with TLS_accept()
 *******************************************************************************/
BIO* CONN_new_accept(const char* port); /*!< for servers; @todo */


/*!*****************************************************************************
 * @ brief TLS server accept
 *
 * @ param ctx SSL/TLS context, typically obtained using TLS_CTX_new()
 * @ param conn the connection BIO to use for accepting connections, typically obtained using CONN_accept()
 * @ return pointer to a new SSL/TLS structure, or null on error
 *******************************************************************************/
/*SSL* TLS_accept(SSL_CTX* ctx, BIO* conn);*/ /*!< for servers; @todo */

/*!*****************************************************************************
 * @brief deallocate TLS server BIO
 *
 * @param conn (optional) pointer connection BIO to deallocate
 * @return true on success, else false
 *******************************************************************************/
bool CONN_free(OPTIONAL BIO* conn); /*!< for servers; @todo */

/*!*****************************************************************************
 * @brief release SSL/TLS connection
 *
 * @param tls (optional) pointer to SSL/TLS connection
 *******************************************************************************/
void TLS_drop(OPTIONAL SSL* tls);

#endif /* !defined(SECUTILS_NO_TLS) */

#endif /* SECUTILS_TLS_H_ */
