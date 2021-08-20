/** 
* @file ocsp.h
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

#ifndef SECUTILS_OCSP_H_
#define SECUTILS_OCSP_H_

#include "../util/util.h"

#ifndef OPENSSL_NO_OCSP
#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0

#include <openssl/x509_vfy.h>

# include <openssl/ocsp.h>
# define X509_V_FLAG_OCSP_STAPLING  0x2000000 /* Use OCSP stapling (for TLS) */
# define X509_V_FLAG_OCSP_CHECK     0x4000000 /* Check certificates with OCSP */
# define X509_V_FLAG_OCSP_LAST      0x8000000 /* Try OCSP last (after CRLs) */

/*!
 * @brief obtain OCSP response from given OCSP responder
 *
 * @param url the location of the OCSP responder
 * @param timeout number of seconds the HTTP transaction may take, or 0 for infinite or -1 for default
 * @param req the OCSP request to send
 * @param desc description of contents to use for any error messages, or null
 * @return pointer to OCSP response, or null on error
 */
OCSP_RESPONSE* CONN_load_OCSP_http(const char* url, int timeout,
                                   const OCSP_REQUEST* req,
                                   OPTIONAL const char* desc);
static const int OCSP_DEFAULT_TIMEOUT = 10; /* in seconds */

/*!
 * @brief check cert status using the given OCSP response
 * @note the OCSP response may be obtained using an OCSP request or OCSP stapling
 *
 * @param ts pointer to trust store containing verification parameters
 * @param untrusted a stack of certs that may be used for chain building, or null
 * @param cert the cerificate to check
 * @param issuer the issuer cerificate
 * @param resp the OCSP response to use
 * @return 1 on success, 0 on rejection (i.e., cert revoked), -1 on error
 */
int check_ocsp_resp(X509_STORE* ts, STACK_OF(X509) *untrusted,
                    X509* cert, X509* issuer, OCSP_RESPONSE* resp);

/*!
 * @brief check cert revocation status via OCSP.
 * @note tries using any AIA entries (if enabled) then try any given fallback OCSP responder URLs, in the given order
 *
 * @param ctx verification context containing verification parameters etc.
 * @param untrusted a stack of certs that may be used for chain building, or null
 * @param cert the cerificate to check
 * @param issuer the issuer cerificate
 * @return 1 on success, 0 on rejection (i.e., cert revoked), -2 on no OCSP response available, -1 on other error
 */
int check_cert_status_ocsp(X509_STORE_CTX* ctx, STACK_OF(X509) *untrusted,
                           X509* cert, X509* issuer);

#ifndef SECUTILS_NO_TLS
/*!
 * @brief callback function for verifying stapled OCSP responses for leaf certs
 *
 * @param ssl the current SSL/TLS connection
 * @param untrusted a stack of certs that may be used for chain building, or null
 * @return 1 on success, 0 on rejection (i.e., cert revoked), -1 on error
 */
int ocsp_stapling_cb(SSL* ssl, OPTIONAL STACK_OF(X509) *untrusted);
#endif /* !defined(SECUTILS_NO_TLS) */

#endif /* OPENSSL_VERSION_NUMBER >= OPENSSL_V_1_1_0 */
#endif  /* !defined(OPENSSL_NO_OCSP) */

#endif /* SECUTILS_OCSP_H_ */
