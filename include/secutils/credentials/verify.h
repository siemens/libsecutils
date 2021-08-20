/** 
* @file verify.h
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

#ifndef SECUTILS_VERIFY_H_
#define SECUTILS_VERIFY_H_

#include <openssl/x509_vfy.h>
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
#define X509_V_FLAG_NO_CHECK_TIME 0x200000
#endif
#if OPENSSL_VERSION_NUMBER < 0x10002090L
#define X509_V_ERR_STORE_LOOKUP 70 /* from x509_vfy.h */
#endif

#include "../util/log.h"

#define X509_V_FLAG_ALLOW_EXPIRED_NONROOT_CERTS 0x400000
/* usage: X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(trust_store),
                                      X509_V_FLAG_ALLOW_EXPIRED_NONROOT_CERTS); */

/*!*****************************************************************************
 * @brief check if TLS is active in given cert verification context
 * @note Use STORE_set0_tls_bio() to indicate that TLS is being used.
 *
 * @param ctx pointer to structure containing certificate verification options like trusted certs
 * @return true if and only if TLS is enabled and active
 */
bool STORE_CTX_tls_active(const X509_STORE_CTX* ctx);

/*!*****************************************************************************
 * @brief callback function for certificate verification error reporting
 *
 * @param ok is set to 0 in case there is some verification error
 * @param ctx_x509 pointer to structure containing certificate verification options like trusted certs
 * @return 0 if and only if the cert verification is considered failed
 *
 * @note OpenSSL's X509_verify_cert function calls this function
 * during certificate verification whenever a problem has been
 * found and on success at the end of the verification to give an opportunity
 * to gather and output information regarding a failing cert verification,
 * and to possibly change the result of the verification.
 *
 * @note This callback is also activated when constructing our own TLS chain:
 * tls_construct_client_certificate() -> ssl3_output_cert_chain() ->
 * ssl_add_cert_chain() -> X509_verify_cert() where errors are ignored.
 */
int CREDENTIALS_print_cert_verify_cb(int ok, X509_STORE_CTX* ctx_x509);


/*!*****************************************************************************
 * @brief call any cert verification callback function to adapt cert verify error
 * @note emulates the OpenSSL-internal verify_cb_cert() of crypto/cmp/x509_vfy.c
 *
 * @param store_ctx pointer to structure containing certificate verification options
 * @param cert certificate to be verified
 * @param err preliminary cert verification error code
 * @return true if verification is considered successful, else false
 */
/* TODO DvO remove this function when the ones using it are merged upstream */
bool verify_cb_cert(X509_STORE_CTX* store_ctx, X509* cert, int err);

/*!*****************************************************************************
 * @brief attempt to verify certificate
 *
 * @param ctx (optional) pointer to UTA context, unused
 * @param cert certificate to be verified
 * @param untrusted (optional) intermediate certs that may be useful for building
 * the chain of certificates between the cert and the trusted certs in the trust store
 * @param trust_store pointer to structure containing trusted (root) certs and further verification parameters
 * @note trust_store may contain CRLs loaded via STORE_load_crl_dir()
 * @return < 0 on on verification error, 0 for invalid cert, 1 for vaild cert
 *******************************************************************************/
int CREDENTIALS_verify_cert(OPTIONAL uta_ctx* ctx, X509* cert,
                            OPTIONAL const STACK_OF(X509) * untrusted, X509_STORE* trust_store);

#endif /* SECUTILS_VERIFY_H_ */
