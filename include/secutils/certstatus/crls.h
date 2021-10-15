/** 
* @file crls.h
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

#ifndef SECUTILS_CRLS_H_
#define SECUTILS_CRLS_H_

#include <openssl/x509.h>

/*!
 * @brief retrieve CRL in DER format (ASN.1) from given CRL distribution point
 *
 * @param url the location of the CDP
 * @param timeout number of seconds the HTTP transaction may take, or 0 for infinite or -1 for default
 * @param max_resp_len the maximal size of the response message, or 0 for the OpenSSL default: 100 kiB
 * @param desc description of the CRL to use for any error messages, or null
 * @return pointer to downloaded CRL, or null on error
 */
X509_CRL* CONN_load_crl_http(const char* url, int timeout,
                             unsigned long max_resp_len, OPTIONAL const char* desc);
static const int CRL_DOWNLOAD_DEFAULT_TIMEOUT = 10; /* in seconds */

/*!
 * @brief check the revocation status of the certificate at current error depth in ctx using CRLs
 *
 * @param ctx pointer to verification context structure including the cert to check
 * @param crls a list of CRLs that may be useful in addition to the local ones in ctx, or null
 * @return 1 on success, 0 on rejection (i.e., cert revoked), -1 on error
 */
int check_cert_crls(X509_STORE_CTX* ctx, OPTIONAL STACK_OF(X509_CRL) * crls);

#ifndef SEC_NO_CRL_DOWNLOAD

/*!
 * @brief check the revocation status of the certificate at current error depth in ctx using CDPs
 *
 * @param ctx pointer to verification context structure including the cert to check
 * @return 1 on success, 0 on rejection (i.e., cert revoked), -2 on no CRL available, -1 on other error
 */
int check_cert_status_cdps(X509_STORE_CTX* ctx);

#endif  /* !defined(SEC_NO_CRL_DOWNLOAD) */

#endif /* SECUTILS_CRLS_H_ */
