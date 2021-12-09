/** 
* @file certstatus.h
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

#ifndef SECUTILS_CERTSTATUS_H_
#define SECUTILS_CERTSTATUS_H_

#include <openssl/x509_vfy.h>
#include "../util/log.h"

#if OPENSSL_VERSION_NUMBER < 0x10101000L
# define X509_V_ERR_OCSP_VERIFY_NEEDED 73 /* Need OCSP verification */
# define X509_V_ERR_OCSP_VERIFY_FAILED 74 /* Could not verify cert via OCSP */
#endif

typedef struct revstatus_access_st
{
    int flags;
    const char* urls; /* fallback */
    int timeout;
} revstatus_access; /* for CDPs or OCSP responders */
#define REVSTATUS_IGNORE_CERT_EXT 0x1 /* ignore AIA/CDP entry in certificates */

#define X509_V_FLAG_STATUS_CHECK_ALL X509_V_FLAG_CRL_CHECK_ALL /* full chain */
#define X509_V_FLAG_STATUS_CHECK_ANY 0x1000000 /* any cert containing CDP/AIA */
/* X509_V_FLAG_STATUS_CHECK_ALL overrides X509_V_FLAG_STATUS_CHECK_ANY */
#ifndef OPENSSL_NO_OCSP
# include <openssl/ocsp.h>
# define X509_V_FLAG_OCSP_STAPLING   0x2000000 /* Use OCSP stapling (for TLS) */
# define X509_V_FLAG_OCSP_CHECK      0x4000000 /* Check certificates with OCSP */
# define X509_V_FLAG_OCSP_LAST       0x8000000 /* Try OCSP last (after CRLs) */
#endif /* !defined(OPENSSL_NO_OCSP) */
#define X509_V_FLAG_NONFINAL_CHECK  0x10000000 /* do not log failure as error */

/*!*****************************************************************************
 * @brief log messsage about the given certificate, focusing on CDP contents
 * in extensions with NID_crl_distribution_points or NID_freshest_crl
 *
 * @note This is more of a debug function to show which cert is currently processed.
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param cert the certificate to log
 */
void LOG_cert_CDP(
    OPTIONAL const char *func,
    OPTIONAL const char *file,
    int                 lineno,
    severity            level,
    const X509          *cert
);

/*!*****************************************************************************
 * @brief report which certificate status checking methods are enabled in which order
 *
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param ctx the verification context to read verification parameters from
 * @param verb description of activity, e.g., "will try checking"
 * @param check_single whether checking a single cert or a chain of certs
 */
void LOG_certstatus_methods(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                            X509_STORE_CTX* ctx, const char* verb, bool check_single);

/*!*****************************************************************************
 * @brief report certificate status source availability
 *
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param trust_store pointer to structure containing verification parameters
 * @param verb description of activity, e.g., "will check"
 * @param cert certificate to be verified
 */
void LOG_certstatus_sources(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                            X509_STORE* trust_store, const char* verb, const X509* cert);

/*!*****************************************************************************
 * @brief report the outcome of a certificate status check
 *
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param desc the type of the status check
 * @param ctx the verification context to read verification parameters from
 * @param res the result where 1 = success, 0 = rejection, -1 = error
 */
void LOG_certstatus_mark(OPTIONAL const char* func, OPTIONAL const char* file, int lineno,
                         X509_STORE_CTX* ctx, const char *desc, int res);

/*!*****************************************************************************
 * @brief see if currently the final verification attempt is done
 *
 * @param ctx pointer to structure containing certificate verification options
 * @return true if and only if the final verification attempt is done
 */
bool STORE_CTX_nonfinal(const X509_STORE_CTX* ctx);

/*!
 * @brief check the revocation status of the certificate at current error depth in ctx
 * using OCSP stapling, local CRLs, OCSP, and CDPs as far as enabled
 *
 * @param ctx pointer to verification context structure including the cert to check
 * @param resp OCSP response, which may have been stapled, or null
 * @return true on success, false on rejection or checking error (inconclusive)
 */
bool check_cert_revocation(X509_STORE_CTX* ctx, OPTIONAL OCSP_RESPONSE* resp);

/*!
 * @brief check the revocation status on certs in ctx->chain
 * @note as a generalization of check_revocation() in OpenSSL:crypto/x509/x509_vfy.c,
 * not only considers locally available CRLs,
 * but uses any stapled OCSP resp, local CRLs, else OCSP or CRLs as far as required.
 * @param ctx pointer to verification context structure including the cert(s) to check
 * @return true on success, false on rejection or checking error (inconclusive)
 * @note using result type 'int' rather than 'bool' for compatiblity with X509_STORE_set_check_revocation()
 */
int check_revocation_any_method(X509_STORE_CTX* ctx);

#endif /* SECUTILS_CERTSTATUS_H_ */
