/**
* @file cert.h
* 
* @brief Certificate utility functions
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

#ifndef SECUTILS_CERT_H_
#define SECUTILS_CERT_H_

/* #if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0 */
/* #define OPENSSL_API_COMPAT 30000 */
#define OPENSSL_NO_DEPRECATED

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>  /* for strcmp, strlen */

#include "../basic.h"
#include "../operators.h"
# include "../util/log.h"

#include <openssl/x509.h>

/*!
 * @brief load a certificate from the given file in format derived from file name extension
 *
 * @param file (path) name of the input file
 * @param pass the password source to use in case the input file is encrypted, or null
 * @param desc description of file contents to use for any error messages, or null
 * @param type_CA check for CA cert if 1 or EE if 0; no type check if < 0
 * @param vpm verification parameters, or null, governing if and how to check cert times,
 * depending on X509_V_FLAG_USE_CHECK_TIME and X509_V_FLAG_NO_CHECK_TIME
 * @return null on error, else the first certificate contained in the file
 * @note Check failures are logged as a warning if vpm is null, otherwise as an error.
 */
/* this function is part of the genCMPClient API */
X509 *CERT_load(const char *file, OPTIONAL const char *pass, OPTIONAL const char *desc,
                int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm);


/*!
 * @brief store the given certificate in given file and in format derived from file name extension
 *
 * @param cert certificate to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
/* this function is part of the genCMPClient API */
bool CERT_save(const X509 *cert, const char *file, OPTIONAL const char *desc);


/*!
 * @brief load certificates from the given file(s) with flexible format
 *
 * @param files comma/space-separated list of input file (path) names
 * @param desc description of file contents to use for any error messages, or null
 * @param type_CA check for CA cert if 1 or EE if 0; no type check if < 0
 * @param vpm verification parameters, or null, governing if and how to check cert times,
 * depending on X509_V_FLAG_USE_CHECK_TIME and X509_V_FLAG_NO_CHECK_TIME
 * @return null on error, else a stack of certs with the first/primary one on top
 * @note Check failures are logged as a warning if vpm is null, otherwise as an error.
 * @note duplicate certificates among different input files are included only once
 */
/* this function is part of the genCMPClient API */
STACK_OF(X509)
    *CERTS_load(const char *files, OPTIONAL const char *desc,
                int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm);


/*!
 * @brief store the given list of certificates in given file and in format derived from file name extension
 *
 * @param certs list of certificates to save, or null to save empty list
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param desc description of file contents to use for any error messages, or null
 * @return the number of certificates saved, or < 0 on error
 */
/* this function is part of the genCMPClient API */
int CERTS_save(OPTIONAL const STACK_OF(X509) *certs, const char *file, OPTIONAL const char *desc);


/*!
 * @brief release a list of certificates
 *
 * @param certs (optional) the certificates to be freed
 */
/* this function is part of the genCMPClient API */
void CERTS_free(OPTIONAL STACK_OF(X509) *certs);


/*!*****************************************************************************
 * @brief parse an X.500 Distinguished Name (DN)
 *
 * @param dn string to be parsed, format "/type0=value0/type1=value1/type2=..." where characters may be escaped by '\'.
 * The NULL-DN may be given as "/" or "".
 * @param chtype type of the string, e.g., MBSTRING_UTF8, as defined in openssl/asn1.h
 * @param multirdn flag whether to allow multi-valued RDNs
 * @return ASN.1 representation of the DN, or null on error
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
X509_NAME* UTIL_parse_name(const char* dn, long chtype, bool multirdn);


/*!*****************************************************************************
 * @brief log message about the given certificate, printing its subject
 *
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param msg the message to be logged
 * @param cert the certificate the message refers to
 */
void LOG_cert(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
              const char* msg, const X509* cert);


/*!*****************************************************************************
 * @brief print a certificate
 *
 * @param cert certificate to be printed, or null
 * @param bio BIO to print to, e.g., bio_err, or null
 * @param neg_cflags indicates elements not to be printed
 *******************************************************************************/
void CERT_print(OPTIONAL const X509* cert, OPTIONAL BIO* bio, unsigned long neg_cflags);
#define UTIL_print_cert(bio, cert, neg_cflags) CERT_print(cert, bio, neg_cflags)


/*!*****************************************************************************
 * @brief print a list of certificates
 *
 * @param certs list of certificates to be printed, or null
 * @param bio BIO to print to, e.g., bio_err, or null
 *******************************************************************************/
void CERTS_print(OPTIONAL const STACK_OF(X509) * certs, OPTIONAL BIO* bio);
#define UTIL_print_certs(bio, certs) CERTS_print(certs, bio)


/*!*****************************************************************************
 * @brief check if certificate is within validity period, optionally check type
 *
 * @param uri The source of the certificate, e.g., a URL or file name
 * @param cert certificate to be be checked, or null for no checks
 * @param type_CA check for CA cert if 1 or EE if 0; no type check if < 0
 * @param vpm verification parameters, or null, governing if and how to check cert times,
 * depending on X509_V_FLAG_USE_CHECK_TIME and X509_V_FLAG_NO_CHECK_TIME
 * @return true if no cert given or cert validity period check passed
 * @note Check failures are logged as a warning if vpm is null, otherwise as an error.
 *******************************************************************************/
bool CERT_check(const char *uri, OPTIONAL X509 *cert, int type_CA,
                OPTIONAL const X509_VERIFY_PARAM *vpm);


/*!*****************************************************************************
 * @brief check if a cert list member is within validity period, optionally check type
 *
 * @param uri The source of the certificates, e.g., a URL or file name
 * @param certs list of certificates to be be checked, or null for no checks
 * @param type_CA check for CA cert if 1 or EE if 0; no type check if < 0
 * @param vpm verification parameters, or null, governing if and how to check cert times,
 * depending on X509_V_FLAG_USE_CHECK_TIME and X509_V_FLAG_NO_CHECK_TIME
 * @return true if no certs given or validity period check passed for all certs
 * @note Check failures are logged as a warning if vpm is null, otherwise as an error.
 *******************************************************************************/
bool CERT_check_all(const char *uri, OPTIONAL STACK_OF(X509) *certs, int type_CA,
                    OPTIONAL const X509_VERIFY_PARAM *vpm);


/*!*****************************************************************************
 * @brief add certificate to given stack, optionally only if not already contained
 *
 * @param sk stack of certificates
 * @param cert certificate to be pushed to the stack
 * @param no_duplicate flag governing whether to add cert if it is a duplicate
 * @return true on success, else false
 *******************************************************************************/
bool UTIL_sk_X509_add1_cert(STACK_OF(X509) * sk, X509* cert, bool no_duplicate);


/*!*****************************************************************************
 * @brief add stack of certificates to given stack,
 * optionally only if not self-signed and optionally if not already contained
 *
 * @param sk stack of certificates
 * @param certs (optional) stack of certificates to be pushed to the stack
 * @param no_self_signed flag governing whether to add self-signed certs
 * @param no_duplicates flag governing whether to add cert if it is a duplicate
 * @return true on success, else false
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
int UTIL_sk_X509_add1_certs(STACK_OF(X509) * sk, OPTIONAL const STACK_OF(X509) * certs, int no_self_signed,
                            int no_duplicates);


#endif /* SECUTILS_CERT_H_ */
