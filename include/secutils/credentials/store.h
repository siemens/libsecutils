/** 
* @file store.h
* 
* @brief Certificate store, used for verification
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

#ifndef SECUTILS_STORE_H_
# define SECUTILS_STORE_H_

# include <openssl/x509_vfy.h>

# include "../storage/files.h"
# include "../storage/uta_api.h"
# include "credentials.h"
# include "../certstatus/certstatus.h"

/*!*****************************************************************************
 * @brief enable TLS host verification and define the expected server host name and/or IP address
 * @note it is crucial for TLS clients to verify the identity of the host to connect to
 *
 * @param truststore the trust store (typically returned from TLS_CTX_new()) where to set the host verification options
 * @param name the host DNS name to be expected, which may be given as a URL, or null
 * @param ip the host IP address to be expected, which may be given as a URL, or null
 * @note if both name and ip are non-null and equal, tries to interpret the string first as IP address then as domain name.
 * @note name and ip strings are copied, so do not need to be preserved after the call.
 * @return true on success, else false
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
bool STORE_set1_host_ip(X509_STORE* truststore, const char* name, const char* ip);

/*!*****************************************************************************
 * @brief add CRLs to trust store and enable CRL-based status checks for end-entity certificates
 *
 * @param store the trust store to be extended
 * @param crls the list of CRLs to be added, or null.
 * @return true on success, false on failure
 * @note A warning is given for each exired CRL. X509_V_FLAG_CRL_CHECK is set in the store.
 */
/* this function is part of the genCMPClient API */
bool STORE_add_crls(X509_STORE* store, OPTIONAL const STACK_OF(X509_CRL) * crls);

/*!*****************************************************************************
 * @brief set descriptive name of trust store to be used in diagnostics
 * @param store the certificate trust store, or null
 * @param desc description to use for diagnostics, or null
 * @return true on success, false on failure
 */
bool STORE_set1_desc(X509_STORE* store, OPTIONAL const char* desc);

/*!*****************************************************************************
 * @brief get descriptive name of trust store to be used in diagnostics
 * @param store the certificate trust store
 * @return description to use for diagnostics, or null on failure or if not set
 */
const char* STORE_get0_desc(OPTIONAL X509_STORE* store);

/*!*****************************************************************************
 * @brief set various optional verification parameters in the given trust store
 * @note demands certificate status checks in case any of the OCSP- or CRL-related options is set.
 * If in addition the full_chain option is set then all (except root) certificates are checked,
 * else only end-entity certificates, i.e., the first certificate of each chain.
 * @note For each certificate for which the status check is demanded the verification procedure will
 * try to obtain the revocation status first via OCSP stapling if enabled,
 * then from any locally available CRLs,
 * then from any Online Certificate Status Protocol (OCSP) responders if enabled,
 * and finally via any certificate distribution points (CDPs) if enabled.
 * Verification fails if no valid and current revocation status can be found
 * or the status indicates that the certificate has been revoked.
 *
 * @param store the certificate trust store to be extended
 * @param vpm OpenSSL certificate verification parameters to be taken over, or null for default
 * @param full_chain extend status checks to all (except root) certs
 * @param stapling enable OCSP stapling, which makes sense only for TLS
 * @param crls (optional) provide a list of CRLS to be added to the store and enable CRL-based checks
 * @param use_CDP enable using HTTP CDP entries in certificates and enable CRL-based status checking
 * @param cdps (optional) provide fallback CDP URL(s) and enable CRL-based status checking
 * @param crls_timeout number of seconds fetching a CRL may take, or 0 for infinite or -1 for default (= 10)
 * @param use_AIA enable using AIA OCSP responder entries in certificates and enable OCSP-based status checking
 * @param ocsp (optional) provides fallback OCSP responder URL(s) and enable OCSP-based status checking
 * @param ocsp_timeout number of seconds getting an OCSP response may take, or 0 for infinite or -1 for default (= 10)
 * @return true on success, false on failure
 *
 * @note further non-default trust store parameters may be set as far as needed
 *  using the various respective low-level OpenSSL functions.
 */
/* this function is part of the genCMPClient API */
bool STORE_set_parameters(X509_STORE* store, OPTIONAL const X509_VERIFY_PARAM* vpm,
                          bool full_chain, bool stapling,
                          OPTIONAL const STACK_OF(X509_CRL) * crls,
                          bool use_CDP, OPTIONAL const char* cdps, int crls_timeout,
                          bool use_AIA, OPTIONAL const char* ocsp, int ocsp_timeout);

typedef X509_CRL* (* CONN_load_crl_cb_t)(OPTIONAL void* arg,
                                         OPTIONAL const char* url, int timeout,
                                         const X509* cert, OPTIONAL const char* desc);
/*!*****************************************************************************
 * @brief set a CRL fetching callback function and optional argument in the given trust store
 * @note If use_CDP is set in the trust store the callback is called for each
 * HTTP URL found in the CDP entries of a cert. If all these are inconclusive then
 * it is called once more with a null URL (such that the callback may try getting
 * a CRL based on any further information contained in the certificate being checked).
 * @param store the certificate trust store to be extended
 * @param crl_cb the callback function to use, or null for default: CONN_load_crl_http() is called for non-null URL
 * @param crl_cb_arg the argument to pass to the callback function, or null
 * @return true on success, false on failure
 */
bool STORE_set_crl_callback(X509_STORE* store,
                            OPTIONAL CONN_load_crl_cb_t crl_cb,
                            OPTIONAL void* crl_cb_arg);

/*!*****************************************************************************
 * @brief use the CRL fetching function specified in the given trust store
 * @param store the certificate trust store containin the callback information
 * @param url the location of the CDP to use, or null
 * @param timeout number of seconds the HTTP transaction may take, or 0 for infinite or -1 for default
 * @param cert the certificate for which the status should be checked using the CRL
 * @param desc description of the CRL to use for any error messages, or null
 * @return pointer to downloaded CRL, or null on error
 */
X509_CRL* STORE_fetch_crl(X509_STORE* store, OPTIONAL const char* url, int timeout,
                          const X509* cert, OPTIONAL const char* desc);

/*!
 * @brief create or extend cert store structure with any given cert(s)
 * @note sets CREDENTIALS_print_cert_verify_cb() enabling diagnostic log output
 * @note use in addition STORE_set_parameters() to enable certificate status checks
 *
 * @param store certificate store to be extended if not null
 * @note  on error the store (if given) is deallocated
 * @param cert certificate to be added if not null
 * @param certs list of certificate to be added if not null
 * @return the created/extended store on success, null on error
 */
X509_STORE* STORE_create(OPTIONAL X509_STORE* store, OPTIONAL const X509* cert, OPTIONAL const STACK_OF(X509) * certs);

/*!
 * @brief extend or create cert store structure with cert(s) read from file
 * @note use in addition STORE_set_parameters() to enable certificate status checks
 *
 * @param pstore pointer to certificate store to be extended, which is created if null
 * @note  on error the trust store is not touched (allocated nor deallocated)
 * @param file name of file (in PEM or PKCS#12 or DER format) holding trusted certificates
 * @param format the format to try first when reading the file contents
 * @param desc description of file contents to use for any error messages, or null to ignore load errors
 * @param vpm verification parameters, or null, governing if and how to check cert times,
 * depending on X509_V_FLAG_USE_CHECK_TIME and X509_V_FLAG_NO_CHECK_TIME
 * @param ctx (optional) pointer to UTA context for checking file integrity&authenticity using ICV
 * @return true on success, false on error
 * @note For loaded certs their validity period and their CA flag are checked.
 *       Failures are logged as a warning if vpm is null, otherwise as an error.
 */
bool STORE_load_more_check(X509_STORE** pstore, const char* file,
                           file_format_t format, OPTIONAL const char* desc,
                           OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx* ctx);
#define STORE_load_more(pstore, file, format, desc, ctx) \
    STORE_load_more_check(pstore, file, format, desc, NULL, ctx)


/*!
 * @brief create a basic trust store, loading trusted certs from the given file(s)
 * @note use in addition STORE_set_parameters() to enable certificate status checks
 *
 * @param files name(s) of PEM or PKCS#12 or DER file(s) holding trusted certificates
 * @param desc description of file contents to use for any error messages, or null to ignore load errors
 * @param vpm verification parameters, or null, governing if and how to check cert times,
 * depending on X509_V_FLAG_USE_CHECK_TIME and X509_V_FLAG_NO_CHECK_TIME
 * @param ctx (optional) pointer to UTA context for checking file integrity&authenticity using ICV
 * @return pointer to a new X509_STORE structure, or null on error
 * @note For loaded certs their validity period and their CA flag are checked.
 *       Failures are logged as a warning if vpm is null, otherwise as an error.
 */
/* this function is used by the genCMPClient API implementation */
X509_STORE* STORE_load_check(const char* files, OPTIONAL const char* desc,
                             OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx* ctx);
#define STORE_load_trusted(files, desc, ctx) \
    STORE_load_check(files, desc, NULL, ctx)

/*!*****************************************************************************
 * @brief search for files with certificates in specified directory and adds them to X509_STORE
 *
 * @param pstore pointer to pointer to the trust store, which is created if null.
 * @note  on error the store is deallocated and set to null
 * @param trust_dir   directory where to search for certificates
 * @param desc        description of trusted certs to use for error reporting, or null
 * @param recursive   if true, use recursive search in subdirectories
 * @param vpm verification parameters, or null, governing if and how to check cert times,
 * depending on X509_V_FLAG_USE_CHECK_TIME and X509_V_FLAG_NO_CHECK_TIME
 * @param ctx (optional) pointer to UTA context for checking file integrity&authenticity using ICV
 * @note at least one valid certificate file must be found in all tested directories
 * @return true on success, false on error/failure
 * @note For loaded certs their validity period and their CA flag are checked.
 *       Failures are logged as a warning if vpm is null, otherwise as an error.
 ******************************************************************************/
bool STORE_load_check_dir(X509_STORE** pstore, const char* trust_dir,
                          OPTIONAL const char* desc, bool recursive,
                          OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx* ctx);
#define STORE_load_trusted_dir(pstore, trust_dir, desc, recursive, ctx) \
    STORE_load_check_dir(pstore, trust_dir, desc, recursive, NULL, ctx)

/*!*****************************************************************************
 * @brief search for files with CRLs in specified directory and add them to X509_STORE
 *
 * @param pstore      pointer to trust store to be augmented with CRLs.
 *                    CRL-based status checking will be enabled in it for the full certificate chain.
 * @param crl_dir     directory where to search for CRLs
 * @param desc        description of CRLs to use for error reporting, or null
 * @param recursive   if true, use recursive search in subdirectories
 * @param ctx pointer to UTA context for checking file integrity&authenticity using ICV, or null
 * @note at least one valid CRL file must be found in each visited directory
 * @return true on success, false on error/failure
 ******************************************************************************/
bool STORE_load_crl_dir(X509_STORE* pstore, const char* crl_dir, OPTIONAL const char* desc, bool recursive, OPTIONAL uta_ctx* ctx);

/*!*****************************************************************************
 * @brief release a trust store
 *
 * @param store (optional) the certificate trust store to be freed
 *******************************************************************************/
/* this function is part of the genCMPClient API */
void STORE_free(OPTIONAL X509_STORE* store);

/*!
 * Auxiliary functions for managing internal extensions to X509_STORE
 * to keep track of certificate verification and diagnostics parameters
 */

/*!
 * @brief Check that the initialization of X509_STORE extensions succeeded.
 *
 * @return true on success, false on failure
 *
 * The initialization is done automatically by using `__attribute__ ((constructor))`.
 * Destruction is also done automatically. You can use this to check that the static
 * global variable is initialized to a meaningful value.
 */
/* this function is part of the genCMPClient API */
bool STORE_EX_check_index(void);

/*!
 * @brief (re-)set expected host name for cert verification diagnostics
 *
 * @param store the affected certificate store
 * @param host the host name to set, or null to clear it
 * @return true on success, false on failure
 */
bool STORE_set1_host(X509_STORE* store, OPTIONAL const char* host);

/*!
 * @brief get expected host name for cert verification diagnostics
 *
 * @param store the certificate store to read from
 * @return the host name that has been set, or null if unset or on failure
 */
const char* STORE_get0_host(X509_STORE* store);

# ifndef SECUTILS_NO_TLS
/*!
 * @brief (re-)set the SSL BIO to indicate if TLS is active, for diagnostics
 * @note used to improve diagnostic output of CREDENTIALS_print_cert_verify_cb()
 *
 * @param store the affected certificate store
 * @param bio the SSL/TLS bio to set, or null to clear it
 * @return true on success, false on failure
 */
/* this function is used by the genCMPClient API implementation */
bool STORE_set0_tls_bio(X509_STORE* store, OPTIONAL BIO* bio);

/*!
 * @brief get the SSL BIO indicating if TLS is active, for diagnostics
 *
 * @param store the certificate store to read from
 * @return the SSL/TLS bio that has been set, or null if unset or on failure
 */
BIO* STORE_get0_tls_bio(X509_STORE* store);
# endif /* !defined(SECUTILS_NO_TLS) */

/*!
 * @brief get the cert revocation status checking parameters for CDP access
 *
 * @param store the certificate store to read from
 * @return pointer to the structure, or null if unset or on failure
 */
const revstatus_access* STORE_get0_cdps(X509_STORE* store);

/*!
 * @brief get the cert revocation status checking parameters for OCSP responder access
 *
 * @param store the certificate store to read from
 * @return pointer to the structure, or null if unset or on failure
 */
const revstatus_access* STORE_get0_ocsp(X509_STORE* store);

/*!*****************************************************************************
 * @brief print the certificates in a cert store
 *
 * @param store cert store with certificates to be printed, or null
 * @param bio BIO to print to, e.g., bio_err, or null
 *******************************************************************************/
void STORE_print_certs(OPTIONAL const X509_STORE* store, OPTIONAL BIO* bio);
#define UTIL_print_store_certs(bio, certs) STORE_print_certs(certs, bio)

/*!*****************************************************************************
 * @brief retrieves number of certificates in a cert store
 *
 * @param store cert store with certificates to be printed
 * @return number of certificates in the cert store
 *******************************************************************************/
int STORE_certs_num(const X509_STORE* store);
#define UTIL_store_certs_num(store) STORE_certs_num(store)

#endif /* SECUTILS_STORE_H_ */
