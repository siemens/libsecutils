/** 
* @file crl_mgmt.h
* 
* @brief Handling CRLs during certificate revocation check.
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

#ifndef SECUTILS_HEADER_CRL_MGMT_H
#define SECUTILS_HEADER_CRL_MGMT_H

#include <openssl/x509.h>

#include "../basic.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crlmgmt_data_st CRLMGMT_DATA;

/*!
 * @brief The function creates and initialises the context of the CRL management.
 *        The context is used during the verification of a certificate chain
 *        and holds parameter necessary for CRL download, a potential proxy,
 *        caching and other parameters.
 *
 * @return  pointer to initialized context of the CRL management
 *          0 on failure
 */
CRLMGMT_DATA *CRLMGMT_DATA_new(void);

/*!
 * @brief The function frees the context of the CRL management created by
 *        CRLMGMT_DATA_new(). Only the context itself is freed. Strings
 *        that have been set with the setter functions are in the
 *        responsability of the caller.
 *
 * @param cmdat pointer to the CRL management data structure
 */
void CRLMGMT_DATA_free(
    CRLMGMT_DATA *cmdat
);

/*!
 * @brief The function returns the proxy url in the CRL management context.
 *
 * @param cmdat pointer to the CRL management data structure
 * @return the proxy url
 */
const char *CRLMGMT_DATA_get_proxy_url(
    CRLMGMT_DATA *cmdat
);

/*!
 * @brief The function sets the proxy url in the CRL management context.
 * It will be used to send CDP URLs to inr the form C<url?url=CDP_URL>
 * to send issuer Distinguished Names (DNs) to in the form C<url?issuer=DN>.

 * @note  The proxy url is not copied into the structure. Therefore the
 *        parameter proxy_url must exist during the lifetime of the context.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param proxy_url the proxy url
 */
void CRLMGMT_DATA_set_proxy_url(
    CRLMGMT_DATA    *cmdat,
    const char      *proxy_url
);

/*!
 * @brief The function returns the maximum download size stored in the CRL
 *        management context.
 *
 * @param cmdat pointer to the CRL management data structure
 * @return the maximum download size in bytes, or 0 for the default
 */
unsigned long CRLMGMT_DATA_get_crl_max_download_size(
    CRLMGMT_DATA *cmdat
);

/*!
 * @brief The function sets the the maximum download size in the CRL management
 *        context.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param max_download_size the size limit for downloading CRLs in bytes, or 0 for the OpenSSL default: 100 kiB
 */
void CRLMGMT_DATA_set_crl_max_download_size(
    CRLMGMT_DATA    *cmdat,
    unsigned long   max_download_size
);

/*!
 * @brief The function returns the cache directory in the CRL management context.
 *
 * @param cmdat pointer to the CRL management data structure
 * 
 * @return the cache directory
 */
const char *CRLMGMT_DATA_get_crl_cache_dir(
    CRLMGMT_DATA *cmdat
);

/*!
 * @brief The function sets the cache directory in the CRL management context.
 * @note  The directory name is not copied into the structure. Therefore the
 *        parameter cache directory must exist during the lifetime of the context.
 *        If not null, it must end with the (potentally platform-specific) path separator.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param crl_cache_dir the cache directory
 */
void CRLMGMT_DATA_set_crl_cache_dir(
    CRLMGMT_DATA    *cmdat,
    const char      *crl_cache_dir
);

/*!
 * @brief The function returns the state of the use_url flag in the CRL management context.
 *
 * @param cmdat pointer to the CRL management data structure
 * 
 * @return the use_url flag
 */
bool CRLMGMT_DATA_get_use_url(
    CRLMGMT_DATA *cmdat
);

/*!
 * @brief The function sets the use_url flag in the CRL management context.
 *        The use_url flag indicates whether the CDP url shall be used to
 *        retrieve a CRL. The default is true.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param use_url the use_url flag
 */
void CRLMGMT_DATA_set_use_url(
    CRLMGMT_DATA    *cmdat,
    bool            use_url
);

/*!
 * @brief The function returns the use_issuer flag in the CRL management context.
 *
 * @param cmdat pointer to the CRL management data structure
 * 
 * @return the use_issuer flag
 */
bool CRLMGMT_DATA_get_use_issuer(
    CRLMGMT_DATA *cmdat
);

/*!
 * @brief The function sets the use_issuer flag in the CRL management context.
 *        The use_issuer flag indicates whether the certificates issuer shall
 *        be used to retrieve a CRL. This only works in combination with a
 *        CDP proxy.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param use_issuer the use_issuer flag
 */
void CRLMGMT_DATA_set_use_issuer(
    CRLMGMT_DATA    *cmdat,
    bool            use_issuer
);


/*!
 * @brief The function returns the note in the CRL management context.
 *
 * @param cmdat pointer to the CRL management data structure
 * 
 * @return the note
 */
const char *CRLMGMT_DATA_get_note(
    CRLMGMT_DATA *cmdat
);

/*!
 * @brief The function sets the note in the CRL management context.
 * @note  The note is not copied into the structure. Therefore the
 *        parameter note must exist during the lifetime of the context.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param note the note
 */
void CRLMGMT_DATA_set_note(
    CRLMGMT_DATA    *cmdat,
    const char      *note
);



/*!
 * @brief The function returns the CRL downloaded or cached from the url.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param url the url from where the CRL shall be downloaded
 * @param timeout the timeout of the http download
 * @param cert the certificate that is to be checked for revocation
 * @param desc description of the CRL source to use for diagnostics, or null
 * 
 * @return the CRL that has been downloaded (or gotten from cache) or NULL
 */
X509_CRL *CRLMGMT_load_crl_by_url(
    const CRLMGMT_DATA *cmdat,
    const char *url,
    int timeout,
    OPTIONAL const X509 *cert,
    OPTIONAL const char *desc
);

/*!
 * @brief The function returns the CRL downloaded or cached by using other
 *        certificate data, e.g. the issuer.
 *
 * @param cmdat pointer to the CRL management data structure
 * @param timeout the timeout of the http download
 * @param cert the certificate that is to be checked for revocation
 * @param desc description of the CRL source to use for diagnostics, or null
 * 
 * @return the CRL that has been downloaded (or gotten from cache) or NULL
 */
X509_CRL *CRLMGMT_load_crl_by_cert(
    const CRLMGMT_DATA *cmdat,
    int timeout,
    OPTIONAL const X509 *cert,
    OPTIONAL const char *desc
);

/*!
 * @brief Provide a callback function to be used in STORE_set_crl_callback().
 *
 * Depending on the presence of the url parameter
 * it calls CRLMGMT_load_crl_by_url() or CRLMGMT_load_crl_by_cert().
 *
 * @param arg optional argument to be passed to callback, this must
 *            be a pointer to a CRLMGMT_DATA structure.
 * @param url the url of the CRL to be downloaded
 * @param timeout timeout value for the download
 * @param cert the certificate that shall be checked
 * @param desc description of the CRL source to use for diagnostics, or null
 *
 * @return pointer to the downloaded CRL, NULL in case of error
 */

X509_CRL *CRLMGMT_load_crl_cb(
    OPTIONAL void *arg,
    const char *url,
    int timeout,
    OPTIONAL const X509 *cert,
    OPTIONAL const char *desc
);

# ifdef  __cplusplus
}
# endif
#endif // SECUTILS_HEADER_CRL_MGMT_H
