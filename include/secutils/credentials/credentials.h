/** 
* @file credentials.h
* 
* @brief Credentials handling for all components
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

#ifndef SECUTILS_CREDENTIALS_H_
#define SECUTILS_CREDENTIALS_H_

#include "../basic.h"
#include "../util/util.h"
#include "../storage/files_dv.h"
#include "../storage/uta_api.h"

#include <openssl/x509.h>

typedef const char* component_creds_id; /**< component credentials identifier */
/**< one system component or application may have several sets of credentials */

/**< typedef struct credentials CREDENTIALS; -- already defined in basic.h */


/*!*****************************************************************************
 * @brief construct CREDENTIALS structure from the given parameters
 * @note On success the reference count of the first three parameters is incremented.
 * @param pkey   (optional) private key
 * @param cert   (optional) related certificate
 * @param chain  (optional) related chain of certificates
 * @param pwd    (optional) alternative: password (shared secret), may be preceded by 'pass:'
 * @param pwdref (optional) reference identifying the password
 * @return pointer to a new CREDENTIALS structure, or null on error
 *******************************************************************************/
/* this function is part of the genCMPClient API */
CREDENTIALS* CREDENTIALS_new(OPTIONAL const EVP_PKEY* pkey, OPTIONAL const OPTIONAL X509* cert,
                             OPTIONAL const STACK_OF(X509) * chain, OPTIONAL const char* pwd,
                             OPTIONAL const char* pwdref);

/*!*****************************************************************************
 * @brief get private key component of the given credentials
 *
 * @param creds credentials to read from
 * @return the component ptr on success, null ptr on failure (i.e., null creds argument)
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
EVP_PKEY* CREDENTIALS_get_pkey(const CREDENTIALS* creds);

/*!*****************************************************************************
 * @brief get certificate component of the given credentials
 *
 * @param creds credentials to read from
 * @return the component ptr on success, null ptr on failure (i.e., null creds argument)
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
X509* CREDENTIALS_get_cert(const CREDENTIALS* creds);

/*!*****************************************************************************
 * @brief get certificate chain component of the given credentials
 *
 * @param creds credentials to read from
 * @return the component ptr on success, null ptr on failure (i.e., null creds argument)
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
STACK_OF_X509 * CREDENTIALS_get_chain(const CREDENTIALS* creds);

/*!*****************************************************************************
 * @brief get password component of the given credentials
 *
 * @param creds credentials to read from
 * @return the component ptr on success, null ptr on failure (i.e., null creds argument)
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
char* CREDENTIALS_get_pwd(const CREDENTIALS* creds);

/*!*****************************************************************************
 * @brief get password reference component of the given credentials
 *
 * @param creds credentials to read from
 * @return the component ptr on success, null ptr on failure (i.e., null creds argument)
 *******************************************************************************/
/* this function is used by the genCMPClient API implementation */
char* CREDENTIALS_get_pwdref(const CREDENTIALS* creds);


/*!*****************************************************************************
 * @brief set private key component of the given credentials
 * @note the current component value is not freed but overwritten.
 *
 * @param pkey (optional) value to be set
 * @param creds credentials to modify
 * @return true on success, else failure (e.g, null creds argument)
 *******************************************************************************/
bool CREDENTIALS_set_pkey(CREDENTIALS* creds, EVP_PKEY* pkey);

/*!*****************************************************************************
 * @brief set certificate component of the given credentials
 * @note the current component value is not freed but overwritten.
 *
 * @param cert (optional) value to be set
 * @param creds credentials to modify
 * @return true on success, else failure (e.g, null creds argument)
 *******************************************************************************/
bool CREDENTIALS_set_cert(CREDENTIALS* creds, X509* cert);

/*!*****************************************************************************
 * @brief set certificate chain component of the given credentials
 * @note the current component value is not freed but overwritten.
 *
 * @param chain (optional) value to be set
 * @param creds credentials to modify
 * @return true on success, else failure (e.g, null creds argument)
 *******************************************************************************/
bool CREDENTIALS_set_chain(CREDENTIALS* creds, STACK_OF(X509) * chain);

/*!*****************************************************************************
 * @brief set password component of the given credentials
 * @note the current component value is not freed but overwritten.
 *
 * @param pwd (optional) value to be set
 * @param creds credentials to modify
 * @return true on success, else failure (e.g, null creds argument)
 *******************************************************************************/
bool CREDENTIALS_set_pwd(CREDENTIALS* creds, char* pwd);

/*!*****************************************************************************
 * @brief set password reference component of the given credentials
 * @note the current component value is not freed but overwritten.
 *
 * @param pwdref (optional) value to be set
 * @param creds credentials to modify
 * @return true on success, else failure (e.g, null creds argument)
 *******************************************************************************/
bool CREDENTIALS_set_pwdref(CREDENTIALS* creds, char* pwdref);


/*!*****************************************************************************
 * @brief release CREDENTIALS structure including all its components
 *
 * @param creds (optional) pointer to CREDENTIALS structure to be freed
 * @note this securely erases any memory cells used to store private key
 *******************************************************************************/
/* this function is part of the genCMPClient API */
void CREDENTIALS_free(OPTIONAL CREDENTIALS* creds);


/*!*****************************************************************************
 * @brief load asymmetric credentials from the given file(s) and optionally crypto engine
 * @note If used, encryption indirectly also protects integrity&authenticity of file-based storage.
 *
 * @param certs name of file holding certificate and optional chain, or null
 * @param key name of file holding private key or an engine key identifier, or null
 * @param source if this parameter is null or of the form "pass:PWD" then the 'key' parameter is taken as file name).
 *  If present, PWD is taken as password that may be needed for key file decryption.
 *  If the 'source' parameter is of the form "engine:ID" then ID refers to a pre-loaded OpenSSL
 *  crypto engine and the key parameter is used as a key identifier within the engine.
 * @param desc (optional) is used if present for forming more descriptive error messages
 * @return pointer to a new CREDENTIALS structure, or null on error
 * @note The 'certs' and the 'key' argument may not both be null. If they refer to equal names the credentials are first
 * tried to read jointly from the same file in PKCS#12 format. Otherwise, for each file the format tried first is PEM (while
 *depending on the file name extension also PKCS#12 or ASN.1 can be tried).
 *******************************************************************************/
/* this function is part of the genCMPClient API */
CREDENTIALS* CREDENTIALS_load(OPTIONAL const char* certs, OPTIONAL const char* key, OPTIONAL const char* source,
                              OPTIONAL const char* desc);


/*!*****************************************************************************
 * @brief load asymmetric credentials from the given file(s) and optionally using DV-based integrity&authenticity
 *protection
 * @note If used, encryption indirectly also protects integrity&authenticity of file-based storage.
 *
 * @param certs name of file holding certificate and optional chain, or null
 * @param key name of file holding private key, or null
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param desc (optional) is used if present for forming more descriptive error messages
 * @return pointer to a new CREDENTIALS structure, or null on error
 * @note When reading files, the file format tried first is PKCS#12 if the 'certs' and 'key' arguments are equal, else
 *PEM. A further format tried, which may be DER (ASN.1), is based on the file name extension.
 *******************************************************************************/
CREDENTIALS* CREDENTIALS_load_dv(OPTIONAL const char* certs, OPTIONAL const char* key, OPTIONAL uta_ctx* ctx,
                                 OPTIONAL const char* desc);


/*!*****************************************************************************
 * @brief save asymmetric credentials (except key held in crypto engine) to the given file(s)
 * @note If used, encryption indirectly also protects integrity&authenticity of file-based storage.
 *
 * @param creds pointer to the credential structure to save
 * @param certs name of file to store certificates, or null. Any previous contents are overwritten.
 * @param key name of file to store the private key unless the 'source' parameter
 *  refers to an engine (where this parameter may be null). Any previous file contents are overwritten.
 * @param source if this parameter is null or of the form "pass:PWD" then the key
 *   is stored to the given key. If present, PWD is taken as password to be
 *   used for key encryption. If the 'source' parameter is of the form "engine:<id>"
 *   the key is not stored because this does not apply for the engine interface.
 * @param desc (optional) is used if present for forming more descriptive error messages
 * @return true on success, else failure
 * @note If the 'certs' and 'key' arguments are equal and the file name extension is ".p12" or ".pkcs12",
 * the certs and the key are written jointly to the same PKCS#12 file.
 * Otherwise they are written in PEM format, potentially jointly to the same file.
 *******************************************************************************/
/* this function is part of the genCMPClient API */
bool CREDENTIALS_save(const CREDENTIALS* creds, OPTIONAL const char* certs, OPTIONAL const char* key,
                      OPTIONAL const char* source, OPTIONAL const char* desc);


/*!*****************************************************************************
 * @brief save asymmetric credentials to the given file(s)
 * @note If used, encryption indirectly also protects integrity&authenticity of file-based storage.
 *
 * @param creds pointer to the credential structure to save
 * @param certs name of file to store certificates, or null. Any previous contents are overwritten.
 * @param key name of file to store the private key, or null. Any previous contents are overwritten.
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param desc (optional) is used if present for forming more descriptive error messages
 * @return true on success, else failure
 * @note If the 'certs' and 'key' arguments are equal the certs and the key are
 *   jointly written to the same PKCS#12 file, else they are written to PEM files.
 *******************************************************************************/
bool CREDENTIALS_save_dv(const CREDENTIALS* creds, OPTIONAL const char* certs, OPTIONAL const char* key,
                         OPTIONAL uta_ctx* ctx, OPTIONAL const char* desc);

static const char* const CREDS_DIR_ENV = "CREDS_DIR";
static const char* const CREDS_DIR_DEFAULT = "certs/creds";

/*!*****************************************************************************
 * @brief obtain credentials of the given component (based on its ID) from PKCS#12 file
 * @note file name is derived from CREDS_DIR_ENV (defaulting to CREDS_DIR_DEFAULT), cid, and extension ".p12".
 * @note uses DV-based encryption, which also protects integrity&authenticity.
 *
 * @param cid identifier of the component credentials
 * @return pointer to a new CREDENTIALS structure, or null on error
 *******************************************************************************/
CREDENTIALS* CREDENTIALS_get(component_creds_id cid);

/*!*****************************************************************************
 * @brief store credentials of the given component (based on its ID) in PKCS#12 format
 * @note file name is derived from CREDS_DIR_ENV (defaulting to CREDS_DIR_DEFAULT), cid, and extension ".p12".
 * @note uses DV-based encryption, which also protects integrity&authenticity.
 *
 * @param cid identifier of the component credentials
 * @param creds credentials to store
 * @return true on success, else failure
 *******************************************************************************/
bool CREDENTIALS_store(component_creds_id cid, const CREDENTIALS* creds);


/**< callback to notify the owner of a set of credentials
 * when the certificate manager has updated this set of credentials
 * and saves them via CREDENTIALS_store()
 */
typedef void CREDENTIALS_update_cb(const char* tag);


/*!*****************************************************************************
 * @brief register callback to trigger when credentials are stored
 *
 * @param tag identifier of the credentials
 * @param fn (optional) callback function to be set, or null to clear entry
 * @return true on success, false on failure
 *******************************************************************************/
/*! @todo does not work if callers of this function and CREDENTIALS_save() use different secutils instances */
/*! @todo this feature is not (yet) thread safe */
bool CREDENTIALS_register_update_cb(const char* tag, OPTIONAL CREDENTIALS_update_cb* fn);

#endif /* SECUTILS_CREDENTIALS_H_ */
