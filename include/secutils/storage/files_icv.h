/** 
* @file files_icv.h
* 
* @brief ICV-based protection for many types of files (including binary)
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

#ifndef SECUTILS_FILES_ICV_H_
#define SECUTILS_FILES_ICV_H_

#include "../basic.h"
#ifdef SECUTILS_USE_ICV

#include "../storage/uta_api.h"

#include <openssl/ossl_typ.h>

/*!
 * @brief (re-)protect integrity of file (of any type that allows appending text) with ICV derived via UTA
 *        from the absolute path name of the file
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file (path) name of the file to be protected
 * @return true on success, false on failure
 */
bool FILES_protect_icv(OPTIONAL uta_ctx* ctx, const char* file);


/*!
 * @brief (re-)protect integrity of file (of any type that allows appending text) with ICV derived via UTA
 *        from the supplied path name of the file. If none is supplied, the absolute path is derived.
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file (path) name of the file to be protected
 * @param location assumed location of the file.
 * @return true on success, false on failure
 */
bool FILES_protect_icv_at(OPTIONAL uta_ctx* ctx, const char* file, const char* location);


/*!
 * @brief (re-)protect integrity of file, if it has suffix .pem, .crt, or .cnf (unless SECUTILS_NO_ICV), with ICV
 * derived via UTA
 *
 * @param file (path) name of the file to be protected
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @return true on success, false on failure
 */
bool FILES_protect_icv_config_trusted(const char* file, OPTIONAL uta_ctx* ctx);


/*!
 * @brief check integrity of file (of any type that allows appending text) using ICV derived via UTA
 *        from the absolute path name of the file
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file (path) name of the file to be checked
 * @return true on positive outcome, else false (negative outcome or failure)
 */
bool FILES_check_icv(OPTIONAL uta_ctx* ctx, const char* file);


/*!
 * @brief check integrity of file (of any type that allows appending text) using ICV derived via UTA
 *        from the supplied path name of the file. If none is supplied, the absolute path is derived.
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file (path) name of the file to be checked
 * @param location assumed location of the file.
 * @return true on positive outcome, else false (negative outcome or failure)
 */
bool FILES_check_icv_at(OPTIONAL uta_ctx* ctx, const char* file, const char* location);


/*!
 * @brief load a certificate from the given PEM file, checking ICV-based protection
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file (path) name of the input file
 * @param desc description of file contents to use for any error messages, or null
 * @return the first certificate contained in the file on success, else null
 */
X509* FILES_load_cert_pem_icv(OPTIONAL uta_ctx* ctx, const char* file, OPTIONAL const char* desc);


/*!
 * @brief store the given certificate in given PEM file, with ICV-based protection
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param cert certificate to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
bool FILES_store_cert_pem_icv(OPTIONAL uta_ctx* ctx, const X509* cert, const char* file, OPTIONAL const char* desc);


/*!
 * @brief store the given certificate in given PEM file and optionally add ICV-based protection
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param cert certificate to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param desc description of file contents to use for any error messages, or null
 * @param add_icv *true* add ICV-based protection
 *                *false* without ICV-based protection
 * @return true on success, false otherwise
 */
bool FILES_store_cert_pem(OPTIONAL uta_ctx* ctx, const X509* cert, const char* file, OPTIONAL const char* desc,
                          bool add_icv);

/*!
 * @brief store the given CRL in given PEM file, with ICV-based protection
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param crl CRL to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
bool FILES_store_crl_pem_icv(OPTIONAL uta_ctx* ctx, const X509_CRL* crl, const char* file, OPTIONAL const char* desc);

#endif /* defined SECUTILS_USE_ICV */

#endif /* SECUTILS_FILES_ICV_H_ */
