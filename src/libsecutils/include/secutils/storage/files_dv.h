/** 
* @file files_dv.h
* 
* @brief Credential file handling using HW/SW derived key for protection
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

#ifndef SECUTILS_FILES_DV_H_
#define SECUTILS_FILES_DV_H_

/*!
 * Macro used for configuring the derivation value (DV) use at compile time:
 * If USE_DVFILE is defined, FILES_get_dv() bases the DVs on random values
 * held in a shared DV file referenced by DVFILE (or by "./config/dv.cnf").
 * Else FILES_get_dv() bases the DV on the absolute path of the respective DV-protected file.
 */

#include <openssl/x509.h>

#include "../storage/uta_api.h"
#define MAX_UTA_PASS_LEN (MAX_B64_CHARS_PER_BYTE * TA_OUTLEN + 1)
#include "files.h"

/*!
 * @brief get file encryption password from UTA using derivation value based on file path name
 *
 * @param pass_buf place to store the derived password as base64 encoded string, must be at least MAX_UTA_PASS_LEN chars
 * long
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context
 * @param filename name of file, typically including path
 * @param write flag whether the file is going to be written (rather than read)
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, false on failure
 * @note if USE_DVFILE is defined, DV is held in shared DV file, else taken from hashed absolute file path name
 */
bool FILES_get_pass_dv(char* pass_buf, uta_ctx* ctx, const char* filename, bool write, OPTIONAL const char* desc);

/*!
 * @brief get derivation value (DV) from a file path name
 *
 * @param filename name of file, typically including path
 * @param dv_out place to store the DV; must have DVLEN bytes of space
 * @return true on success, false on failure
 * @note function internally transforms relative path into absolute
 */
bool FILES_get_dv(const char* filename, unsigned char* dv_out);

/*!
 * @brief store private key in given file and format, optionally using DV-based password
 *
 * @param pkey private key to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param format the output format to use
 * @param pass password to use for encryption, in preference to DV-based one, or null
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
bool FILES_store_key_dv(const EVP_PKEY* pkey, const char* file, file_format_t format, OPTIONAL const char* pass,
                        OPTIONAL uta_ctx* ctx, OPTIONAL const char* desc);


/*!
 * @brief load private key from the given file or engine with flexible format, optionally using DV-based password
 *
 * @param key file (path) name of the input file or engine key ID
 * @param file_format the format to try first when reading file contents
 * @param pass password to use for decryption, in preference to DV-based one, or null
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param engine name of crypto engine to use, else null
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to the key loaded, or null on error
 */
EVP_PKEY* FILES_load_key_autofmt_dv(OPTIONAL const char* key, file_format_t file_format, OPTIONAL const char* pass,
                                    OPTIONAL uta_ctx* ctx, OPTIONAL const char* engine, OPTIONAL const char* desc);


/*!
 * @brief load certificates from the given file with flexible format, optionally using DV-based password
 *
 * @param file (path) name of the input file
 * @param format the format to try first when reading file contents
 * @param pass password to use for decryption, in preference to DV-based one, or null
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return null on error, else a stack of certs with the first/primary one on top
 */
STACK_OF(X509)
    * FILES_load_certs_autofmt_dv(const char* file, file_format_t format, OPTIONAL const char* pass,
                                  OPTIONAL uta_ctx* ctx, OPTIONAL const char* desc);


#endif /* SECUTILS_FILES_DV_H_ */
