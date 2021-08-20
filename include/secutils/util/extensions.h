/** 
* @file extensions.h
* 
* @brief X.509 extensions
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

#ifndef SECUTILS_EXTENSIONS_H_
#define SECUTILS_EXTENSIONS_H_

#include <openssl/x509v3.h>

#include "util.h"


/*!*****************************************************************************
 * @brief allocate EXTENSIONS structure
 *
 * @result pointer to allocated EXTENSIONS structure, or null on out-of-memory error
 *******************************************************************************/
/* this function is part of the genCMPClient API */
X509_EXTENSIONS* EXTENSIONS_new(void);


/*!*****************************************************************************
 * @brief add domain names, IP addresses, and/or URIs as Subject Alternative Names to exts
 *
 * @param exts X.509 extensions to which SANs shall be appended
 * @param spec comma/space separated string of SAN names, may include "critical"
 * @return true on success, false on error
 *******************************************************************************/
/* this function is part of the genCMPClient API */
bool EXTENSIONS_add_SANs(X509_EXTENSIONS* exts, const char* spec);


/*!*****************************************************************************
 * @brief add (extended) key usages, basic constraints, policies, etc. to a list of X.509 extensions
 *
 * @param exts X.509 extensions to which new extensions shall be appended, or NULL
 * @param name unused
 * @param spec comma/space separated string of names, may include "critical"
 * @param sections (optional) BIO (e.g., memory BIO holding string) with sub-sections referred to by spec
 * @return true on success, false on error
 *******************************************************************************/
/* this function is part of the genCMPClient API */
bool EXTENSIONS_add_ext(X509_EXTENSIONS* exts, const char* name, const char* spec, OPTIONAL BIO* sections);


/*!*****************************************************************************
 * @brief release EXTENSIONS structure
 *
 * @param exts (optional) pointer to EXTENSIONS structure to be freed
 *******************************************************************************/
/* this function is part of the genCMPClient API */
void EXTENSIONS_free(OPTIONAL X509_EXTENSIONS* exts);

#endif /* SECUTILS_EXTENSIONS_H_ */
