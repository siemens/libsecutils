/** 
* @file trusted.h
* 
* @brief Trust anchor configuration
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

#ifndef SECUTILS_TRUSTED_H_
#define SECUTILS_TRUSTED_H_

#include "../config/config.h"
#include "store.h"

static const char* const TRUST_CONFIG_ENV = "TRUST_CONF";
static const char* const TRUST_CONFIG_DEFAULT = "config/trusted.cnf";
static const char* const TRUST_CONFIG_SECTION_DEFAULT = "default";
static const char* const TRUST_CONFIG_ENTRY_TRUSTED = "trusted";
static const char* const TRUST_CONFIG_ENTRY_CRLS = "crls";


/*!*****************************************************************************
 * @brief obtain the trust store for the given component from its trust configuration ile section
 * @note the trust configuration file is taken from TRUST_CONFIG_ENV (defaulting to TRUST_CONFIG_DEFAULT)
 * @note the section may contain multiple entries for trusted cert files, with names derived from TRUST_CONFIG_ENTRY_TRUSTED, e.g.,
 * trusted.1 = certs/trusted1.crt
 * trusted.2 = certs/trusted2.crt
 * @note the section may contain multiple entries for CRL files, with names derived from TRUST_CONFIG_ENTRY_CRLS
 *
 * @param cid identifier of the component, which indicates the config file section to use, or TRUST_CONFIG_SECTION_DEFAULT if it is 0
 * @param vpm OpenSSL certificate verification parameters to be taken over, or null for default
 * @param ctx (optional) pointer to UTA context for checking file integrity&authenticity using ICV
 * @return pointer to a new CREDENTIALS structure, or null on error
 *******************************************************************************/
X509_STORE* CREDENTIALS_get_trust_store(component_creds_id cid, OPTIONAL X509_VERIFY_PARAM* vpm, OPTIONAL uta_ctx* ctx);

#endif /* SECUTILS_TRUSTED_H_ */
