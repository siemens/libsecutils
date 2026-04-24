/** 
* @file key.h
* 
* @brief Key management
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

#ifndef SECUTILS_KEY_H_
#define SECUTILS_KEY_H_

#include <openssl/evp.h>

#include "../basic.h"
#include "../util/util.h" /* for OSSL_LIB_CTX legacy workaround */

/*!*****************************************************************************
 * @brief generate a new private key according to the given specification
 *
 * @param spec specification for the type of the new key.
 * For ECC and RSA keys, this can be of the form "EC:<curve>", "RSA:<length>", "RSA-<length>" or "<length>".
 * Everything else is considered an ECC curve name if the OpenSSL version is below 3.5,
 * while for OpenSSL 3.5+, it is taken as an algorithm name, potentially including parameters, such as "ED25519" or "ML-DSA-<level>".
 * For the full list of available algorithms see the output of openssl list -public-key-algorithms
 * @param libctx for optional use with providers with OpenSSL 3.0+, otherwise must be null
 * @param propq may give a provider query string with OpenSSL 3.0+, otherwise must be null
 * @note The RSA key length may be 1024, 2048, 4096, or 8192 and the available ECC curves
 * can be shown with the command `openssl ecparam -list_curves`.
 * @note This function cannot be used for generating keys managed by a crypto engine.
 * @note Since OpenSSL 3.0, this may depend on the availability of a suitable provider.
 * @return the new key on success and null otherwise.
 *******************************************************************************/
/* this function is part of the genCMPClient API */
EVP_PKEY *KEY_new_ex(const char *spec, OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq);
#define SECUTILS_RSA_STR "RSA"
#define SECUTILS_EC_STR "EC"

/* this function is part of the genCMPClient API */
EVP_PKEY *KEY_new(const char *spec); /* same as KEY_new_ex(spec, NULL, NULL) */

/*!*****************************************************************************
 * @brief free an asymmetric (private) key
 *
 * @param pkey the key to be freed, or null
 * @note Any memory area holding private key data is securely erased.
 *******************************************************************************/
/* this function is part of the genCMPClient API */
void KEY_free(OPTIONAL EVP_PKEY* pkey);

#endif /* SECUTILS_KEY_H_ */
