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

/*!*****************************************************************************
 * @brief generate a new private key according to the given specification
 *
 * @param spec specification for the type of the new key, which may be of the form "EC:<curve>" or "RSA-<length>"
 * @note The RSA key length may be 1024, 2048, or 4096 and the available ECC curves can be shown with the command
 *openssl ecparam -list_curves.
 * @note This function cannot be used for generating keys managed by a crypto engine.
 * @return the new key on success and null otherwise.
 *******************************************************************************/
/* this function is part of the genCMPClient API */
EVP_PKEY* KEY_new(const char* spec);


/*!*****************************************************************************
 * @brief free an asymmetric (private) key
 *
 * @param pkey the key to be freed, or null
 * @note Any memory area holding private key data is securely erased.
 *******************************************************************************/
/* this function is part of the genCMPClient API */
void KEY_free(OPTIONAL EVP_PKEY* pkey);

#endif /* SECUTILS_KEY_H_ */
