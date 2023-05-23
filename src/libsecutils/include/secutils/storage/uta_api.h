/** 
* @file uta_api.h
* 
* @brief libuta (https://github.com/siemens/libuta) integration for DV and ICV protection
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

#ifndef SECUTILS_UTA_API_H_
#define SECUTILS_UTA_API_H_

#include "static_config.h"

#define DVLEN 8 /* = UTA_LEN_DV_V1 */
#define TA_OUTLEN 32

typedef struct _uta_context_v1_t uta_ctx;

#ifdef SECUTILS_USE_UTA 

#include <stddef.h>
#include <stdint.h>

#include "../basic.h"


/*!
 * @brief initialize the use of the UTA library
 * @return pointer to the uta context, null on failure
 */
uta_ctx* uta_open(void); /* may be called more than once */


/*!
 * @brief de-initialize the given use of the UTA library
 * @param ctx the uta context to free
 * @return true on success, else false
 */
bool uta_close(uta_ctx* ctx);


/*!
 * @brief derives a device-specific key from a given derivation value through the UTA
 * @param ctx uta context to use
 * @param dv pointer to the derivation value
 * @param dvlen size in bytes of the derivation value. DVLEN bytes will be used internally.
 *              If a different length is supplied, a hash will be applied first.
 * @param out pointer to the place where the resulting key will be stored
 * @param outlen desired size in bytes of the resulting key. TA_OUTLEN bytes at most.
 * @return true on success, else false
 */
bool uta_getkey(uta_ctx* ctx, const unsigned char* dv, size_t dvlen, unsigned char* out, size_t outlen);


/*!
 * @brief get cryptographically secure (hardware-generated) random bytes from the UTA
 * @param ctx uta context to use
 * @param dst pointer where to store the random data
 * @param cnt number of bytes to be stored at dst
 * @return true on success, else false
 */
bool uta_get_random(uta_ctx* ctx, uint8_t* dst, size_t cnt);


#endif /* defined SECUTILS_USE_UTA  */

#endif /* SECUTILS_UTA_API_H_ */
