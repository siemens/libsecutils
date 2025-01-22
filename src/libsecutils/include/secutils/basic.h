/** 
* @file basic.h
* 
* @brief Basic declarations (of types and macros) that need to be exported
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

#ifndef SECUTILS_BASIC_H_
#define SECUTILS_BASIC_H_

#include <secutils_static_config.h>

/* this type is part of the genCMPClient API */
#ifndef __cplusplus
typedef enum
{
    false = 0,
    true = 1
} bool; /*!< Boolean value */
#endif

/* this type is part of the genCMPClient API */
#define OPTIONAL /*!< marker for non-required parameter, i.e., null pointer allowed */

typedef enum
{
    success = 0,
    failure = -1
} result; /*!< Linux-style function result */

/* this type is part of the genCMPClient API */
typedef struct credentials CREDENTIALS; /* details in credentials/credentials.h */

#endif /* SECUTILS_BASIC_H_ */
