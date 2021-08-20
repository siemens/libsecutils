/** 
* @file operators.h
* 
* @brief Readable operator replacements
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2021
*
* @author David von Oheimb <david.von.oheimb@siemens.com>
*
* This work is  licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef SECUTILS_OPERATORS_H
#define SECUTILS_OPERATORS_H

/*
 * This is the only operator that is required by the coding standard for SIMIS Platforms
 * and is not defined in the C++ standard, or <ciso646>, or <iso646.h>
 */
#define is_eq   ==

/*
 * The following operators reserved keywords in the C++ standard
 * They are here, so that this header file can also be used by C source files
 */
#ifndef __cplusplus

/* These are recommended in the coding standard for SIMIS Platforms */
#define and     &&
#define not_eq  !=
#define or      ||

/* The following are not mentioned in the coding standard for SIMIS Platforms */
#define and_eq  &=
#define bitand  &
#define bitor   |
#define compl   ~
#define not     !
#define or_eq   |=
#define xor     ^
#define xor_eq  ^=

#endif /* __cplusplus */

#endif /* SECUTILS_OPERATORS_H */
