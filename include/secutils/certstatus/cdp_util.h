/** 
* @file cdp_util.h
* 
* @brief Utilities needed by and assisting the CDP functionality.
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

#ifndef HEADER_CDP_UTIL_H
#define HEADER_CDP_UTIL_H

#include <util/util.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CRL reasons as bitfield flags */
typedef enum CDP_reason_flag {
    CDP_REASON_FLAG_UNUSED                  = 0x0001,
    CDP_REASON_FLAG_KEY_COMPROMISE          = 0x0002,
    CDP_REASON_FLAG_CA_COMPROMISE           = 0x0004,
    CDP_REASON_FLAG_AFFILIATION_CHANGED     = 0x0008,
    CDP_REASON_FLAG_SUPERSEEDED             = 0x0010,
    CDP_REASON_FLAG_CESSATION_OF_OPERATION  = 0x0020,
    CDP_REASON_FLAG_CERTIFICATE_HOLD        = 0x0040,
    CDP_REASON_FLAG_PRIVILEGE_WITHDRAWN     = 0x0080,
    CDP_REASON_FLAG_AA_COMPROMISE           = 0x0100
} CDP_REASON_FLAG;

#define CDP_REASON_FLAGSALL                 0x01FF
#define CDP_REASON_FLAGSCOUNT               9

typedef int CDP_REASON_FLAGS;

/* Copy a one-line representation of the X509_NAME into the buffer */
int CDP_get_x509_name(
    X509_NAME       *name,
    char            *name_utf8_buf,
    size_t          name_utf8_buf_len,
    unsigned long   flags
);

/* Copy the ASN1 time into a string */
int CDP_get_x509_time(
    const ASN1_TIME *time,
    char            *name_utf8_buf,
    size_t          name_utf8_buf_len
);

/*-
 * Get the first general name from a stack of general names
 * that is of type GEN_URI. Return a const char * pointer to
 * the internal data. The pointer is valid only as long as
 * the genereral_names parameter given is not freed.
 */
const char *CDP_get_uri_from_general_names(
    GENERAL_NAMES *general_names
);

/*-
 * Get the CDP url from a DIST_POINT structure.
 * Return a const char * pointer to the internal data.
 * The pointer is valid only as long as the distpoint
 * parameter given is not freed.*/
const char *CDP_get_crl_distribution_point_from_distpoint(
    DIST_POINT *distpoint
);

/*-
 * Get the CDP url from a stack of DIST_POINT structures.
 * Return a const char * pointer to the internal data.
 * The pointer is valid only as long as the cdp_extension
 * parameter given is not freed.*/
const char *CDP_get_crl_distribution_point_from_extension(
    CRL_DIST_POINTS *cdp_extension
);

/* Get the CDP url from an X509 certificate structure.
 * Return a const char * pointer to the internal data.
 * The pointer is valid only as long as the cert
 * parameter given is not freed.*/
int CDP_get_crl_distribution_point_from_cert(
    const X509  *cert,
    int         nid,
    char        *cdp_utf8_buf,
    size_t      cdp_utf8_buf_len
);

# ifdef  __cplusplus
}
# endif
#endif
