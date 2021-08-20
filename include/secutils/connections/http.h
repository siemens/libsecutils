/** 
* @file http.h
* 
* @brief HTTP client for ASN.1 structures, needed for CRL fetching and OCSP
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

#ifndef SECUTILS_HTTP_H_
#define SECUTILS_HTTP_H_

#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)

#include <openssl/asn1.h>

#include "../basic.h"

/*!
 * @brief obtain ASN.1 response from given server
 *
 * @param url the location of the server
 * @param timeout number of seconds the HTTP transaction may take, or 0 for infinite
 * @param max_resp_len the maximal size of the response message, or 0 for the default: 100k
 * @param content_type the content type of the request, or null
 * @param req the request to send using the POST method, or null for using GET
 * @param req_it the ASN.1 item (type) info of the request, or null
 * @param res_it the ASN.1 item (type) info of the response
 * @param desc description of contents to use for any error messages, or null
 * @return pointer to the parsed response, or null on error
 */
ASN1_VALUE* CONN_load_ASN1_http(const char* url, int timeout,
                                unsigned long max_resp_len,
                                OPTIONAL const char* content_type,
                                OPTIONAL const ASN1_VALUE* req,
                                OPTIONAL const ASN1_ITEM* req_it,
                                const ASN1_ITEM* res_it, OPTIONAL const char* desc);

#endif /* !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) */

#endif /* SECUTILS_HTTP_H_ */
