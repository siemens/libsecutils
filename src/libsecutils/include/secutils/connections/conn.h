/** 
* @file conn.h
* 
* @brief Communication via OpenSSL BIO
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

#ifndef SECUTILS_CONN_H_
# define SECUTILS_CONN_H_

# include "../basic.h"

static const char* const CONN_scheme_postfix = "://";
static const char* const CONN_http_prefix = "http://";
static const char* const CONN_https_prefix = "https://";

#define CONN_IS_HTTP( uri) ((uri) != NULL && HAS_PREFIX(uri, OSSL_HTTP_PREFIX ))
#define CONN_IS_HTTPS(uri) ((uri) != NULL && HAS_PREFIX(uri, OSSL_HTTPS_PREFIX))

/*!*****************************************************************************
 * @brief parse URI of the form "[http[s]://]host[:port][/path]"
 * @param p_uri pointer to variable holding the URI to be parsed.
 * The variable is advanced past any leading "http[s]://" and any given port and/or path strings are chopped.
 * @param default_port specifies the default port to return:
 * may give an actual default port number or 0, which is replaced by 443 for https else by 80
 * @param p_path if this pointer is not null it will be used to assign on success
 * the pointer to any path component included in the input string, or null if not included.
 * @param desc description of the server to connect to, for use in diagnostic messages, or null
 * @return valid port number from input string or default, or <= 0 on error
 ******************************************************************************/
int CONN_parse_uri(char** p_uri, int default_port, const char** p_path, char* desc);

/*!*****************************************************************************
 * @brief copy host name or IP address from URI of the form "[http[s]://]host[:port][/path]"
 *
 * @param uri (optional) containing host name or IP address
 * @return pointer to a copy of the host specifier or null, null also on error
 ******************************************************************************/
char* CONN_get_host(OPTIONAL const char* uri);

# if !defined(OPENSSL_NO_SOCK)

#  include <openssl/bio.h>

/*!*****************************************************************************
 * @brief prepare a TCP abstraction BIO for client connect
 *
 * @param host the domain name or IP address, given as string, of the server to connect to
 * @param port (optional) the port number, given as string, to connect to
 * @note The host parameter may contain a ':' followed by a port specification.
 * In this case the port parameter must be null or contain the same string.
 * @return pointer to a new BIO structure, or null on error
 ******************************************************************************/
BIO* CONN_new(const char* host, const char* port);

/*!*****************************************************************************
 * @brief wait for peer via TCP BIO
 *
 * @param bio the connection setup to use (a TCP abstraction)
 * @param timeout number of seconds to wait at most, or 0 for infinite
 * @return < 0 on error, 0 on timeout, > 0 on success
 ******************************************************************************/
int CONN_wait(BIO* bio, int timeout);

#  ifndef SECUTILS_NO_TLS
/*!*****************************************************************************
 * @brief attach SSL_CTX to TCP BIO
 *
 * @param bio the connection setup modify (a TCP abstraction)
 * @param ssl_ctx the TLS context to attach. It can be free'd by the caller immediately.
 * @return the modified bio, 0 on error
 ******************************************************************************/
BIO* CONN_set1_TLS(BIO* bio, SSL_CTX* ssl_ctx);
#  endif

/*!*****************************************************************************
 * @brief connect as client via TCP BIO
 *
 * @param bio the connection setup to use (a TCP abstraction)
 * @param timeout number of seconds the connect may take, or 0 for infinite
 * @return -1 on error, 0 on timeout, 1 on success
 ******************************************************************************/
int CONN_connect(BIO* bio, int timeout);

# endif /* !defined(OPENSSL_NO_SOCK) */

#endif /* SECUTILS_CONN_H_ */
