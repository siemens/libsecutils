/** 
* @file conn.c
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

#include <util/log.h>
#include <connections/conn.h>

#define OPENSSL_NO_SRP /* TODO remove after deprecation fix in OpenSSL 3.0-alpha */
#ifndef SECUTILS_NO_TLS
# include <openssl/ssl.h>
#endif

#include <operators.h>

static const char* skip_scheme(const char* str)
{
    const char *scheme_end = strstr(str, CONN_scheme_postfix);
    if(0 not_eq scheme_end)
    {
        str = scheme_end + strlen(CONN_scheme_postfix);
    }
    return str;
}

static const char* skip_userinfo(const char* str)
{
    static const char* const delims = "@[]/?#";
    const char* p = str;

    while (*p not_eq '\0' and strchr(delims, *p) is_eq 0)
        p++;
    if (*(p++) not_eq '@')
    {
        p = str;
    }
    return p;
}

int CONN_parse_uri(char** p_uri, int default_port, const char** p_path, char* desc)
{
    char* port_string;
    char* path_string;
    long port;

    if(0 is_eq p_uri or 0 is_eq *p_uri)
    {
        LOG_err("Invalid null pointer argument");
        return -1;
    }
    if(0 is_eq desc)
    {
        desc = "";
    }

    if(strncasecmp(*p_uri, CONN_https_prefix, strlen(CONN_https_prefix)) is_eq 0)
    {
        *p_uri += strlen(CONN_https_prefix);
        if(0 is_eq default_port)
        {
            default_port = 443; /* == integer value of OSSL_HTTPS_PORT */
        }
    }
    else
    {
        *p_uri = (char*)skip_scheme(*p_uri);
    }

    *p_uri = (char*)skip_userinfo(*p_uri);
    char* cont = *p_uri;
    if(*p_uri[0] is_eq '[')
    {
        cont = strrchr(++(*p_uri), ']');
        if(cont is_eq 0)
        {
            LOG(FL_ERR, "the <host> part in %s starts with '[' indicating an IPv6 address, but missing the closing ']' in \"%s\"", desc, *p_uri);
            return 0;
        }
        cont++;
    }

    if((port_string = strrchr(cont, ':')) not_eq 0)
    {
        char* error = 0;

        *port_string++ = '\0'; /* mark end of host string */
        port = strtol(port_string, &path_string, 10);
        if(path_string is_eq port_string
                or (*path_string not_eq '\0' and *path_string not_eq '/'))
        {
            error = "cannot be parsed";
        }
        else if(port < 1 or port > 65535)
        {
            error = "out of range 1..65535";
        }
        if(error not_eq 0)
        {
            if((path_string = strchr(port_string, '/')) not_eq 0)
            {
                *path_string = '\0';
            }
            LOG(FL_ERR, "%s port number '%s' %s", desc, port_string, error);
            return 0;
        }
        default_port = (int)port;
    }
    else
    {
        if(default_port is_eq 0)
        {
            default_port = 80; /* == integer value of OSSL_HTTP_PORT */
        }
        path_string = strchr(cont, '/');
    }

    if(path_string not_eq 0 and *path_string is_eq '/')
    {
        *path_string++ = '\0'; /* end of host string in case no port given */
    }
    if(p_path not_eq 0)
    {
        *p_path = path_string;
    }

    return default_port;
}

char* CONN_get_host(const char* uri)
{
    char* str = 0;
    if(uri not_eq 0)
    {
        uri = skip_scheme(uri);
        uri = skip_userinfo(uri);
        char* end;
        if(*uri is_eq '[')
        {
            end = strrchr(++uri, ']');
            if(end is_eq 0)
            {
                return 0;
            }
        }
        else if(0 is_eq (end = strrchr(uri, ':')))
        {
            end = strchr(uri, '/');
        }
        size_t len = end not_eq 0 ? (size_t)(end - uri) : strlen(uri);
        str = OPENSSL_strndup(uri, len);
        if(0 is_eq str)
        {
            LOG_err("Out of memory");
        }
    }
    return str;
}


#if !defined(OPENSSL_NO_SOCK)

# include <string.h>
# include <stdio.h>
# ifndef _WIN32
#  include <unistd.h>
# else
#  include <winsock.h> /* for type fd_set */
# endif

/* explicit #includes not strictly needed since implied by the above: */
# include <ctype.h>
# include <fcntl.h>
# include <stdlib.h>
# include <openssl/bio.h>
# include <openssl/buffer.h>
# include <openssl/err.h>

/* adapted from OpenSSL:apps/include/apps.h */
# ifndef openssl_fdset
#  ifdef _WIN32
#   define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#  else
#   define openssl_fdset(a,b) FD_SET(a, b)
#  endif
# endif

/* returns < 0 on error, 0 on timeout, > 0 on success */
static int socket_wait(int fd, int for_read, int timeout)
{
    fd_set confds;
    struct timeval tv;

    if(timeout <= 0)
    {
        return 0;
    }

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = timeout;
    return select(fd + 1, for_read ? &confds : 0,
                  for_read ? 0 : &confds, 0, &tv);
}

/* returns < 0 on error, 0 on timeout, > 0 on success */
int CONN_wait(BIO* bio, int timeout)
{
    int fd;

    if(BIO_get_fd(bio, &fd) <= 0)
    {
        return -1;
    }
    return socket_wait(fd, BIO_should_read(bio), timeout);
}

BIO* CONN_new(const char* host, const char* port)
{
    if(host is_eq 0) {
        LOG(FL_ERR, "no host name given");
        return 0;
    }

    char *host_port = strchr(host, ':');
    if(0 is_eq host_port and 0 is_eq port)
    {
        LOG(FL_ERR, "no port given");
        return 0;
    }
    if(host_port not_eq 0 and port not_eq 0 and strcmp(host_port+1, port) not_eq 0)
    {
        LOG(FL_ERR, "conflicting port specification given");
        return 0;
    }

    BIO* bio = BIO_new_connect(host);
    if(bio is_eq 0)
    {
        LOG(FL_ERR, "cannot create connect BIO");
        return 0;
    }
    if(port not_eq 0 /* else host_port is not null and has been used */
       and not BIO_set_conn_port(bio, port)) 
    {
        LOG(FL_ERR, "cannot set port for connect BIO");
        BIO_free(bio);
        return 0;
    }
    return bio;
}

# ifndef SECUTILS_NO_TLS
BIO* CONN_set1_TLS(BIO* bio, SSL_CTX* ssl_ctx) /* @todo check potential overlap with TLS_connect() */
{
    if(bio is_eq 0 or ssl_ctx is_eq 0)
    {
        LOG_err("Null argument");
    }

    BIO* sbio = BIO_new_ssl(ssl_ctx, 1);
    if (sbio is_eq 0)
    {
        LOG_err("cannot allocate SSL BIO");
        BIO_free_all(bio);
        return 0;
    }
    return BIO_push(sbio, bio);
}
#endif

/* returns -1 on error, 0 on timeout, 1 on success */
int CONN_connect(BIO* bio, int timeout)
{
    int blocking = timeout <= 0;
    time_t max_time = timeout > 0 ? time(0) + timeout : 0;
    bool retry;
    int rv;

/* https://www.openssl.org/docs/man1.1.0/crypto/BIO_should_io_special.html */
    if(not blocking)
    {
        BIO_set_nbio(bio, 1);
    }

    /* it does not help here to set SSL_MODE_AUTO_RETRY */
    do
    {
        retry = false;
        rv = BIO_do_connect(bio); /* This indirectly calls ERR_clear_error(); */
        /*
         * in blocking case, despite blocking BIO, BIO_do_connect() timed out
         * when non-blocking, BIO_do_connect() timed out early
         * with rv == -1 and errno == 0
         */
        if(rv <= 0 and (errno is_eq ETIMEDOUT or
                        ERR_GET_REASON(ERR_peek_error()) is_eq ETIMEDOUT))
        {
            ERR_clear_error();
            (void)BIO_reset(bio);
            /*
             * otherwise, blocking next connect() may crash and
             * non-blocking next BIO_do_connect() will fail
             */
            retry = true;
        }
        if(rv <= 0 and BIO_should_retry(bio))
        {
            if(blocking or (rv = CONN_wait(bio, (int)(max_time - time(0)))) > 0)
            {
                retry = true;
            }
        }
    } while(retry);
    return rv;
}

#endif /* !defined(OPENSSL_NO_SOCK) */
