/**
 * @file util.h
 *
 * @brief Various utility functions
 *
 * @copyright Copyright (c) Siemens Mobility GmbH, 2021
 *
 * @author David von Oheimb <david.von.oheimb@siemens.com>
 *
 * This work is licensed under the terms of the Apache Software License 2.0.
 * See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SECUTILS_UTIL_H_
# define SECUTILS_UTIL_H_

/* #if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0 */
/* #define OPENSSL_API_COMPAT 30000 */
# define OPENSSL_NO_DEPRECATED

# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
# include <ctype.h>   /* for isspace, isdigit */
# include <string.h>  /* for strcmp, strlen */
# include <strings.h> /* for strnlen, ... */
# include <limits.h>  /* for INT_MIN */
# include <unistd.h>

# include "../basic.h"
# include "../operators.h"

# include <openssl/err.h>
# include <openssl/x509v3.h>

static const char *const
UTIL_SECUTILS_NAME = "secutils";           /*!< short name of this library */
static const int UTIL_max_path_len = 512;  /*!< max length of file path name */
static const int UTIL_max_name_len = 128;  /*!< max length of file name */

# define OPENSSL_V_1_0_2 0x10002000L
# define OPENSSL_V_1_1_0 0x10100000L
# define OPENSSL_V_1_1_1 0x10101000L
# define OPENSSL_V_3_0_0 0x30000000L

# ifndef OpenSSL_version_num
#  if OPENSSL_VERSION_NUMBER < 0x10100000L
#   define OpenSSL_version_num SSLeay
#  elif OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
#   define OpenSSL_version_num() \
    ((unsigned long) \
     ((OPENSSL_version_major() << 28) | (OPENSSL_version_minor() << 20) | \
      (OPENSSL_version_patch() << 4) | _OPENSSL_VERSION_PRE_RELEASE))
#   define SHA256(data, len, buf) \
    (EVP_Digest(data, len, buf, NULL, EVP_sha256(), NULL), buf)
#  endif
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100002L
#  define X509_V_ERR_UNSPECIFIED 1
#  undef OPENSSL_strdup
#  define OPENSSL_strdup(s) ((s) not_eq 0 ? CRYPTO_strdup(s, __FILE__, \
                                                          __LINE__) : 0)
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100004L
#  define OPENSSL_FILE __FILE__
#  define OPENSSL_LINE __LINE__
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100005L
#  define SSL_CTX_get_ciphers(ctx) ((ctx)->cipher_list)
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100006L
#  define X509_STORE_CTX_get1_crls X509_STORE_get1_crls
#  ifndef X509_STORE_CTX_set0_verified_chain
#   define X509_STORE_CTX_set0_verified_chain(ctx, sk) \
    (sk_X509_pop_free((ctx)->chain, X509_free), (ctx)->chain = (sk))
#  endif
typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);
typedef int (*X509_STORE_CTX_check_revocation_fn)(X509_STORE_CTX *ctx);
#  define X509_STORE_CTX_get_check_revocation(ctx) ((ctx)->check_revocation)
#  ifndef X509_STORE_set_check_revocation
#   define X509_STORE_set_check_revocation(cx, f) ((cx)->check_revocation = (f))
#  endif
#  ifndef X509_STORE_CTX_set_error_depth
#   define X509_STORE_CTX_set_error_depth(c, dep) { (c)->error_depth = (dep); }
#  endif
#  define X509_STORE_CTX_get0_chain X509_STORE_CTX_get_chain
#  define EVP_PKEY_up_ref(x) ((x)->references++)
/*
 * OpenSSL 1.0.2 does not directly support STACK_OF(OPENSSL_CSTRING),
 * so add (limited) support here:
 */
DECLARE_STACK_OF(OPENSSL_CSTRING)
#  define sk_OPENSSL_CSTRING_push(st, v) SKM_sk_push(OPENSSL_CSTRING, (st), (v))
#  define sk_OPENSSL_CSTRING_new_null() SKM_sk_new_null(OPENSSL_CSTRING)
#  define sk_OPENSSL_CSTRING_num(st) SKM_sk_num(OPENSSL_CSTRING, (st))
/* define sk_OPENSSL_CSTRING_value(s,i)SKM_sk_value(OPENSSL_CSTRING,(s),(i)) */
static inline OPENSSL_CSTRING
sk_OPENSSL_CSTRING_value(const STACK_OF(OPENSSL_CSTRING) *sk, int idx)
{
    return (OPENSSL_CSTRING)sk_value((const _STACK *)sk, idx);
}
#  define sk_OPENSSL_CSTRING_free(st) SKM_sk_free(OPENSSL_CSTRING, (st))
#  define sk_OPENSSL_CSTRING_pop_free(st, free_func) \
    SKM_sk_pop_free(OPENSSL_CSTRING, (st), (free_func))
# endif
typedef STACK_OF(X509) STACK_OF_X509; /* workaround for Doxygen */
typedef STACK_OF(X509_CRL) STACK_OF_X509_CRL; /* workaround for Doxygen */

# if OPENSSL_VERSION_NUMBER < 0x10101000L
#  define sk_X509_new_reserve(f, n) sk_X509_new(f) /* sorry, no reservation */
#  define sk_X509_CRL_new_reserve(f, n) sk_X509_CRL_new(f) /* no reservation */
#  define OPENSSL_sk_new_reserve(f, n) sk_new(f) /* sorry, no reservation */
#  define OPENSSL_sk_reserve(sk, n) 1 /* sorry, no-op */
#  define ERR_clear_last_mark() 1 /* sorry, no-op */
int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b);
int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100007L
#  define ASN1_STRING_get0_data ASN1_STRING_data
#  define X509_get0_notBefore X509_get_notBefore
#  define X509_get0_notAfter X509_get_notAfter
# endif

# if OPENSSL_VERSION_NUMBER < 0x1010001fL
#  ifndef OPENSSL_zalloc
#   define OPENSSL_zalloc(num) CRYPTO_zalloc(num, __FILE__, __LINE__)
#   include <string.h>
static inline void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc((int)num, file, line);

    if (ret)
        memset(ret, 0, num);
    return ret;
}
#  endif
#  define X509_up_ref(x) ((x)->references++)
#  define X509_STORE_up_ref(x)((x)->references++)
#  define X509_OBJECT_get0_X509(obj) \
    ((obj) == NULL || (obj)->type != X509_LU_X509 ? NULL : (obj)->data.x509)
#  define X509_STORE_get0_objects(store) ((store)->objs)
#  define X509_STORE_CTX_get0_untrusted(ctx) ((ctx)->untrusted)
#  define X509_STORE_CTX_set_current_cert(ctx, x) { (ctx)->current_cert = (x); }
#  define X509_STORE_CTX_get_verify_mode(ctx) ((ctx)->verify_mode)
#  ifndef X509_STORE_CTX_get_verify_cb
#   define X509_STORE_CTX_get_verify_cb(ctx) ((ctx)->verify_cb)
typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);
#  endif
#  define X509_STORE_get0_objects(store) ((store)->objs)
#  define X509_STORE_get0_param(ctx) ((ctx)->param)
#  define X509_STORE_set_ex_data(ctx, idx, data) \
    CRYPTO_set_ex_data(&(ctx)->ex_data, (idx), (data))
#  define X509_STORE_get_ex_data(ctx, idx) \
    CRYPTO_get_ex_data(&(ctx)->ex_data, (idx))
#  define X509_VERIFY_PARAM_get_time(param) ((param)->check_time)
#  define X509_CRL_get0_lastUpdate X509_CRL_get_lastUpdate
#  define X509_CRL_get0_nextUpdate X509_CRL_get_nextUpdate
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100000L
/* compilation quirks for OpenSSL <= 1.0.2 */
_Pragma("GCC diagnostic ignored \"-Wdiscarded-qualifiers\"")
_Pragma("GCC diagnostic ignored \"-Wunused-function\"")
_Pragma("GCC diagnostic ignored \"-Wunused-parameter\"")
typedef unsigned char uint8_t;
typedef u_int32_t uint32_t;
typedef u_int64_t uint64_t;
#  define OPENSSL_strndup strndup
#  define CRYPTO_free_ex_index(cls_idx, idx) /* sorry, no-op (yet no memleak) */
#  define X509_get0_extensions(x) ((x)->cert_info->extensions)
#  define X509_get_extension_flags(x) (X509_check_purpose((x), -1, -1), \
                                       (x)->ex_flags)
#  define X509_V_FLAG_NO_CHECK_TIME 0x200000
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(TLS_client_method)
#  define TLS_server_method SSLv23_server_method /* Negot. highest available */
#  define TLS_client_method SSLv23_client_method /* Negot. highest available */
#  define TLS_method        SSLv23_method /* Negotiate highest available */
# endif

# if OPENSSL_VERSION_NUMBER < 0x10101000L
#  define SSL_CTX_set1_cert_store(ctx, st) \
    (X509_STORE_up_ref(st), SSL_CTX_set_cert_store(ctx, st))
# endif

# if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
STACK_OF(X509) *X509_STORE_get1_all_certs(X509_STORE *store);
# endif

/*!*****************************************************************************
 * @brief initialize the OpenSSL crypto library
 * @param version expected OpenSSL version number
 * @param build_name name of SW being built to be used in error messages,
 *        or null for the default: UTIL_SECUTILS_NAME
 * @note calls exit(EXIT_FAILURE) on error,
 *        e.g., version mismatch or initialization failure
 * @note this function is called upon libarary loading via STORE_EX_init_index()
 ******************************************************************************/
/* this function is used by the genCMPClient API implementation */
void UTIL_setup_openssl(long version, OPTIONAL const char *build_name);

/*!*****************************************************************************
 * @brief parse string as integer value, not allowing trailing garbage
 *
 * @note see also
 * https://www.gnu.org/software/libc/manual/html_node/Parsing-of-Integers.html
 * @param str input string
 * @return integer value, or INT_MIN on error
 ******************************************************************************/
int UTIL_atoint(const char *str); /* returns INT_MIN on error */

/*!*****************************************************************************
 * @brief advance the given string pointer by length of given pattern if present
 *
 * @param s input string
 * @param p (optional) pattern string
 * @return same as input string or pointer past the pattern p if s starts with p
 ******************************************************************************/
const char *UTIL_skip_string(const char *s, OPTIONAL const char *p);

/*!*****************************************************************************
 * @brief successively split string of items
 *     separated by commas and/or whitespace, which may be escapted using '\'
 *
 * @param str input string, which is split by overwriting separator(s) by '\0'
 * @return pointer to next item in string, or null at end of input
 ******************************************************************************/
char *UTIL_next_item(char *str);

/*!*****************************************************************************
 * @brief get the (last) file name extension in the given file (path) name
 *
 * @param filename the file name to analyze
 * @return pointer within the filename on success, else null
 ******************************************************************************/
const char *UTIL_file_ext(OPTIONAL const char *filename);

/*!*****************************************************************************
 * @brief read file contents into dynamically allocated buffer
 *
 * @param filename name of the file to read data from
 * @param lenp pointer to variable used for returning length of data
 * @return pointer to the allocated buffer with data, which is `\0' terminated
 ******************************************************************************/
void *UTIL_read_file(const char *filename, int *lenp);

/*!*****************************************************************************
 * @brief Write the contents of the memory pointed to by data to a file
 * @todo: what to do if file already exists? edge cases?
 * @param filename name of the file which the data will be written to
 * @param data pointer to data to be written to the file
 * @param len length in bytes of the supplied data
 * @return false on failure, true on success
 ******************************************************************************/
bool UTIL_write_file(const char *filename, const void *data, size_t len);

/*!*****************************************************************************
 * @brief call given function on each file in dir, optionally with recursion
 * @param fn function to be called on each file.
 *     The iteration stops and is considered failed as soon as it returns false.
 * @param arg user-defined extra argument to be passed to the function
 * @param path the name of the directory
 * @param recursive flag whether to iterate recursively over sub-directories
 * @return false on failure, true on success
 * @warning security note: the \p fn callback function
 *     must treat its \c file parameter as a `tainted` value
 * in the sense of
 * https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings
 ******************************************************************************/
bool UTIL_iterate_dir(bool (*fn)(const char *file, void *arg), void *arg,
                      const char *path, bool recursive);

/*!*****************************************************************************
 * @brief wipe the given memory area by overwriting it with 0s.
 *
 * @param dst start address of the memory area to wipe
 * @param len size in bytes of the memory area to wipe
 ******************************************************************************/
void UTIL_erase_mem(void *dst, size_t len);

/*!*****************************************************************************
 * @brief wipe the (secret) contents of the given string, using UTIL_erase_mem()
 *
 * @param str pointer to string to process (or null, then nothing is done)
 ******************************************************************************/
void UTIL_cleanse(OPTIONAL char *str);

/*!*****************************************************************************
 * @brief wipe the (secret) contents of the given string and free it
 *
 * @param str pointer to string to process (or null, then nothing is done)
 ******************************************************************************/
/* this function is used by the genCMPClient API implementation */
void UTIL_cleanse_free(OPTIONAL char *str);

/*!
 * @brief gets cryptographically strong random bytes via OpenSSL
 * @param buf pointer where to store the data
 * @param len amount of bytes to be stored
 * @return true on success, false on failure (for instance, insufficient seed)
 */
bool UTIL_get_random(void *buf, size_t len);

#define HAS_PREFIX(str, pre) (strncmp(str, pre "", sizeof(pre) - 1) == 0)
#define CHECK_AND_SKIP_PREFIX(str, pre) (HAS_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)

/*!
 * @brief The function copies the source string into the destination buffer
 * if given, otherwise just calculates how large it needs to be.
 *
 * This function is a helper that could possibly be replaced by built-in one.
 * It respects the receiving buffer length and always NUL terminates the buffer.
 * In addition it returns the buffer size needed when requested.
 * Normaly there are equivalents to this on most platforms,
 * which unfortunately are mostly platfrom dependent. So this placeholder is
 * used here, but could possibly be replaced by a better lib function on the
 * target platform.
 *
 * @param source pointer to the unencoded source string
 * @param destination optional pointer to destination buffer to hold the result
 * @param destination_len size of the destination buffer in bytes
 * @param size_needed optional pointer to the exact size needed for the
 *        converted string. If the size_needed is null the size is not returned
 *
 * @return number of bytes excluding the terminating NUL that have been written
 *             into the destination buffer.
 *         0 also on fatal error, e.g., the source is null
 *         or the destination is not null and the buffer size is 0.
 */
size_t UTIL_safe_string_copy(const char *source, OPTIONAL char *destination,
                             size_t destination_len,
                             OPTIONAL size_t *size_needed);

/*!
 * @brief The function URL-encodes the source string in the destination buffer.
 *
 * The function writes a URL-encoded version of the source string into the
 * destination buffer. The buffer will always be NUL terminated. If the buffer
 * is to small to hold the encoded string as well as the terminating NUL
 * then the encoded version will be truncated.
 *
 * @param source pointer to the unencoded source string
 * @param destination pointer to the destination buffer to hold the result
 * @param destination_len size of the destination buffer in bytes
 * @param size_needed optional pointer to the exact size needed for the
 *        converted string. If the size_needed is null the size is not returned
 *
 * @return number of bytes without the terminating NUL that have been written
 *             into the destination buffer.
 *         -1, if the buffer pointer is null or the buffer size is 0 and
 *             no size_needed is given.
 *         -2, if the buffer is to small
 */
size_t UTIL_url_encode(const char  *source,
                       char        *destination,
                       size_t      destination_len,
                       size_t      *size_needed);

# define BITS_PER_BYTE 8
# define B64_BITS 6
# define HEX_CHARS_PER_BYTE 2
# define HEX_BITS 4
# define HEX_MASK 0x0f
# define MAX_DIGIT 9

/*!
 * @brief The function converts a binary string into a sequence of hex values.
 *
 * This function is a helper that could possibly be replaced by a built-in one.
 * It respects the receiving buffer length and always NUL terminates the buffer.
 * In addition it returns the buffer size needed when requested.
 *
 * @param in pointer to the binary buffer to be converted
 * @param count number of bytes in the in buffer to be converted
 * @param uppercase indicate whether the hex string should be capitalized
 * @param separator a single char to be inserted every separator_count chars
 * @param separator_count the number of chars between separators,
 *        or 0 for no separator
 * @param out pointer to the output buffer,
 *        or null (used to just determine the size needed)
 * @param out_len number of chars (including the trailing NUL) in the output buf
 * @param size_needed optional pointer to the exact size needed for the
 *        converted string. If the size_needed is null the size is not returned
 *
 * @return number of bytes without the terminating NUL that have been written
 *             into the destination buffer.
 *         0 if the buffer is too small.
 */

size_t UTIL_bintohex(const unsigned char *in,
                     size_t              count,
                     const bool          uppercase,
                     const char          separator,
                     const unsigned int  separator_count,
                     char                *out,
                     size_t              out_len,
                     size_t              *size_needed);

/*!
 * @brief Convert given number of bytes to upper-case hex string
 * @param buf buffer to store the hex string, which is NUL terminated
 * @param buf_len size of buffer including the terminating NUL
 * @param bytes: input byte array
 * @param bytes_count: number of bytes in the input array
 * @result true on success, false on error
 */
# define UTIL_bytes_to_hex(buf, buf_len, bytes, bytes_count) \
    (UTIL_bintohex(bytes, bytes_count, 1, '\0', 0, \
                   buf, buf_len, NULL) == 2 * bytes_count)

/*
 * @brief convert given hex string to a given number of bytes
 * @param in_p pointer to input string, which does not need to be NUL terminated
 * @param buf the output buffer where the bytes are written to
 * @param num_out the expected number of bytes to write
 * @return true on success, false on error, e.g., too shore input string given
 */
bool UTIL_hex_to_bytes(const char **in_p, unsigned char *out,
                       unsigned int num_out);

# define MAX_B64_CHARS_PER_BYTE 2

/* return length of encoded string, which is NUL terminated, or < 0 on error */
int UTIL_base64_encode_to_buf(const unsigned char *data, int len,
                              char *buf, int buf_size);

unsigned char *UTIL_base64_decode(const char *b64_data, int b64_len,
                                  int *decoded_len);

#endif /* SECUTILS_UTIL_H_ */
