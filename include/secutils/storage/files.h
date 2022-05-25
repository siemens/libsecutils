/** 
* @file files.h
* 
* @brief Private key, certificate, CSR (PKCS#10), and CRL file handling
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

#ifndef SECUTILS_FILES_H_
#define SECUTILS_FILES_H_

#include "../basic.h"
#include "../util/util.h"
#include "../connections/http.h"

#include <openssl/x509.h>

/*! supported format for security-related files */
/* taken over from OpenSSL:apps/include/apps.h */
enum
{
    B_FORMAT_TEXT = 0x8000
};
typedef enum
{
    FORMAT_UNDEF = 0,               /*! undefined file format */
    FORMAT_TEXT = 1 | B_FORMAT_TEXT,/* Generic text */
    FORMAT_ASN1 = 4,                /*! ASN.1/DER */
    FORMAT_PEM = 5 | B_FORMAT_TEXT, /*! PEM */
    FORMAT_PKCS12 = 6,              /*! PKCS#12 */
    FORMAT_ENGINE = 8,              /*! crypto engine, which is not really a file format */
    FORMAT_HTTP = 13                /*! download using HTTP */
} file_format_t;                  /*! type of format for security-related files or other input */

/**< string constants used for the 'source' parameter of some credentials load/store functions */
static const char* const sec_PASS_STR = "pass:";
static const char* const sec_ENGINE_STR = "engine:";
static const char* const sec_ENV_STR = "env:";
static const char* const sec_FILE_STR = "file:";
static const char* const sec_FD_STR = "fd:";
static const char* const sec_STDIN_STR = "stdin";
static const int sec_PASS_MAX_LEN = 256;

/*!
 * @brief map password source specification to password
 *
 * @param source the password source to use.
 * This may be a plain password, which should be preceded by 'pass:',
 * a key identifier preceded by 'engine:' to use with a crypto engine,
 * the name of a environment variable preceded by 'env:' to read from,
 * the name of a file preceded by 'file:' to read from,
 * the numeric descriptor of a file preceded by 'fd:' to read from,
 * or 'stdin' to indicate that the password input is to be read from STDIN.
 * @param desc description of file contents to use for any error messages, or null
 * @return null on error, else the resulting actual (plain) password
 * @note the caller must free the resulting string using UTIL_cleanse_free().
 */
char* FILES_get_pass(OPTIONAL const char* source, OPTIONAL const char* desc);


static const int MAX_FORMAT_RETRIES = 3;

/*!
 * @brief derive the (most likely) file contents format from the given file name
 *
 * @param filename file (path) name, should end with ".p12", ".pkcs12", ".pem",
 * ".der", ".crt", ".cer", ".crl", or ".csr", ".key", ".priv", or ".pub".
 * @return format as specified above, or FORMAT_UNDEF on error
 */
file_format_t FILES_get_format(const char* filename);


/*!
 * @brief load as many as possible certificates from the given file in specific format
 *
 * @param file (path) name of the input file
 * @param format the format to expect for the file contents
 * @param source the password source to use in case the input file is encrypted, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return null on error, else a stack of certs with the first/primary one on top
 */
STACK_OF(X509)
    * FILES_load_certs(const char* file, file_format_t format, OPTIONAL const char* source, OPTIONAL const char* desc);


/*!
 * @brief load a certificate from the given file in specific format
 *
 * @param file (path) name of the input file
 * @param format the format to expect for the file contents
 * @param source the password source to use in case the input file is encrypted, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return null on error, else the first certificate contained in the file
 */
X509* FILES_load_cert(const char* file, file_format_t format, OPTIONAL const char* source, OPTIONAL const char* desc);


/*!
 * @brief load as many as possible certificates from the given file with flexible format
 *
 * @param file (path) name of the input file
 * @param format the format to try first when reading the file contents
 * @param source the password source to use in case the input is encrypted, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return null on error, else a stack of certs with the first/primary one on top
 */
STACK_OF(X509)
    * FILES_load_certs_autofmt(const char* file, file_format_t format, OPTIONAL const char* source,
                               OPTIONAL const char* desc);


/*!
 * @brief load certificates from the given file(s) with flexible format
 *
 * @param files comma/space-separated list of input file (path) names
 * @param format the format to try first when reading file contents
 * @param source the password source to use in case the input is encrypted, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return null on error, else a stack of certs with the first/primary one on top
 * @note duplicate certificates among different input files are included only once
 */
/* this function is used by the genCMPClient API implementation */
STACK_OF(X509)
    * FILES_load_certs_multi(const char* files, file_format_t format, OPTIONAL const char* source,
                             OPTIONAL const char* desc);


/*!
 * @brief load private key from the given file or engine in specific format
 *
 * @param file (path) name of the input file, or engine key ID, or null
 * @param format FORMAT_ENGINE or the format to try first for the file contents
 * @param maybe_stdin flag whether to allow reading from STDIN if 'file' parameter is null
 * @param pass (optional) password to use for decryption
 * @param engine name of crypto engine if format is FORMAT_ENGINE, else null
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to the key loaded, or null on error
 */
EVP_PKEY* FILES_load_key(OPTIONAL const char* file, file_format_t format, bool maybe_stdin, OPTIONAL const char* pass,
                         OPTIONAL const char* engine, OPTIONAL const char* desc);


/*!
 * @brief load private key from the given file or engine with flexible format
 *
 * @param file (path) name of the input file, or engine key ID, or null
 * @param file_format the format to try first for the file contents
 * @param maybe_stdin flag whether to allow reading from STDIN if 'file' parameter is null
 * @param source the password source to use for decryption, or null
 * @param engine name of crypto engine to use, else null
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to the key loaded, or null on error
 */
EVP_PKEY* FILES_load_key_autofmt(OPTIONAL const char* file, file_format_t file_format, bool maybe_stdin,
                                 OPTIONAL const char* source, OPTIONAL const char* engine, OPTIONAL const char* desc);


/*!
 * @brief jointly load any private key, primary cert, and further certs from PKCS#12 file
 *
 * @param file name of PKCS#12 file to read from
 * @param pass password to use for decryption, or null
 * @param desc description of file contents to use for any error messages, or null
 * @param pkey pointer to variable to assign the read private key, or null
 * @param cert pointer to variable to assign the read primary certificate, or null
 * @param certs pointer to variable to assign the read list of further certificate, or null
 * @return true on success, else false
 * @note On success and in case the 'certs' parameter is not null (i.e., points to a variable),
 * if the variable contains null, a new stack of certs is allocated, else the certs are appended to the given stack.
 */
bool FILES_load_pkcs12(const char* file, OPTIONAL const char* pass, OPTIONAL const char* desc, OPTIONAL EVP_PKEY** pkey,
                       OPTIONAL X509** cert, OPTIONAL STACK_OF(X509) * *certs);

/*!
 * @brief load asymmetric credentials from the given file(s) and optionally from engine
 * @note If used, encryption indirectly also protects integrity&authenticity of file-based storage.
 *
 * @param certs name of file holding certificate and optional chain, or null
 * @param key file (path) name of the input file, or engine key ID, or null
 * @param file_format the format to try first for file contents
 *        If the 'certs' and the 'key' arguments are equal and the 'engine' argument is null
 *        the credentials are jointly read from the same file, which is expected in PKCS#12 format.
 * @param source the password source to use for decryption, or null
 * @param engine name of crypto engine to use for loading the private key, else null
 * @param desc (optional) is used if present for forming more descriptive error messages
 * @param pkey pointer to variable to assign the read private key, or null
 * @param cert pointer to variable to assign the read primary certificate, or null
 * @param chain pointer to variable to assign the read list of further certificate, or null
 * @return true on success, else false
 * @note On success and in case the 'chain' parameter is not null (i.e., points to a variable),
 * if the variable contains null, a new stack of certs is allocated, else the certs are appended to the given stack.
 */
bool FILES_load_credentials(OPTIONAL const char* certs, OPTIONAL OPTIONAL const char* key, file_format_t file_format,
                            OPTIONAL const char* source, OPTIONAL const char* engine, OPTIONAL const char* desc,
                            OPTIONAL EVP_PKEY** pkey, OPTIONAL X509** cert, OPTIONAL STACK_OF(X509) * *chain);


/*!
 * @brief load a public key from the given file in specific format
 *
 * @param file (path) name of the input file
 * @param format the format to expect for the file contents - currently FORMAT_PEM or FORMAT_ASN1
 * @param pass the password to use for decryption (currently supported for PEM only), or null
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to the public key loaded, or null on error
 */
EVP_PKEY *FILES_load_pubkey(const char *file, file_format_t format,
                            OPTIONAL const char *pass, OPTIONAL const char *desc);


/*!
 * @brief load a public key from the given file with flexbile format
 *
 * @param file (path) name of the input file
 * @param format the format to try first when reading the file contents - currently FORMAT_PEM or FORMAT_ASN1
 * @param source the password source to use for decryption (currently supported for PEM only), or null
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to the public key loaded, or null on error
 */
EVP_PKEY *FILES_load_pubkey_autofmt(const char *file, file_format_t format,
                                    OPTIONAL const char *source, OPTIONAL const char *desc);


/*!
 * @brief load a PKCS#10 CSR from the given file in specific format
 *
 * @param file (path) name of the input file
 * @param format the format to expect for the file contents
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to the CSR loaded, or null on error
 */
X509_REQ* FILES_load_csr(const char* file, file_format_t format, OPTIONAL const char* desc);


/*!
 * @brief load a PKCS#10 CSR from the given file with flexbile format
 *
 * @param file (path) name of the input file
 * @param format the format to try first when reading the file contents
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to the CSR loaded, or null on error
 */
X509_REQ* FILES_load_csr_autofmt(const char* file, file_format_t format, OPTIONAL const char* desc);


/*!
 * @brief store private key in given file and format, with optional password
 *
 * @param pkey private key to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param format the output format to use
 * @param source the password source to use for encryption, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
bool FILES_store_key(const EVP_PKEY* pkey, const char* file, file_format_t format, OPTIONAL const char* source,
                     OPTIONAL const char* desc);

/*!
 * @brief store the given list of certificates in given file and format
 *
 * @param certs list of certificates to save, or null
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param format the output format to use
 * @param desc description of file contents to use for any error messages, or null
 * @return the number of certificates saved, or < 0 on error
 */
int FILES_store_certs(OPTIONAL const STACK_OF(X509) * certs, const char* file, file_format_t format,
                      OPTIONAL const char* desc);


/*!
 * @brief store the given certificate in given file and format
 *
 * @param cert certificate to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param format the output format to use
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
bool FILES_store_cert(const X509* cert, const char* file, file_format_t format, OPTIONAL const char* desc);

/*!
 * @brief store the given list of CRLs in given file and format
 *
 * @param crls list of CRLs to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param format the output format to use
 * @param desc description of file contents to use for any error messages, or null
 * @return the number of certificates saved, or < 0 on error
 */
int FILES_store_crls(const STACK_OF(X509_CRL) * crls, const char* file, file_format_t format,
                     OPTIONAL const char* desc);


/*!
 * @brief store the given CRL in given file and format
 *
 * @param crl CRL to save
 * @param file (path) name of the output file. Any previous contents are overwritten.
 * @param format the output format to use
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
bool FILES_store_crl(const X509_CRL* crl, const char* file, file_format_t format, OPTIONAL const char* desc);

/*!
 * @brief jointly store any given private key, cert, and chain in PKCS#12 file
 *
 * @param pkey (optional) private key to save
 * @param cert (optional) related certificate to save
 * @param certs (optional) related certificate chain to save
 * @param file (path) name of the output file, which will have PKCS#12 format. Any previous contents are overwritten.
 * @param pass (optional) password to use for encryption
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 */
bool FILES_store_pkcs12(OPTIONAL const EVP_PKEY* pkey, OPTIONAL const X509* cert, OPTIONAL const STACK_OF(X509) * certs,
                        const char* file, OPTIONAL const char* pass, OPTIONAL const char* desc);

/*!
 * @brief store any given private key, cert, and chain in given file(s) and format
 *
 * @param key (optional) private key to save
 * @param cert (optional) related certificate to save
 * @param certs (optional) related certificate chain to save
 * @param keyfile (optional) path name of the key output file. Any previous contents are overwritten.1
 * @param file (optional) name of the cert(s) output file. Any previous contents are overwritten.
 * @param format the output format to use.
 * If the 'keyfile' and 'file' arguments are present and equal, the certs and the key are written jointly to the same
 * file, where only PKCS#12 is supported.
 * @param source the password source to use for decryption, or null
 * @param desc description of file contents to use for any error messages, or null
 * @return true on success, else false
 * @note If the file format is PEM or ASN1 and both cert and certs are present, the cert is stored before the certs.
 */
bool FILES_store_credentials(OPTIONAL const EVP_PKEY* key, OPTIONAL const X509* cert, OPTIONAL STACK_OF(X509) * certs,
                             OPTIONAL const char* keyfile, OPTIONAL const char* file, file_format_t format,
                             OPTIONAL const char* source, OPTIONAL const char* desc);

/*!
 * @brief load CRL via HTTP or from the given file, with flexbile format
 *
 * @param src input file or URL (in PEM or DER format) or URL
 * @param format FORMAT_HTTP or input format to try first, FORMAT_PEM or FORMAT_ASN1
 * @note For loading via HTTP only DER format (ASN.1) is supported.
 * @param timeout number of seconds an HTTP transaction (if needed) may take, or 0 for infinite or -1 for default
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to a new CRL structure, or null on error
 */
X509_CRL* FILES_load_crl_autofmt(const char* src, file_format_t format, int timeout, const char* desc);

/*!
 * @brief load CRLs via HTTP or from the given file, with flexbile format
 *
 * @param src input file or URL (in PEM or DER format) containing CRLs
 * @param format FORMAT_HTTP or input format to try first, either FORMAT_PEM or FORMAT_ASN1
 * @note For loading via HTTP only DER format (ASN.1) is supported.
 * @param timeout number of seconds an HTTP transaction (if needed) may take, or 0 for infinite or -1 for default
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to a new stack of X509_CRL structures, or null on error
 */
STACK_OF_X509_CRL * FILES_load_crls_autofmt(const char* src, file_format_t format, int timeout, OPTIONAL const char* desc);


/*!
 * @brief load CRLs from the given file(s) or URL(s)
 *
 * @param srcs comma/space-separated list of DER or PEM file(s) containing CRLs
 * @param format FORMAT_HTTP or input format to try first, either FORMAT_PEM or FORMAT_ASN1
 * @note For loading via HTTP only DER format (ASN.1) is supported.
 * @param timeout number of seconds an HTTP transaction (if needed) may take, or 0 for infinite or -1 for default
 * @param desc description of file contents to use for any error messages, or null
 * @return pointer to a new stack of X509_CRL structures, or null on error
 */
/* this function is used by the genCMPClient API implementation */
STACK_OF_X509_CRL * FILES_load_crls_multi(const char* srcs, file_format_t format, int timeout, OPTIONAL const char* desc);

/**
 * @brief get the directory where, e.g., credentials or CRL files are stored
 * @param base_ev name of environment variable optionally holding base path
 * @param base_default fallback base path used in case base_ev is not set
 * @param add_path additional path element to be appended, or null pointer
 * @return path name, to be freed by caller, or null pointer on failure.
 */
char* FILES_get_dir(const char* base_ev, const char* base_default, const char* add_path);

#endif /* SECUTILS_FILES_H_ */
