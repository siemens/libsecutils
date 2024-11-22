/**
* @file files.c
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

#define OPENSSL_NO_RC4 /* prevent errors on undeclared FORMAT_MSBLOB and FORMAT_PVK */
//#define OSSL_DEPRECATEDIN_3_1
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <util/util.h>
#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
/* compilation quirks for using crypto engines in OpenSSL >= 3.0 */
_Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#endif

#include <sys/stat.h>
#include <storage/files.h>
#include <certstatus/crls.h>
#include <credentials/cert.h>
#include <util/log.h>
# include <connections/conn.h>

#include <operators.h>

static file_format_t adjust_format(const char* * file, file_format_t format, bool engine_ok)
{
    if(strncasecmp(*file, CONN_http_prefix, strlen(CONN_http_prefix)) is_eq 0 or
       strncasecmp(*file, CONN_https_prefix, strlen(CONN_https_prefix)) is_eq 0)
    {
        format = FORMAT_HTTP;
    }
#ifndef OPENSSL_NO_ENGINE
    else if(engine_ok and strncmp(*file, sec_ENGINE_STR, strlen(sec_ENGINE_STR)) is_eq 0)
    {
        *file += strlen(sec_ENGINE_STR);
        format = FORMAT_ENGINE;
    }
#endif
    else
    {
        *file = UTIL_skip_string("file:", *file);
    }
    return format;
}

/* guess next potential file format according to given file name extension */
static file_format_t next_format(file_format_t last_format, const char* s)
{
    file_format_t format = FORMAT_UNDEF;
    if(last_format is_eq FORMAT_ENGINE or s is_eq 0)
    {
        return format;
    }
    if(*s is_eq '1' or strcasecmp(s, "PKCS12") is_eq 0 or strcasecmp(s, "p12") is_eq 0)
    {
        format = FORMAT_PKCS12;
    }
    else if(*s is_eq 'P' or *s is_eq 'p')
    { /* due to pattern overlap, must be after checking for PKCS12 */
        format = FORMAT_PEM;
    }
    else if(*s is_eq 'D' or *s is_eq 'd')
    { /* ASN.1/DER */
        format = FORMAT_ASN1;
    }
    else if(strcasecmp(s, "crt") is_eq 0 or strcasecmp(s, "cer") is_eq 0 or
            strcasecmp(s, "crl") is_eq 0 or strcasecmp(s, "csr") is_eq 0)
    {
        /* weak recognition of DER format with fallback to PEM */
        format = last_format is_eq FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM;
    }
    else if(strcasecmp(s, "key") is_eq 0 or strcasecmp(s, "priv") is_eq 0 or strcasecmp(s, "pub") is_eq 0)
    {
        /* weak recognition of DER format with fallback to PEM */
        format = last_format is_eq FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM;
    }
    else
    {
#ifndef OPENSSL_NO_ENGINE
        if(*s is_eq 'E' or *s is_eq 'e')
        {
            format = FORMAT_ENGINE;
        }
#endif
    }
    if(format is_eq last_format /* or format is_eq FORMAT_ENGINE */)
    {
        format = FORMAT_UNDEF;
    }
    return format;
}


#if not defined(OPENSSL_NO_UI) and not defined(OPENSSL_NO_ENGINE)
static UI_METHOD* ui_method = 0;
#endif


file_format_t FILES_get_format(const char* filename)
{
    file_format_t result = FORMAT_PEM;
    if(filename not_eq 0)
    {
        result = next_format(FORMAT_UNDEF, UTIL_file_ext(filename));
        if(result is_eq FORMAT_UNDEF)
        {
            LOG(FL_ERR, "bad input format for '%.40s', should be PEM, DER, or PKCS12", filename);
        }
    }
    return result;
}


static bool istext(file_format_t format)
{
    return ((unsigned)format bitand (unsigned) B_FORMAT_TEXT) is_eq B_FORMAT_TEXT;
}


static BIO* dup_bio_in(file_format_t format)
{
    return BIO_new_fp(stdin, (unsigned)BIO_NOCLOSE bitor (unsigned)(istext(format) ? BIO_FP_TEXT : 0));
}


static BIO* dup_bio_out(file_format_t format)
{
    BIO* b = BIO_new_fp(stdout, (unsigned)BIO_NOCLOSE bitor (unsigned)(istext(format) ? BIO_FP_TEXT : 0));
#ifdef OPENSSL_SYS_VMS
    if(istext(format) not_eq 0)
    {
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
    }
#endif
    return b;
}


static void unbuffer(FILE* fp)
{
/*
 * On VMS, setbuf() will only take 32-bit pointers, and a compilation
 * with /POINTER_SIZE=64 will give off a MAYLOSEDATA2 warning here.
 * However, we trust that the C RTL will never give us a FILE pointer
 * above the first 4 GB of memory, so we simply turn off the warning
 * temporarily.
 */
#if defined(OPENSSL_SYS_VMS) and defined(__DECC)
#pragma environment save
#pragma message disable maylosedata2
#endif
    setbuf(fp, 0);
#if defined(OPENSSL_SYS_VMS) and defined(__DECC)
#pragma environment restore
#endif
}


#define MODESTR_LEN1 (strlen("rb") + 1)
static BIO* bio_open_default_(const char* filename, char mode, file_format_t format, bool quiet)
{
    BIO* ret;

    if(filename is_eq 0)
    {
        LOG(FL_ERR, "null filename argument");
        return 0;
    }
    if(/* filename is_eq 0 or */ strcmp(filename, "-") is_eq 0)
    {
        ret = mode is_eq 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if(quiet)
        {
            ERR_clear_error();
        }
        if(quiet or ret not_eq 0)
        {
            return ret;
        }
        LOG(FL_ERR, "cannot open %s, %s", mode is_eq 'r' ? "stdin" : "stdout", strerror(errno));
    }
    else
    {
        filename = UTIL_skip_string("file:", filename);
        char modestr[MODESTR_LEN1];
        snprintf(modestr, MODESTR_LEN1, "%c%c", mode, istext(format) ? '\0' : 'b');
        ret = BIO_new_file(filename, modestr);
        if(quiet)
        {
            ERR_clear_error();
        }
        if(quiet or ret not_eq 0)
        {
            return ret;
        }
        LOG(FL_ERR, "cannot open file '%s' for mode '%c', %s", filename, mode, strerror(errno));
    }
    (void)ERR_print_errors(bio_err);
    return 0;
}


static BIO* bio_open_default(const char* filename, char mode, file_format_t format)
{
    return bio_open_default_(filename, mode, format, false);
}


char* FILES_get_pass(OPTIONAL const char* source, OPTIONAL const char* desc)
{
    BIO* bio = 0;
    char buf[sec_PASS_MAX_LEN + 1];
    const char* pass = 0;

    if(source is_eq 0)
    {
        return 0; /* no password is fine */
    }
    else if(strncmp(source, sec_PASS_STR, strlen(sec_PASS_STR)) is_eq 0)
    {
        pass = source + strlen(sec_PASS_STR);
    }
#ifndef OPENSSL_NO_ENGINE
    else if(strncmp(source, sec_ENGINE_STR, strlen(sec_ENGINE_STR)) is_eq 0)
    {
        pass = source + strlen(sec_ENGINE_STR);
    }
#endif
    else if(strncmp(source, sec_ENV_STR, strlen(sec_ENV_STR)) is_eq 0)
    {
        pass = getenv(source + strlen(sec_ENV_STR));
        if(pass is_eq 0)
        {
            LOG(FL_ERR, "No environment variable %s\n", source + strlen(sec_ENV_STR));
        }
    }
    else if(strncmp(source, sec_FILE_STR, strlen(sec_FILE_STR)) is_eq 0)
    {
        bio = BIO_new_file(source + strlen(sec_FILE_STR), "r");
        if(bio is_eq 0)
        {
            LOG(FL_ERR, "Cannot open file %s\n", source + strlen(sec_FILE_STR));
        }
    }
#if !defined(_WIN32)
    /*
     * Under _WIN32, which covers even Win64 and CE, file
     * descriptors referenced by BIO_s_fd are not inherited
     * by child process and therefore below is not an option.
     * It could have been an option if bss_fd.c was operating
     * on real Windows descriptors, such as those obtained
     * with CreateFile.
     */
    else if(strncmp(source, sec_FD_STR, strlen(sec_FD_STR)) is_eq 0)
    {
        int i = atoi(source + strlen(sec_FD_STR));
        if(i >= 0)
        {
            bio = BIO_new_fd(i, BIO_NOCLOSE);
        }
        if((i < 0) or bio is_eq 0)
        {
            LOG(FL_ERR, "Cannot access file descriptor %s\n", source + strlen(sec_FD_STR));
        }
        /* Cannot do BIO_gets on an fd BIO so add a buffering BIO */
        bio = BIO_push(BIO_new(BIO_f_buffer()), bio);
#endif
    }
    else if(strcmp(source, sec_STDIN_STR) is_eq 0)
    {
        bio = dup_bio_in(FORMAT_TEXT);
        if(bio is_eq 0)
        {
            LOG(FL_ERR, "Cannot open BIO for stdin");
        }
    }
    else
    {
        pass = source;
        LOG(FL_WARN, "No 'pass:' or 'engine:' or 'env:' or 'file:' or 'fd:' prefix or 'stdin' found; assuming plain password for '%s'",
            desc not_eq 0 ? desc : "key");
    }
    if(bio not_eq 0)
    {
        if(BIO_gets(bio, buf, sec_PASS_MAX_LEN + 1) <= 0)
        {
            LOG(FL_ERR, "Error reading password from BIO");
        }
        else
        {
            char* tmp = strchr(buf, '\n');
            if(tmp not_eq 0)
            {
                *tmp = '\0';
            }
            pass = buf;
        }
        BIO_free_all(bio);
    }
    return OPENSSL_strdup(pass);
}


typedef struct pw_cb_data
{
    const void* password;
    const char* prompt_info;
} PW_CB_DATA;


static int password_callback(char* buf, int bufsiz, int verify, void* cb_tmp)
{
    int res = 0 * verify; /* make (artificial) use of 'verify' */
    const char* password = 0;
    PW_CB_DATA* cb_data = (PW_CB_DATA*)cb_tmp;

    if((cb_data not_eq 0) and (cb_data->password not_eq 0))
    {
        password = cb_data->password;
    }

    if(password not_eq 0)
    {
        res = strlen(password);
        if(res > bufsiz)
        {
            res = bufsiz;
        }
        memcpy(buf, password, res); /* copy password and length(res) into buf */
    }
    return res; /* the size */
}

/* adapted from OpenSSL:apps/lib/apps.c
 * @warning security note: the `pem_cb` callback must be compliant with
 * https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings
 */
static int load_pkcs12(BIO* in, OPTIONAL const char* desc, OPTIONAL pem_password_cb* pem_cb, OPTIONAL void* cb_data,
                       OPTIONAL EVP_PKEY** pkey, OPTIONAL X509** cert, OPTIONAL STACK_OF(X509) * *ca)
{
    const char* pass;
    char tpass[PEM_BUFSIZE];
    int len, ret = 0;
    PKCS12* p12;
    const char* const for_str = desc not_eq 0 ? " for " : "";
    const char* const desc_str = desc not_eq 0 ? desc : "";

    p12 = d2i_PKCS12_bio(in, 0);
    if(p12 is_eq 0)
    {
        if(desc not_eq 0)
        {
            LOG(FL_ERR, "cannot load file for %s in PKCS12 format", desc);
            (void)ERR_print_errors(bio_err);
        }
        return 0;
    }
    /* See if an empty password will do */
    if(PKCS12_verify_mac(p12, "", 0) not_eq 0 or PKCS12_verify_mac(p12, 0, 0) not_eq 0)
    {
        LOG(FL_WARN, "Unencrypted PKCS#12 file%s%s", for_str, desc_str);
        pass = "";
    }
    else
    {
        if(pem_cb is_eq 0)
        {
            pem_cb = password_callback;
        }
        len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
        if(len < 0)
        {
            LOG(FL_ERR, "passphrase callback error for %s", desc not_eq 0 ? desc : "PKCS#12 file");
            goto die;
        }
        if(len < PEM_BUFSIZE)
        {
            tpass[len] = 0;
        }
        if(0 is_eq PKCS12_verify_mac(p12, tpass, len))
        {
            LOG(FL_ERR, "mac verify error (wrong password?) in PKCS12 file%s%s", for_str, desc_str);
            goto die;
        }
        pass = tpass;
    }
    EVP_PKEY* unused_pkey = 0;
    X509* unused_cert = 0;
    ret = PKCS12_parse(p12, pass, pkey is_eq 0 ? &unused_pkey : pkey, cert is_eq 0 ? &unused_cert : cert, ca);
    if(pkey is_eq 0)
    {
        EVP_PKEY_free(unused_pkey);
    }
    if(cert is_eq 0)
    {
        X509_free(unused_cert);
    }
die:
    PKCS12_free(p12);
    return ret;
}


bool FILES_load_pkcs12(const char* file, OPTIONAL const char* pass, OPTIONAL const char* desc, OPTIONAL EVP_PKEY** pkey,
                       OPTIONAL X509** cert, OPTIONAL STACK_OF(X509) * *certs)
{
    PW_CB_DATA cb_data;
    cb_data.password = pass;
    cb_data.prompt_info = file;

    LOG(FL_TRACE, "opening file '%s' for loading %s",
        file, desc not_eq 0 ? desc : "certs and key");
    BIO* bio = bio_open_default(file, 'r', FORMAT_PKCS12);
    if(bio is_eq 0)
    {
        return false;
    }

    bool res = load_pkcs12(bio, desc, password_callback, &cb_data, pkey, cert, certs) not_eq 0;
    BIO_free(bio);
    return res;
}


bool FILES_load_credentials(OPTIONAL const char* certs, OPTIONAL OPTIONAL const char* key, file_format_t file_format,
                            OPTIONAL const char* source, OPTIONAL const char* engine, OPTIONAL const char* desc,
                            OPTIONAL EVP_PKEY** pkey, OPTIONAL X509** cert, OPTIONAL STACK_OF(X509) * *chain)
{
    bool res = false;
    if(engine is_eq 0 and certs not_eq 0 and key not_eq 0 and strcmp(certs, key) is_eq 0)
    {
        char* pass = FILES_get_pass(source, desc);
        ERR_set_mark();
        res = FILES_load_pkcs12(certs, pass, 0 /* desc */, pkey, cert, chain);
        if(res)
        {
            ERR_clear_last_mark();
        }
        else
        {
            ERR_pop_to_mark();
        }
        UTIL_cleanse_free(pass);
    }
    if(not res)
    {
        if(key not_eq 0 and pkey not_eq 0
           and (*pkey = FILES_load_key_autofmt(key, file_format, false, source, engine, desc)) is_eq 0)
        {
            goto err;
        }
        if(certs not_eq 0 and (cert not_eq 0 or chain not_eq 0))
        {
            STACK_OF(X509)* certs_ = FILES_load_certs_autofmt(certs, file_format, source, desc);
            if(certs_ is_eq 0)
            {
                EVP_PKEY_free(*pkey);
                goto err;
            }
            X509* cert_ = 0;
            if(sk_X509_num(certs_) > 0)
            {
                cert_ = sk_X509_delete(certs_, 0);
            }

            if(cert not_eq 0)
            {
                *cert = cert_;
            }
            else
            {
                X509_free(cert_);
            }

            if(chain not_eq 0)
            {
                *chain = certs_;
            }
            else
            {
                CERTS_free(certs_);
            }
        }
    }

    X509_VERIFY_PARAM *vpm = NULL; /* unfortunately no VPM available */
    if(cert != NULL)
        (void)CERT_check(certs, *cert, 0 /* tentatively warn on CA cert */, vpm);
    if(chain != NULL)
        (void)CERT_check_all(certs, *chain, 1 /* warn on non-CA certs */, vpm);

    return true;

err:
    LOG(FL_ERR, "Could not load %s from %s", desc not_eq 0 ? desc : "credentials", pkey is_eq 0 ? key : certs);
    return false;
}


/* verbatim from OpenSSL:apps/lib/apps.c but with two adaptations to avoid code smell warnings */
static int gather_certs_crls(STACK_OF(X509_INFO) * xis, STACK_OF(X509) * *pcerts, STACK_OF(X509_CRL) * *pcrls)
{
    int i, n = sk_X509_INFO_num(xis);

    for(i = 0; i < n; i++)
    {
        X509_INFO* xi = sk_X509_INFO_value(xis, i);
        if(xi->x509 not_eq 0 and pcerts not_eq 0)
        {
            if(0 is_eq sk_X509_push(*pcerts, xi->x509))
            {
                LOG(FL_ERR, "out of memory");
                return 0;
            }
            xi->x509 = 0;
        }
        if(xi->crl not_eq 0 and pcrls not_eq 0)
        {
            if(0 is_eq sk_X509_CRL_push(*pcrls, xi->crl))
            {
                LOG(FL_ERR, "out of memory");
                return 0;
            }
            xi->crl = 0;
        }
    }

    if(pcerts not_eq 0 and sk_X509_num(*pcerts) > 0)
    {
        return 1;
    }

    if(pcrls not_eq 0 and sk_X509_CRL_num(*pcrls) > 0)
    {
        return 1;
    }
    return 0;
}

/* read as many as possible certs and/or CRLs, in PEM or DER format, from BIO */
/* DER format may also contain multiple certs or CRLs, but not mix these types */
static int load_certs_crls_BIO(BIO* bio, file_format_t format, const char* pass, const char* desc,
                               STACK_OF(X509) * *pcerts, STACK_OF(X509_CRL) * *pcrls)
{
    STACK_OF(X509_INFO)* xis = 0;
    int rv = 0;

    if(bio is_eq 0 or (pcerts is_eq 0 and pcrls is_eq 0))
    {
        return 0;
    }

    if(format not_eq FORMAT_PEM and format not_eq FORMAT_ASN1)
    {
        LOG(FL_ERR, "unsupported input format (%d) specified for %s", format,
            desc not_eq 0 ? desc : (pcerts not_eq 0 ? "certs" : "CRLs"));
        return 0;
    }

    if(pcerts not_eq 0 and *pcerts is_eq 0)
    {
        *pcerts = sk_X509_new_null();
        if(0 is_eq * pcerts)
        {
            LOG(FL_ERR, "out of memory");
            goto end;
        }
    }

    if(pcrls not_eq 0 and *pcrls is_eq 0)
    {
        *pcrls = sk_X509_CRL_new_null();
        if(0 is_eq * pcrls)
        {
            LOG(FL_ERR, "out of memory");
            goto end;
        }
    }

    if(format is_eq FORMAT_ASN1)
    {
        X509* cert = 0;
        X509_CRL* crl = 0;
        do
        {
            if(pcerts not_eq 0)
            {
                cert = d2i_X509_bio(bio, 0);
                if(cert not_eq 0 and sk_X509_push(*pcerts, cert) is_eq 0)
                {
                    goto end;
                }
            }
            else
            {
                crl = d2i_X509_CRL_bio(bio, 0);
                if(crl not_eq 0 and sk_X509_CRL_push(*pcrls, crl) is_eq 0)
                {
                    goto end;
                }
            }
        } while(cert not_eq 0 or crl not_eq 0);
        if(not BIO_eof(bio))
        {
            goto end;
        }
        return 1;
    }

    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = desc;
    xis = PEM_X509_INFO_read_bio(bio, 0, password_callback, &cb_data);

    rv = gather_certs_crls(xis, pcerts, pcrls);

end:

    sk_X509_INFO_pop_free(xis, X509_INFO_free);

    if(rv is_eq 0)
    {
        if(pcerts not_eq 0)
        {
            CERTS_free(*pcerts);
            *pcerts = 0;
        }
        if(pcrls not_eq 0)
        {
            sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
            *pcrls = 0;
        }
        if(desc not_eq 0)
        {
            LOG(FL_ERR, "unable to load %s", /* pcerts not_eq 0 ? "certificates" : "CRLs", */ desc);
            (void)ERR_print_errors(bio_err);
        }
    }
    return rv;
}

/* read as many as possible certs and/or CRLs, in PEM or DER format, from file */
/* DER format may also contain multiple certs or CRLs, but not mix these types */
static int load_certs_crls(const char* file, file_format_t format, const char* pass, const char* desc,
                           STACK_OF(X509) * *pcerts, STACK_OF(X509_CRL) * *pcrls)
{
    BIO* bio = bio_open_default_(file, 'r', format, desc is_eq 0);
    int res = load_certs_crls_BIO(bio /* may be 0 */, format, pass, desc, pcerts, pcrls);
    BIO_free(bio);
    return res;
}

static long bio_len(BIO *bio)
{
    long len = -1;
    FILE *fp;

    if (BIO_get_fp(bio, &fp) == 1 && fseek(fp, 0, SEEK_END) == 0) {
        len = ftell(fp);
        (void)fseek(fp, 0, SEEK_SET);
    }
    return len;
}

/* returns non-null pointer if file is empty or at least one certificate has been loaded successfully.
   The top element on the stack returned is the primary one. Uses format as given. */
STACK_OF(X509)
    * FILES_load_certs(const char* file, file_format_t format, OPTIONAL const char* source, OPTIONAL const char* desc)
{
    X509* cert = 0;
    STACK_OF(X509)* certs = 0;
    char* pass = FILES_get_pass(source, desc);

    LOG(FL_TRACE, "opening file '%s' for loading %s", file, desc not_eq 0 ? desc : "certs");
    BIO* bio = bio_open_default(file, 'r', format);
    if(bio is_eq 0)
    {
        goto end;
    }
    if(bio_len(bio) is_eq 0) /* empty file */
    {
        BIO_free(bio);
        UTIL_cleanse_free(pass);
        return sk_X509_new_null();
    }

    if(format is_eq FORMAT_PEM or format is_eq FORMAT_ASN1)
    {
        if(load_certs_crls_BIO(bio, format, pass, desc, &certs, 0 /* crls */) not_eq 0)
        {
            cert = sk_X509_delete(certs, 0);
        }
    }
    else if(format is_eq FORMAT_PKCS12)
    {
        PW_CB_DATA cb_data;

        cb_data.password = pass;
        cb_data.prompt_info = file;

        if(0 is_eq load_pkcs12(bio, desc, password_callback, &cb_data, 0, &cert, &certs))
        {
            cert = 0;
        }
    }
    else
    {
        LOG(FL_ERR, "unsupported input format (%d) for loading %s", format, desc not_eq 0 ? desc : file);
        goto end;
    }
    if(cert not_eq 0)
    {
        if(0 is_eq sk_X509_insert(certs, cert, 0))
        {
            LOG(FL_ERR, "out of memory");
            X509_free(cert);
            cert = 0;
        }
    }

end:
    BIO_free(bio);
    UTIL_cleanse_free(pass);
    if(cert is_eq 0)
    {
        CERTS_free(certs);
        certs = 0;
        if(desc not_eq 0)
        {
            LOG(FL_ERR, "unable to load %s from file '%s'", desc, file);
        }
    }
    return certs;
}


/* returns non-null pointer if file is empty of at least one certificate has been loaded successfully.
   The top element on the stack returned is the primary one. Tries the given format first. */
STACK_OF(X509)
    * FILES_load_certs_autofmt(const char* file, file_format_t format, OPTIONAL const char* source,
                               OPTIONAL const char* desc)
{
    STACK_OF(X509)* certs = 0;

    int retries = 0;

    ERR_set_mark();
    do
    {
        certs = FILES_load_certs(file, format, source, 0 /* desc */);

        if(certs is_eq 0)
        {
            format = next_format(format, UTIL_file_ext(file));
            if((++retries < MAX_FORMAT_RETRIES) and (format not_eq FORMAT_UNDEF))
            {
                continue;
            }
        }
        break;
    } while(1);
    if(certs is_eq 0)
    {
        ERR_clear_last_mark();
        (void)ERR_print_errors(bio_err);
        LOG(FL_ERR, "unable to load %s from file '%s'", desc not_eq 0 ? desc : "certs", file);
    }
    else
    {
        ERR_pop_to_mark();
    }
    return certs;
}


STACK_OF(X509)
    * FILES_load_certs_multi(const char* files, file_format_t format, OPTIONAL const char* source,
                             OPTIONAL const char* desc)
{
    if(files is_eq 0)
    {
        return 0;
    }

    LOG(FL_TRACE, "Loading %s from file(s) '%s'", desc not_eq 0 ? desc : "certs", files);

    STACK_OF(X509)* certs = 0;
    STACK_OF(X509)* result = sk_X509_new_null();
    char* names = OPENSSL_strdup(files);
    if(result is_eq 0 or names is_eq 0)
    {
        goto oom;
    }

    char* file;
    char* next;
    for(file = names; file not_eq 0; file = next)
    {
        next = UTIL_next_item(file); /* must do this here to split string */

        if(0 is_eq(certs = FILES_load_certs_autofmt(file, format, source, desc)))
        {
            goto err;
        }
        if(0 is_eq UTIL_sk_X509_add1_certs(result, certs, 0, 1 /*no dups*/))
        {
            goto oom;
        }
        CERTS_free(certs);
    }
    OPENSSL_free(names);
    return result;

oom:
    LOG_err("Out of memory");
err:
    CERTS_free(certs);
    CERTS_free(result);
    OPENSSL_free(names);
    return 0;
}


X509* FILES_load_cert(const char* file, file_format_t format, OPTIONAL const char* source, OPTIONAL const char* desc)
{
    STACK_OF(X509)* certs = FILES_load_certs(file, format, source, desc);
    X509* cert = sk_X509_num(certs) > 0 ? sk_X509_shift(certs) : 0;

    CERTS_free(certs);
    return cert;
}


/* adapted from OpenSSL:apps/lib/apps.c just for visibility reasons */
#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a sharable library */
static ENGINE* try_load_engine(const char* engine)
{
    ENGINE* e = ENGINE_by_id("dynamic");

    if(e not_eq 0)
    {
        if(0 is_eq ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0) or 0 is_eq ENGINE_ctrl_cmd_string(e, "LOAD", 0, 0))
        {
            ENGINE_free(e);
            e = 0;
        }
    }
    return e;
}
#endif


#ifndef OPENSSL_NO_ENGINE
/* adapted from OpenSSL:apps/lib/apps.c just for visibility reasons */
static ENGINE* setup_engine_no_default(const char* engine, int debug)
{
    ENGINE* e = 0;

    if(engine not_eq 0)
    {
        if(strcmp(engine, "auto") is_eq 0)
        {
            LOG(FL_ERR, "enabling auto ENGINE support");
            ENGINE_register_all_complete();
            return 0;
        }
        if((e = ENGINE_by_id(engine)) is_eq 0)
        {
            if((e = try_load_engine(engine)) is_eq 0)
            {
                LOG(FL_ERR, "invalid engine \"%s\"", engine);
                (void)ERR_print_errors(bio_err);
                return 0;
            }
        }
        if(debug not_eq 0 and 0 is_eq ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0))
        {
            return 0;
        }
        if(0 is_eq ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1))
        {
            return 0;
        }
#if 0
        if(not ENGINE_set_default(e, ENGINE_METHOD_ALL))
        {
            LOG(FL_ERR, "cannot use that engine");
            (void)ERR_print_errors(bio_err);
            ENGINE_free(e);
            return 0;
        }
#endif

        LOG(FL_ERR, "engine \"%s\" set.", ENGINE_get_id(e));
    }
    return e;
}

static void release_engine(ENGINE* e)
{
    if(e not_eq 0)
    {
        /* Free our "structural" reference. */
        ENGINE_free(e);
    }
}
#endif


static EVP_PKEY* load_key_engine(const char* keyid, const char* pass, const char* engine, const char* desc)
{
    EVP_PKEY* pkey = 0;
#ifndef OPENSSL_NO_ENGINE
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = keyid;

    if(engine is_eq 0)
    {
        LOG(FL_ERR, "no engine specified");
        return 0;
    }
    ENGINE* e = setup_engine_no_default(engine, 0);
    if(e is_eq 0)
    {
        LOG(FL_ERR, "cannot set up engine '%s'", engine);
        return 0;
    }
    if(ENGINE_init(e) not_eq 0)
    {
        pkey = ENGINE_load_private_key(e, keyid, ui_method, &cb_data);
        ENGINE_finish(e);
    }
    release_engine(e);
    if(pkey is_eq 0 and desc not_eq 0)
    {
        LOG(FL_ERR, "cannot load %s from engine '%s'", desc, engine);
        (void)ERR_print_errors(bio_err);
    }
#else
    LOG(FL_ERR, "crypto engines not supported in this build, request engine = '%s'", engine);
#endif
    return pkey;
}


/* adapted from OpenSSL:apps/lib/apps.c */
EVP_PKEY* FILES_load_key(OPTIONAL const char* file, file_format_t format, bool maybe_stdin, OPTIONAL const char* pass,
                         OPTIONAL const char* engine, OPTIONAL const char* desc)
{
    BIO* bio = 0;
    EVP_PKEY* pkey = 0;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if(file is_eq 0 and (0 is_eq maybe_stdin or format is_eq FORMAT_ENGINE))
    {
        LOG(FL_ERR, "no key input specified for %s", desc not_eq 0 ? desc : "private key");
        goto end;
    }
    if(format is_eq FORMAT_ENGINE)
    {
        LOG(FL_TRACE, "loading %s '%s' from engine '%s'", desc, file, engine);
        pkey = load_key_engine(file, pass, engine, desc not_eq 0 ? desc : "private key");
        goto end;
    }
    LOG(FL_TRACE, "opening file '%s' for loading %s",
        file not_eq 0 ? file : "STDIN", desc not_eq 0 ? desc : "private key");
    if(file is_eq 0 and maybe_stdin not_eq 0)
    {
        unbuffer(stdin);
        bio = dup_bio_in(format);
    }
    else
    {
        bio = bio_open_default(file, 'r', format);
    }
    if(bio is_eq 0)
    {
        goto end;
    }
    if(format is_eq FORMAT_ASN1)
    {
        pkey = pass is_eq 0 ? d2i_PrivateKey_bio(bio, 0) : d2i_PKCS8PrivateKey_bio(bio, 0, password_callback, &cb_data);
    }
    else if(format is_eq FORMAT_PEM)
    {
        pkey = PEM_read_bio_PrivateKey(bio, 0, password_callback, &cb_data);
    }
    else if(format is_eq FORMAT_PKCS12)
    {
        if(0 is_eq load_pkcs12(bio, desc, password_callback, &cb_data, &pkey, 0, 0))
        {
            goto end;
        }
    }
#if not defined(OPENSSL_NO_RSA) and not defined(OPENSSL_NO_DSA) and not defined(OPENSSL_NO_RC4)
    else if(format is_eq FORMAT_MSBLOB)
        pkey = b2i_PrivateKey_bio(bio);
    else if(format is_eq FORMAT_PVK)
        pkey = b2i_PVK_bio(bio, password_callback, &cb_data);
#endif
    else
    {
        LOG(FL_ERR, "bad input format specified for key");
    }
end:
    BIO_free(bio);
    if(pkey is_eq 0 and desc not_eq 0)
    {
        LOG(FL_ERR, "unable to load %s from %s", desc, file);
        (void)ERR_print_errors(bio_err);
    }
    return pkey;
}


/** load a key from file with format retry and optional password or from engine */
EVP_PKEY* FILES_load_key_autofmt(OPTIONAL const char* file, file_format_t file_format, bool maybe_stdin,
                                 OPTIONAL const char* source, OPTIONAL const char* engine, OPTIONAL const char* desc)
{
    EVP_PKEY* pkey = 0;

    char* pass = FILES_get_pass(source, desc);
    if(engine not_eq 0)
    {
        if(file not_eq 0 and strncasecmp(file, sec_ENGINE_STR, strlen(sec_ENGINE_STR)) is_eq 0)
        {
            file += strlen(sec_ENGINE_STR);
        }
        file_format = FORMAT_ENGINE;
    }

    int retries = 0;

    ERR_set_mark();
    do
    {
        pkey = FILES_load_key(file, file_format, maybe_stdin, pass, engine, 0 /* desc */);

        if(pkey is_eq 0)
        {
            file_format = next_format(file_format, UTIL_file_ext(file));
            if((++retries < MAX_FORMAT_RETRIES) and (file_format not_eq FORMAT_UNDEF))
            {
                continue;
            }
        }
        break;
    } while(1);
    if(pkey is_eq 0)
    {
        ERR_clear_last_mark();
        (void)ERR_print_errors(bio_err);
        LOG(FL_ERR, "unable to load %s from %s", desc not_eq 0 ? desc : "credentials",
            file_format is_eq FORMAT_ENGINE ? "engine" : file);
    }
    else
    {
        ERR_pop_to_mark();
    }
    UTIL_cleanse_free(pass);
    return pkey;
}


EVP_PKEY *FILES_load_pubkey(const char *file, file_format_t format,
                            OPTIONAL const char *pass, OPTIONAL const char *desc)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (file == NULL) {
        LOG(FL_ERR, "no input file specified for %s", desc != NULL ? desc : "public key");
        goto end;
    }
    LOG(FL_TRACE, "opening file '%s' for loading %s", file, desc != NULL ? desc : "public key");
    if ((bio = bio_open_default(file, 'r', format)) == NULL)
        goto end;
    if(format is_eq FORMAT_ASN1)
        pkey = d2i_PUBKEY_bio(bio, NULL);
    else if(format is_eq FORMAT_PEM)
        pkey = PEM_read_bio_PUBKEY(bio, NULL, password_callback, &cb_data);
    else
        LOG(FL_ERR, "unsupported input format specified for %s file %s",
            desc != NULL ? desc : "public key", file);
end:
    BIO_free(bio);
    if (pkey == NULL && desc != NULL) {
        LOG(FL_ERR, "unable to load %s from %s", desc, file);
        (void)ERR_print_errors(bio_err);
    }
    return pkey;
}

EVP_PKEY *FILES_load_pubkey_autofmt(const char *file, file_format_t format,
                                    OPTIONAL const char *source, OPTIONAL const char *desc)
{
    EVP_PKEY *pkey = NULL;
    int retries = 0;

    LOG(FL_TRACE, "loading %s from file '%s'", desc != NULL ? desc : "public key", file != NULL ? file : "<NULL>");

    char *pass = FILES_get_pass(source, desc);
    ERR_set_mark();
    do
    {
        pkey = FILES_load_pubkey(file, format, pass, NULL /* desc */);
        if (pkey == NULL) {
            format = next_format(format, UTIL_file_ext(file));
            if((++retries < 2) and (format not_eq FORMAT_UNDEF))
            {
                continue;
            }
        }
        break;
    } while (1);
    if(pkey is_eq 0)
    {
        ERR_clear_last_mark();
        (void)ERR_print_errors(bio_err);
        LOG(FL_ERR, "unable to load %s from file '%s'", desc != NULL ? desc : "public key",
            file != NULL ? file : "<NULL>");
    }
    else
    {
        ERR_pop_to_mark();
    }
    UTIL_cleanse_free(pass);
    return pkey;
}


X509_REQ* FILES_load_csr(const char* file, file_format_t format, OPTIONAL const char* desc)
{
    X509_REQ* req = 0;
    BIO* in;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L /* TODO really needed? */
    in = bio_open_default(file, 'r', format);
    if(in is_eq 0)
    {
        goto end;
    }
#else
    in = BIO_new(BIO_s_file());
    if(in is_eq 0)
    {
        goto end;
    }
    if(file is_eq 0)
    {
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    }
    else
    {
        if(BIO_read_filename(in, file) <= 0)
        {
            perror(file);
            goto end;
        }
    }
#endif

    if(format is_eq FORMAT_ASN1)
    {
        req = d2i_X509_REQ_bio(in, 0);
    }
    else if(format is_eq FORMAT_PEM)
    {
        req = PEM_read_bio_X509_REQ(in, 0, 0, 0);
    }
    else
    {
        LOG(FL_ERR, "unsupported format (%d) for loading %s", format, desc not_eq 0 ? desc : file);
    }

end:
    if(req is_eq 0 and desc not_eq 0)
    {
        LOG(FL_ERR, "unable to load %s", desc);
    }
    BIO_free(in);
    return req;
}


X509_REQ* FILES_load_csr_autofmt(const char* file, file_format_t format, OPTIONAL const char* desc)
{
    X509_REQ* csr = 0;
    int retries = 0;

    LOG(FL_TRACE, "loading %s from file '%s'", desc not_eq 0 ? desc : "CSR", file != NULL ? file : "<NULL>");

    ERR_set_mark();
    do
    {
        csr = FILES_load_csr(file, format, 0 /* desc */);

        if(csr is_eq 0)
        {
            format = next_format(format, UTIL_file_ext(file));
            if((++retries < 2) and (format not_eq FORMAT_UNDEF))
            {
                continue;
            }
        }
        break;
    } while(1);
    if(csr is_eq 0)
    {
        ERR_clear_last_mark();
        (void)ERR_print_errors(bio_err);
        LOG(FL_ERR, "unable to load %s from file '%s'", desc not_eq 0 ? desc : "CSR",
            file != NULL ? file : "<NULL>");
    }
    else
    {
        ERR_pop_to_mark();
    }
    return csr;
}


static bool
store_key(const EVP_PKEY* pkey, const char* file, file_format_t format,
          char mode, OPTIONAL const char* source, OPTIONAL const char* desc)
{
    BIO* bio = 0;
    PW_CB_DATA cb_data;
    char* pass = FILES_get_pass(source, desc);
    bool result = false;

    LOG(FL_INFO, "storing private key in file '%s'", file);
    if(format is_eq FORMAT_PKCS12 and mode == 'w')
    {
        result = FILES_store_pkcs12(pkey, 0, 0, file, pass, desc);
        goto end;
    }
    if(format not_eq FORMAT_PEM and format not_eq FORMAT_ASN1)
    {
        LOG(FL_ERR, "unsupported format (%d) or mode '%c' for storing %s",
            format, mode, desc not_eq 0 ? desc : file);
        goto end;;
    }

    cb_data.password = pass;
    cb_data.prompt_info = file;

    /* create bio and connect it with the file */
    if((bio = bio_open_default(file, mode, format)) is_eq 0)
    {
        goto end;
    }

    /* Write the private key to file */
    const EVP_CIPHER* enc = pass is_eq 0 ? 0 : EVP_aes_256_cbc();
    if(format is_eq FORMAT_ASN1)
    {
        result = pass is_eq 0 ? i2d_PrivateKey_bio(bio, (EVP_PKEY*)pkey)
                              : i2d_PKCS8PrivateKey_bio(bio, (EVP_PKEY*)pkey, enc, 0, 0, password_callback, &cb_data);
    }
    else if(format is_eq FORMAT_PEM)
    {
        result = PEM_write_bio_PrivateKey(bio, (EVP_PKEY*)pkey, enc, 0, 0, password_callback, &cb_data);
    }
    if(0 is_eq result)
    {
        if(desc not_eq 0)
        {
            LOG(FL_ERR, "failed to write %s", desc);
        }
        goto end;
    }
#ifdef SEC_WRITE_PUBKEY /* TODO keep? */
    PEM_write_bio_PUBKEY(bio, (EVP_PKEY*)pkey);
#endif
    result = true;

 end:
    UTIL_cleanse_free(pass);
    BIO_free(bio);
    return result;
}

bool FILES_store_key(const EVP_PKEY* pkey, const char* file, file_format_t format,
                     OPTIONAL const char* source, OPTIONAL const char* desc)
{
    return store_key(pkey, file, format, 'w', source, desc);
}

/*******************************************************
 * store private key, cert, and (extra) certs, as far as present, in pkcs12
 *******************************************************/
bool FILES_store_pkcs12(OPTIONAL const EVP_PKEY* pkey, OPTIONAL const X509* cert, OPTIONAL const STACK_OF(X509) * certs,
                        const char* file, OPTIONAL const char* pass, OPTIONAL const char* desc)
{
    bool result = false;
    PKCS12* p12 = 0;
    FILE* fp = 0;

    if(0 is_eq file)
    {
        LOG_err("null pointer file argument");
        return false;
    }
    const int n = certs not_eq 0 ? sk_X509_num(certs) : 0;
    LOG(FL_INFO, "storing %s private key, %s primary cert, and %d extra cert%s in file '%s'", pkey is_eq 0 ? "no" : "a",
        cert is_eq 0 ? "no" : "a", n, n is_eq 1 ? "" : "s", file);

    /*create the pkcs12 structure and fill it in */
    p12 = PKCS12_create((char*)(pass not_eq 0 ? pass : ""), /* access password */
                        (char*)desc,               /* cert friendly name */
                        (EVP_PKEY*)pkey,           /* the private key for the certificate */
                        (X509*)cert,               /* primary certificate */
                        (STACK_OF(X509)*)certs,    /* stack of (extra) certs */
                        NID_aes_256_cbc,           /* int nid_key = AES-256 CBC */
                                                   /* NID_aes_256_gcm = AES-256 GCM is not supported by OpenSSL */
                        -1,                        /* int nid_cert (no encryption) */
                        PKCS12_DEFAULT_ITER,       /* int iter (default 2048) */
                        PKCS12_DEFAULT_ITER,       /* int mac_iter (default 2048 */
                        0                          /* int keytype (default no flag) */
    );
    if(p12 is_eq 0)
    {
        (void)ERR_print_errors(bio_err);
        if(desc not_eq 0)
        {
            LOG(FL_ERR, "cannot create PKCS12 structure for %s", desc);
        }
        goto end;
    }

    /* store the pkcs12 structure in file */
    if(0 is_eq(fp = fopen(file, "wb")))
    {
        if(desc not_eq 0)
        {
            LOG(FL_ERR, "cannot open file '%s' for writing %s", file, desc);
        }
        goto end;
    }
    if(i2d_PKCS12_fp(fp, p12) <= 0)
    {
        LOG(FL_ERR, "cannot write PKCS12 structure to file '%s'", file);
        goto end;
    }
    result = true;

end:
    if(0 is_eq result and desc not_eq 0)
    {
        LOG(FL_ERR, "cannot store %s in file '%s'", desc, file);
    }
    PKCS12_free(p12);
    if(fp not_eq 0)
    {
        fclose(fp);
    }
    return result;
}


/*!########################################################################## *
 * writes a stack of certificates or null in the given format to the given file
 * returns number of written certificates on success, < 0 on error
 * ########################################################################## */
int FILES_store_certs(OPTIONAL const STACK_OF(X509) * certs, const char* file, file_format_t format, OPTIONAL const char* desc)
{
    int n = sk_X509_num(certs);
    BIO* bio = 0;
    int i;
    X509* cert = 0;

    if (n < 0)
        n = 0;
    LOG(FL_INFO, "storing %d certificate%s%s%s in file '%s'", n, n is_eq 1 ? "" : "s",
        desc == 0 ? "" : " of ", desc == 0 ? "" : desc, file);
    if(format is_eq FORMAT_PKCS12)
    {
        return FILES_store_pkcs12(0, 0, certs, file, 0, desc);
    }

    if(format not_eq FORMAT_ASN1 and format not_eq FORMAT_PEM)
    {
        LOG(FL_ERR, "unsupported output format (%d) for %s", format, desc not_eq 0 ? desc : "certs");
        n = -1;
        goto err;
    }
    if(n > 1 and format is_eq FORMAT_ASN1)
    {
        LOG(FL_WARN, "jointly saving more than one certificate in DER format");
    }

    if((bio = bio_open_default(file, 'w', format)) is_eq 0)
    {
        LOG(FL_ERR, "cannot open file '%s' for writing %s", file, desc not_eq 0 ? desc : "certs");
        n = -1;
        goto err;
    }
    for(i = 0; i < n; i++)
    {
        cert = sk_X509_value(certs, i);
        if((format is_eq FORMAT_PEM and not PEM_write_bio_X509(bio, cert))
           or (format is_eq FORMAT_ASN1 and not i2d_X509_bio(bio, cert)))
        {
            LOG(FL_ERR, "cannot write %s certificates to file '%s'", desc, file);
            n = -1;
            goto err;
        }
    }

err:
    BIO_free(bio); /* may be null pointer */
    return n;
}


bool FILES_store_cert(const X509* cert, const char* file, file_format_t format, OPTIONAL const char* desc)
{
    STACK_OF(X509)* certs = sk_X509_new_reserve(0, 1);

    if(0 is_eq certs or 0 is_eq sk_X509_push(certs, (X509*)cert))
    {
        LOG(FL_ERR, "out of memory writing cert to file '%s'", file);
        return false;
    }
    bool res = FILES_store_certs(certs, file, format, desc) is_eq 1;
    sk_X509_free(certs);
    return res;
}

int FILES_store_crls(const STACK_OF(X509_CRL) * crls, const char* file, file_format_t format, OPTIONAL const char* desc)
{
    int n = sk_X509_CRL_num(crls);
    BIO* bio = 0;
    int i;
    X509_CRL* crl = 0;

    LOG(FL_INFO, "storing %d CRL%s%s%s in file '%s'", n < 0 ? 0: n, n is_eq 1 ? "" : "s",
        desc == 0 ? "" : " of ", desc == 0 ? "" : desc, file);
    if(format not_eq FORMAT_ASN1 and format not_eq FORMAT_PEM)
    {
        LOG(FL_ERR, "unsupported output format (%d) for %s", format, desc not_eq 0 ? desc : "CRLs");
        n = -1;
        goto err;
    }
    if(n > 1 and format is_eq FORMAT_ASN1)
    {
        LOG(FL_WARN, "saving more than one certificate in DER format");
    }

    if((bio = bio_open_default(file, 'w', format)) is_eq 0)
    {
        LOG(FL_ERR, "cannot open file '%s' for writing %s", file, desc not_eq 0 ? desc : "CRLs");
        n = -1;
        goto err;
    }
    for(i = 0; i < n; i++)
    {
        crl = sk_X509_CRL_value(crls, i);
        if((format is_eq FORMAT_PEM and not PEM_write_bio_X509_CRL(bio, crl))
           or (format is_eq FORMAT_ASN1 and not i2d_X509_CRL_bio(bio, crl)))
        {
            LOG(FL_ERR, "cannot write CRLs to file '%s'", file);
            n = -1;
            goto err;
        }
    }

err:
    BIO_free(bio); /* may be null pointer */
    return n;
}

bool FILES_store_crl(const X509_CRL* crl, const char* file, file_format_t format, OPTIONAL const char* desc)
{
    STACK_OF(X509_CRL)* crls = sk_X509_CRL_new_reserve(0, 1);

    if(0 is_eq crls or 0 is_eq sk_X509_CRL_push(crls, (X509_CRL*)crl))
    {
        LOG(FL_ERR, "out of memory writing cert to file '%s'", file);
        return false;
    }
    bool res = FILES_store_crls(crls, file, format, desc) is_eq 1;
    sk_X509_CRL_free(crls);
    return res;
}

/*******************************************************
 * store private key, cert, and chain, as far as present, in given file(s) and format
 *******************************************************/
bool FILES_store_credentials(OPTIONAL const EVP_PKEY* key, OPTIONAL const X509* cert, OPTIONAL STACK_OF(X509) * certs,
                             OPTIONAL const char* keyfile, OPTIONAL const char* file, file_format_t format,
                             OPTIONAL const char* source, OPTIONAL const char* desc)
{
    if(0 is_eq key and 0 is_eq cert and 0 is_eq certs)
    {
        LOG_err("no key, cert, and cert list to store");
        return false;
    }
    if(0 not_eq key and 0 is_eq keyfile)
    {
        LOG_err("null pointer keyfile argument");
        return false;
    }
    if((cert not_eq 0 or certs not_eq 0) and 0 is_eq file)
    {
        LOG_err("null pointer file argument");
        return false;
    }

    char mode = 'w';
    if(0 not_eq key and 0 not_eq keyfile and 0 is_eq strcmp(keyfile, file)) /* store to same file */
    {
        if(format is_eq FORMAT_PKCS12)
        {
            char *pass = FILES_get_pass(source, desc);
            bool result = FILES_store_pkcs12(key, cert, certs, file, pass, desc);
            UTIL_cleanse_free(pass);
            return result;
        }
        mode = 'a';
        if(format is_eq FORMAT_ASN1 and key not_eq 0 and
           (cert not_eq 0 or certs not_eq 0))
        {
            LOG(FL_WARN, "jointly saving certificate(s) and key in DER format");
        }
    }

    if(format is_eq FORMAT_PKCS12 and (cert not_eq 0 or certs not_eq 0))
    {
        char *pass = FILES_get_pass(source, desc);
        bool result = FILES_store_pkcs12(NULL, cert, certs, file, pass, desc);
        UTIL_cleanse_free(pass);
        if (not result)
        {
            return false;
        }
    }
    else
    {
        if(cert not_eq 0 and certs is_eq 0)
        {
            if(not FILES_store_cert(cert, file, format, desc))
            {
                return false;
            }
        }
        else
        {
            if(cert not_eq 0) /* here, certs not_eq 0 holds */
            {
                if(0 is_eq sk_X509_unshift(certs, (X509*)cert)) /* prepend cert */
                {
                    LOG(FL_ERR, "out of memory writing certs to file '%s'", file);
                    return false;
                }
            }
            if(FILES_store_certs(certs, file, format, desc) < 0)
            {
                return false;
            }
            if(cert not_eq 0)
            {
                (void)sk_X509_shift(certs); /* remove cert again from head */
            }
        }
    }
    return key is_eq 0 or store_key(key, keyfile, format, mode, source, desc);
}


/* Initialize or extend, if *crls not_eq 0, a CRL stack. */
static bool load_crls(const char* src, STACK_OF(X509_CRL) * *pcrls, file_format_t format, int timeout, OPTIONAL const char* desc)
{
    if(format is_eq FORMAT_HTTP)
    {
        X509_CRL* crl = CONN_load_crl_http(src, timeout, 0, desc);
        if(crl is_eq 0)
        {
            return false;
        }

        if(*pcrls is_eq 0)
        {
            *pcrls = sk_X509_CRL_new_reserve(0, 1);
        }
        if(0 is_eq *pcrls or 0 is_eq crl or 0 is_eq sk_X509_CRL_push(*pcrls, crl))
        {
            LOG(FL_ERR, "out of memory");
            return false;
        }
        return true;
    }
    return load_certs_crls(src, format, 0 /* pass */, desc, 0 /* pcerts */, pcrls);
}


static X509_CRL* load_crl(const char* file, file_format_t format)
{
    X509_CRL* crl = 0;
    BIO* in = bio_open_default(file, 'r', format);
    if(in is_eq 0)
        goto end;

    if(format is_eq FORMAT_ASN1)
    {
        crl = d2i_X509_CRL_bio(in, 0);
    }
    else if(format is_eq FORMAT_PEM)
    {
        crl = PEM_read_bio_X509_CRL(in, 0, 0, 0);
    }
    else
    {
        LOG(FL_ERR, "bad input format specified for input crl");
        goto end;
    }
    if(crl is_eq 0)
    {
        LOG(FL_ERR, "unable to load CRL");
        (void)ERR_print_errors(bio_err);
        goto end;
    }

 end:
    BIO_free(in);
    return crl;
}


/*
 * TODO: replace by OpenSSL function when available (in progress by DvO)
 */
X509_CRL* FILES_load_crl_autofmt(const char* src, file_format_t format,
                                 int timeout, const char* desc)
{
    X509_CRL* crl = 0;

    if(src is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }
    LOG(FL_TRACE, "loading %s from '%s'", desc not_eq 0 ? desc : "CRL", src);

    format = adjust_format(&src, format, false);
    if(format is_eq FORMAT_HTTP)
    {
        crl = CONN_load_crl_http(src, timeout, 0, desc);
    }
    else
    {
        crl = load_crl(src, format);
        if(crl is_eq 0)
        {
            ERR_clear_error();
            crl = load_crl(src, format is_eq FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
        }
    }

    if(crl is_eq 0)
    {
        (void)ERR_print_errors(bio_err);
        LOG(FL_ERR, "unable to load %s from file '%s'", desc not_eq 0 ? desc : "CRL", src);
    }
    return crl;
}

/*
 * TODO: replace by OpenSSL function when available (in progress by DvO)
 */
STACK_OF(X509_CRL) * FILES_load_crls_autofmt(const char* src, file_format_t format, int timeout, OPTIONAL const char* desc)
{
    STACK_OF(X509_CRL)* crls = 0;
    LOG(FL_TRACE, "loading %s from '%s'", desc not_eq 0 ? desc : "CRL", src);
    format = adjust_format(&src, format, false);
    if(format is_eq FORMAT_HTTP)
    {
        (void)load_crls(src, &crls, format, timeout, desc);
    }
    else
    {
         (void)ERR_set_mark(); /* remember any existing diagnostic info */
         (void)load_crls(src, &crls, format, timeout, 0 /* desc */);
         if(crls is_eq 0)
         {
             (void)ERR_pop_to_mark(); /* discard any new diagnostic info */
             (void)load_crls(src, &crls, format is_eq FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM, timeout, desc);
         }
         else
         {
             (void)ERR_clear_last_mark();
         }
         if(crls is_eq 0)
         {
             (void)ERR_print_errors(bio_err);
             LOG(FL_ERR, "unable to load %s from '%s'", desc not_eq 0 ? desc : "CRLs", src);
         }
    }
    return crls;
}


/*
 * TODO: replace by OpenSSL function when available (in progress by DvO)
 */
STACK_OF(X509_CRL) * FILES_load_crls_multi(const char* srcs, file_format_t format, int timeout, OPTIONAL const char* desc)
{
    if(srcs is_eq 0)
    {
        return 0;
    }

    X509_CRL* crl;
    STACK_OF(X509_CRL) * crls;
    STACK_OF(X509_CRL)* all_crls = 0;

    char* names = OPENSSL_strdup(srcs);
    if(names is_eq 0 or (all_crls = sk_X509_CRL_new_null()) is_eq 0)
    {
        goto oom;
    }

    char* src;
    char* next;
    for(src = names; src not_eq 0; src = next)
    {
        next = UTIL_next_item(src); /* must do this here to split string */

        crls = FILES_load_crls_autofmt(src, format, timeout, desc);
        if(crls is_eq 0)
            goto err;
        while(sk_X509_CRL_num(crls) > 0)
        {
            crl = sk_X509_CRL_shift(crls);
            if(0 is_eq sk_X509_CRL_push(all_crls, crl))
            {
                sk_X509_CRL_pop_free(crls, X509_CRL_free);
                goto oom;
            }
#if 0
            if(OSSL_CMP_expired(X509_CRL_get0_nextUpdate(crl), vpm))
            {
                /* well, should ignore expiration of base CRL if delta CRL is valid */
                char* issuer =
                    X509_NAME_oneline(X509_CRL_get_issuer(crl), 0, 0);
                LOG(FL_ERR, "CRL from '%s' issued by '%s' has expired",
                           src, issuer);
                OPENSSL_free(issuer);
#if 0
                sk_X509_CRL_pop_free(crls, X509_CRL_free);
                goto err;
#endif
            }
#endif
        }
        sk_X509_CRL_free(crls);
        src = next;
    }
    OPENSSL_free(names);
    return all_crls;

oom:
    LOG(FL_ERR, "out of memory");
err:
    sk_X509_CRL_pop_free(all_crls, X509_CRL_free);
    OPENSSL_free(names);
    return 0;
}

/*! Checks whether the given path points to an existing directory
 *
 * @param path c-string specifying the path
 *
 * @returns \c true if the specified path points to a directory
 *
 * @par Errors
 * The function sets the system \c errno and returns \c false:
 *   - In case of a system call failure, \c errno is set appropriately.
 *   - Sets \c errno to \c EINVAL if \p path is a \c NULL pointer.
 *   - Sets \c errno to \c ENOTDIR, if the object the path points to exists but is not a directory.
 *     note: \c ENOTDIR also results if any component of the path prefix of path is not a directory.
 *
 * @par Thread safety
 * The function is thread-safe as long as there are no race conditions on the path object itself,
 * in which case the return value of this function is undefined.
 * (For example, an existing directory may get removed within the function call by another thread or process.)
 *
 * @par Permission requirements
 * Uses the stat() function internally. Citation from man stat(2):
 * No permissions are required on the directory itself, but execute (search) permission
 * is required on all of the directories in \p path that lead to the directory.
 *
 * @sa https://man7.org/linux/man-pages/man2/stat.2.html
 */
static bool check_path_available(const char *path)
{

    if (0 is_eq path)
    {
        errno = EINVAL;
        return false;
    }

    struct stat f_stat;
    if (0 is_eq stat(path, &f_stat))
    {
        if (S_ISDIR(f_stat.st_mode))
        {
            return true;
        }

        errno = ENOTDIR;
    }

    return false;
}

char *FILES_get_dir(const char* base_ev, const char* base_default, const char *add_path)
{
    const char *result = getenv(base_ev);

    if (0 is_eq result)
    {
        LOG(FL_DEBUG, "Can't find environment variable '%s'. Implicit base directory will be used", base_ev);
        result = base_default;
    }

    // concatenated_path must stay in the function global scope (-> result)
    char concatenated_path[UTIL_max_path_len];
    if (0 not_eq add_path)
    {
        const int length_needed = snprintf(concatenated_path, sizeof(concatenated_path), "%s/%s", result, add_path);
        if (length_needed < 0 || (unsigned)length_needed >= sizeof(concatenated_path))
        {
            // -1 for '\0'
            LOG(FL_ERR, "Path exceeded maximal allowed length: %i, '%s/%s'; or a path concatenation error occurred.", sizeof(concatenated_path) - 1, result, add_path);
            result = 0;
        }
        else
        {
            result = concatenated_path;
        }
    }

    if (not check_path_available(result))
    {
        LOG_system_debug(errno);
        LOG(FL_ERR, "Directory check failure: '%s'", (0 not_eq result) ? result : "<NULL>");
        result = 0;
    }

    return (0 not_eq result) ? strdup(result) : 0;
}
