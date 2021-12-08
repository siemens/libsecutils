/** 
* @file util.c
* 
* @brief Various utility functions
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

#include <dirent.h>
#include <sys/stat.h>

#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <util/log.h>

#include <operators.h>

int UTIL_atoint(const char* str)
{
    char* tailptr = 0;
    long res = strtol(str, &tailptr, 10);
    if((*tailptr not_eq '\0') or (res < INT_MIN) or (res > INT_MAX))
    {
        return INT_MIN;
    }
    else
    {
        return (int)res;
    }
}

const char* UTIL_skip_string(const char* s, OPTIONAL const char* p)
{
    const int len_s = strlen(s);
    if(p not_eq 0 and 0 is_eq strncmp(p, s, len_s))
    {
        p += len_s;
    }
    return p;
}


char* UTIL_next_item(char* str)
{
    /* advance to separator (comma or whitespace), if any */
    while(*str not_eq ',' and not isspace(*str) and *str not_eq '\0')
    {
        if(*str is_eq '\\' and str[1] not_eq '\0')
        {
            /* skip and unescape '\' escaped char */
            memmove(str, str + 1, strlen(str));
        }
        str++;
    }
    if(*str not_eq '\0')
    {
        /* terminate current item */
        *str++ = '\0';
        /* skip over any whitespace after separator */
        while(isspace(*str))
        {
            str++;
        }
    }
    return *str is_eq '\0' ? 0 : str;
}


const char* UTIL_file_ext(OPTIONAL const char* filename)
{
    const char* ext = 0;
    const char* next = filename;
    if(filename not_eq 0)
    {
        do
        {
            ext = next;
            next = strchr(next, '.');
            if(next not_eq 0)
            {
                next++;
            }
        } while(next);
    }
    return ext;
}


void* UTIL_read_file(const char* filename, int* lenp)
{
    FILE* fp = 0;
    struct stat st;
    unsigned char* contents = 0;
    int contents_len = 0;

    if(stat(filename, &st) < 0)
    {
        LOG(FL_ERR, "Could not determine size of file %s", filename);
        return 0;
    }

    fp = fopen(filename, "rb");
    if(fp is_eq 0)
    {
        LOG(FL_ERR, "Could not open file %s", filename);
        return 0;
    }

    contents_len = st.st_size;
    contents = OPENSSL_malloc(contents_len + 1);
    if(contents is_eq 0)
    {
        LOG_err("Out of memory");
        goto end;
    }

    if(fread(contents, sizeof(*contents), contents_len, fp) not_eq contents_len)
    {
        LOG_err("Could not read file contents");
        OPENSSL_free(contents);
        contents = 0;
        goto end;
    }
    contents[contents_len] = '\0'; /*!< just in case used as char string */
end:
    if(fclose(fp) not_eq 0)
    {
        LOG(FL_ERR, "Closing file failed. Error: %s", strerror(errno));
        OPENSSL_free(contents);
        contents = 0;
        contents_len = 0;
    }
    if(0 not_eq lenp)
    {
        *lenp = contents_len;
    }
    return contents;
}


bool UTIL_write_file(const char* filename, const void* data, size_t len)
{
    FILE* fp = 0;

    fp = fopen(filename, "wb");
    if(fp is_eq 0)
    {
        LOG(FL_ERR, "Could not open file %s", filename);
        return false;
    }

    size_t written = fwrite(data, sizeof(char), len, fp);
    if(written not_eq len)
    {
        LOG(FL_ERR, "Could not write to file %s. Supposed to write %zu but wrote %zu", filename, len, written);
        fclose(fp);
        return false;
    }

    if(fclose(fp) not_eq 0)
    {
        LOG(FL_ERR, "Closing file failed. Error: %s", strerror(errno));
        return false;
    }

    return true;
}


bool UTIL_iterate_dir(bool (*fn)(const char* file, void* arg), void* arg, const char* path, bool recursive)
{
    bool res = false;

    if(0 is_eq fn or 0 is_eq path)
    {
        LOG(FL_ERR, "null pointer argument");
        return false;
    }

    DIR* p_dir = opendir(path);
    if(0 == p_dir)
    {
        LOG(FL_ERR, "cannot open directory '%s'", path);
        return false;
    }

    struct dirent* p_dirent = readdir(p_dir);
    while(0 not_eq p_dirent)
    {
        char full_path[UTIL_max_path_len];
        /* constant 2 takes into account end of string and format string content */
        snprintf(full_path, sizeof(full_path), "%.*s/%.*s", UTIL_max_path_len - UTIL_max_name_len - 2, path,
                 UTIL_max_name_len, p_dirent->d_name);

        struct stat f_stat;
        memset(&f_stat, 0x00, sizeof(f_stat));
        if(-1 is_eq stat(full_path, &f_stat))
        {
            LOG(FL_INFO, "cannot read status of %s - %s", full_path, strerror(errno));
        }
        else
        {
            if(f_stat.st_mode bitand S_IFREG)
            {
                if(not(*fn)(full_path, arg))
                {
                    goto err;
                }
            }
            else if(recursive and (f_stat.st_mode bitand S_IFDIR) and (0 not_eq strncmp(p_dirent->d_name, ".", 1)))
            {
                if(not UTIL_iterate_dir(fn, arg, full_path, recursive))
                {
                    goto err;
                }
            }
        }
        p_dirent = readdir(p_dir);
    }
    res = true;

err:
    closedir(p_dir);
    return res;
}


/*
 * dn is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
/* adapted from OpenSSL:apps/lib/apps.c */
X509_NAME* UTIL_parse_name(const char* dn, long chtype, bool multirdn)
{
    size_t buflen = strlen(dn) + 1; /* to copy the types and values.
                                     * Due to escaping, the copy can only become shorter */
    char* buf = OPENSSL_malloc(buflen);
    size_t max_ne = buflen / (1 + 1) + 1; /* maximum number of name elements */
    const char** ne_types = OPENSSL_malloc(max_ne * sizeof(char*));
    char** ne_values = OPENSSL_malloc(max_ne * sizeof(char*));
    int* mval = OPENSSL_malloc(max_ne * sizeof(int));

    const char* sp = dn;
    char* bp = buf;
    int i, ne_num = 0;

    X509_NAME* n = 0;
    int nid;

    if(0 is_eq buf or 0 is_eq ne_types or 0 is_eq ne_values or 0 is_eq mval)
    {
        LOG_err("Malloc error");
        goto error;
    }

    /* no multivalued RDN by default */
    mval[ne_num] = 0;

    if(*sp++ not_eq '/')
    { /* skip leading '/' */
        LOG(FL_ERR, "DN '%s' does not start with '/'.", dn);
        goto error;
    }

    while(*sp not_eq '\0')
    {
        /* collect type */
        ne_types[ne_num] = bp;
        /* parse element name */
        while(*sp not_eq '=')
        {
            if(*sp is_eq '\\')
            { /* is there anything to escape in the * type...? */
                if(*++sp not_eq '\0')
                {
                    *bp++ = *sp++;
                }
                else
                {
                    LOG(FL_ERR, "Escape character at end of DN '%s'", dn);
                    goto error;
                }
            }
            else if(*sp is_eq '\0')
            {
                LOG(FL_ERR, "End of string encountered while processing type of DN '%s' element #%d", dn, ne_num);
                goto error;
            }
            else
            {
                *bp++ = *sp++;
            }
        }
        sp++;
        *bp++ = '\0';
        /* parse element value */
        ne_values[ne_num] = bp;
        while(*sp not_eq '\0')
        {
            if(*sp is_eq '\\')
            {
                if(*++sp not_eq '\0')
                {
                    *bp++ = *sp++;
                }
                else
                {
                    LOG(FL_ERR, "Escape character at end of DN '%s'", dn);
                    goto error;
                }
            }
            else if(*sp is_eq '/')
            { /* start of next element */
                sp++;
                /* no multivalued RDN by default */
                mval[ne_num + 1] = 0;
                break;
            }
            else if(*sp is_eq '+' and multirdn)
            {
                /* a not escaped + signals a multi-valued RDN */
                sp++;
                mval[ne_num + 1] = -1;
                break;
            }
            else
            {
                *bp++ = *sp++;
            }
        }
        *bp++ = '\0';
        ne_num++;
    }

    if(0 is_eq(n = X509_NAME_new()))
    {
        goto error;
    }

    for(i = 0; i < ne_num; i++)
    {
        if((nid = OBJ_txt2nid(ne_types[i])) is_eq NID_undef)
        {
            LOG(FL_WARN, "DN '%s' attribute %s has no known NID, skipped", dn, ne_types[i]);
            continue;
        }

        if(0 is_eq * ne_values[i])
        {
            LOG(FL_WARN, "No value provided for DN '%s' attribute %s, skipped", dn, ne_types[i]);
            continue;
        }

        if(0 is_eq X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char*)ne_values[i], -1, -1, mval[i]))
        {
            ERR_print_errors(bio_err);
            LOG(FL_ERR, "Error adding name attribute '/%s=%s'", ne_types[i], ne_values[i]);
            X509_NAME_free(n);
            n = 0;
            goto error;
        }
    }

error:
    OPENSSL_free(ne_values);
    OPENSSL_free(ne_types);
    OPENSSL_free(mval);
    OPENSSL_free(buf);
    return n;
}


void UTIL_erase_mem(void* dst, size_t len)
{
    if(dst not_eq 0)
    {
        OPENSSL_cleanse(dst, len);
    }
}


void UTIL_cleanse(char* str)
{
    if(str not_eq 0)
    {
        UTIL_erase_mem((void*)str, strlen(str));
    }
}


void UTIL_cleanse_free(OPTIONAL char* str)
{
    UTIL_cleanse(str);
    OPENSSL_free(str);
}

bool UTIL_get_random(void* buf, size_t len)
{
    return RAND_bytes(buf, len) > 0;
}


void UTIL_setup_openssl(long version, OPTIONAL const char* build_name)
{
    if (build_name == NULL)
        build_name = UTIL_SECUTILS_NAME;
#if OPENSSL_VERSION_NUMBER < OPENSSL_V_1_0_2
#error Must not use OpenSSL versions older than 1.0.2. They are unsupported and insecure.
#endif
    if(OpenSSL_version_num() < OPENSSL_V_1_0_2)
    {
        LOG(FL_FATAL, "OpenSSL version 0x%lx is too old for %s. Must be at least 0x10002000L", OpenSSL_version_num(), build_name);
        exit(EXIT_FAILURE);
    }
#define MAJOR_MINOR_MASK 0xfff00000L
    if((MAJOR_MINOR_MASK bitand OpenSSL_version_num()) not_eq (MAJOR_MINOR_MASK bitand version))
    {
        LOG(FL_FATAL, "OpenSSL runtime version 0x%lx does not match version 0x%lx used for compiling %s",
            OpenSSL_version_num(), version, build_name);
        exit(EXIT_FAILURE);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100003L
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#else
    if(0 is_eq OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN
#ifdef PRELOAD_DEFAULT_DYNAMIC_ENGINES
                                       bitor OPENSSL_INIT_LOAD_CONFIG
#endif
                                   ,
                                   0))
    {
        LOG(FL_FATAL, "failed to initialize OpenSSL library for use in %s", build_name);
        exit(EXIT_FAILURE);
    }
#endif
#ifndef OPENSSL_NO_UI
/* setup_ui_method */
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x10101000L
int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b)
{
    int day, sec;

    if (!ASN1_TIME_diff(&day, &sec, a, b))
        return -2;
    if (day > 0 || sec > 0)
        return 1;
    if (day < 0 || sec < 0)
        return -1;
    return 0;
}
#endif

/* adatped from OpenSSL:crypto/x509/t_crl.c */
void UTIL_print_crl(OPTIONAL BIO* bio, OPTIONAL const X509_CRL* crl)
{
    unsigned long flags =
        ASN1_STRFLGS_RFC2253 bitor ASN1_STRFLGS_ESC_QUOTE bitor XN_FLAG_SEP_CPLUS_SPC bitor XN_FLAG_FN_SN;

    if(bio is_eq 0)
    {
        return;
    }
    if(crl not_eq 0)
    {
        BIO_printf(bio, "    Certificate Revocation List (CRL):\n");
#if 0
        long ver = X509_CRL_get_version(crl);
        if(ver >= 0 and ver <= 1)
        {
            BIO_printf(bio, "%8sVersion %ld (0x%lx)\n", "", ver + 1, (unsigned long)ver);
        }
        else
        {
            BIO_printf(bio, "%8sVersion unknown (%ld)\n", "", ver);
        }
        const X509_ALGOR* sig_alg;
        const ASN1_BIT_STRING* sig;
        X509_CRL_get0_signature(crl, &sig, &sig_alg);
        BIO_puts(bio, "    ");
        X509_signature_print(bio, sig_alg, NULL);
#endif
        BIO_printf(bio, "%8sIssuer: ", "");
        X509_NAME_print_ex(bio, X509_CRL_get_issuer(crl), 0, flags);
        BIO_puts(bio, "\n");
        BIO_printf(bio, "%8sLast Update: ", "");
        ASN1_TIME_print(bio, X509_CRL_get0_lastUpdate(crl));
        BIO_printf(bio, "\n%8sNext Update: ", "");
        if (X509_CRL_get0_nextUpdate(crl))
        {
            ASN1_TIME_print(bio, X509_CRL_get0_nextUpdate(crl));
        }
        else
        {
            BIO_printf(bio, "NONE");
        }
        BIO_printf(bio, "\n");

#if 0
        X509V3_extensions_print(bio, "CRL extensions",
                                X509_CRL_get0_extensions(crl), 0, 8);
#endif

        STACK_OF(X509_REVOKED) * rev = X509_CRL_get_REVOKED((X509_CRL*) crl);
        BIO_printf(bio, "    Number of revoked Certificates: %d\n",
                   rev is_eq 0 ? 0 : sk_X509_REVOKED_num(rev));

#if 0
        int i;
        for(i = 0; i < sk_X509_REVOKED_num(rev); i++)
        {
            X509_REVOKED* r = sk_X509_REVOKED_value(rev, i);
            BIO_printf(bio, "    Serial Number: ");
            i2a_ASN1_INTEGER(bio, X509_REVOKED_get0_serialNumber(r));
            BIO_printf(bio, "\n        Revocation Date: ");
            ASN1_TIME_print(bio, X509_REVOKED_get0_revocationDate(r));
            BIO_printf(bio, "\n");
            X509V3_extensions_print(bio, "CRL entry extensions",
                                    X509_REVOKED_get0_extensions(r), 0, 8);
        }
        X509_signature_print(bio, sig_alg, sig);
#endif
    }
    else
    {
        BIO_printf(bio, "    (no CRL)\n");
    }
    BIO_flush(bio);
}

void UTIL_print_cert(OPTIONAL BIO* bio, OPTIONAL const X509* cert, unsigned long neg_cflags)
{
    if(bio is_eq 0)
    {
        return;
    }
    if(cert not_eq 0)
    {
        unsigned long flags =
            ASN1_STRFLGS_RFC2253 bitor ASN1_STRFLGS_ESC_QUOTE bitor XN_FLAG_SEP_CPLUS_SPC bitor XN_FLAG_FN_SN;
        BIO_printf(bio, "    Certificate\n");
        X509_print_ex(bio, (X509*)cert, flags, compl X509_FLAG_NO_SUBJECT);
        if(X509_check_issued((X509*)cert, (X509*)cert) is_eq X509_V_OK)
        {
            BIO_printf(bio, "        self-signed\n");
        }
        else
        {
            BIO_printf(bio, " ");
            X509_print_ex(bio, (X509*)cert, flags, compl X509_FLAG_NO_ISSUER);
        }
        X509_print_ex(bio, (X509*)cert, flags, compl(X509_FLAG_NO_SERIAL bitor X509_FLAG_NO_VALIDITY));
        if(X509_cmp_current_time(X509_get0_notBefore(cert)) > 0)
        {
            BIO_printf(bio, "        not yet valid\n");
        }
        if(X509_cmp_current_time(X509_get0_notAfter(cert)) < 0)
        {
            BIO_printf(bio, "        no more valid\n");
        }
        X509_print_ex(bio, (X509*)cert, flags, compl(neg_cflags));
    }
    else
    {
        BIO_printf(bio, "    (no certificate)\n");
    }
    BIO_flush(bio);
}


void UTIL_print_certs(OPTIONAL BIO* bio, OPTIONAL const STACK_OF(X509) * certs)
{
    if(bio is_eq 0)
    {
        return;
    }
    if(certs and sk_X509_num(certs) > 0)
    {
        int i = 0;
        for(i = 0; i < sk_X509_num(certs); i++)
        {
            X509* cert = sk_X509_value(certs, i);
            if(cert not_eq 0)
            {
                UTIL_print_cert(bio, cert, 0);
            }
        }
    }
    else
    {
        BIO_printf(bio, "    (no certificates)\n");
        BIO_flush(bio);
    }
}

/* This is similar to LOG_cert() from ../certstatus/certstatus.c */
static void warn_cert_msg(const char *uri, X509 *cert, const char *msg)
{
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

    if (cert == NULL)
        LOG_err("null pointer uri argument");
    if (cert == NULL)
        LOG_err("null pointer msg argument");
    LOG(FL_WARN, "Certificate from '%s' with subject '%s' %s\n", uri, subj, msg);
    OPENSSL_free(subj);
}

bool UTIL_warn_cert(const char *uri, OPTIONAL X509 *cert, bool warn_EE,
                    OPTIONAL X509_VERIFY_PARAM *vpm)
{
    if (cert == NULL)
        return true;
    uint32_t ex_flags = X509_get_extension_flags(cert);
    int res = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    res = X509_cmp_timeframe(vpm, X509_get0_notBefore(cert),
                             X509_get0_notAfter(cert));
#endif
    bool ret = res != 0;
    if (!ret)
        warn_cert_msg(uri, cert, res > 0 ? "has expired" : "not yet valid");
    if (warn_EE && (ex_flags & EXFLAG_V1) == 0 && (ex_flags & EXFLAG_CA) == 0) {
        warn_cert_msg(uri, cert, "is not a CA cert");
        ret = false;
    }
    return ret;
}

bool UTIL_warn_certs(const char *uri, OPTIONAL STACK_OF(X509) *certs, bool warn_EE,
                     OPTIONAL X509_VERIFY_PARAM *vpm)
{
    int i;
    bool ret = true;

    for (i = 0; i < sk_X509_num(certs /* may be NULL */); i++)
        ret = ret && UTIL_warn_cert(uri, sk_X509_value(certs, i), warn_EE, vpm);
    return ret;
}


/** get a copy of all certificates in a store */
STACK_OF(X509) * X509_STORE_get_certs(X509_STORE* store)
{ /* TODO remove when available in library */
    int i = 0;
    STACK_OF(X509) * sk;
    STACK_OF(X509_OBJECT) * objs;

    if(0 is_eq store)
    {
        return 0;
    }
    if(0 is_eq(sk = sk_X509_new_null()))
    {
        return 0;
    }
    objs = X509_STORE_get0_objects(store);
    for(i = 0; i < sk_X509_OBJECT_num(objs); i++)
    {
        X509* cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
        if(cert not_eq 0)
        {
            X509_up_ref(cert);
            if(0 is_eq sk_X509_push(sk, cert))
            {
                X509_free(cert);
                sk_X509_pop_free(sk, X509_free);
                return 0;
            }
        }
    }
    return sk;
}


void UTIL_print_store_certs(OPTIONAL BIO* bio, OPTIONAL const X509_STORE* store)
{
    if(bio is_eq 0)
    {
        return;
    }
    if(store not_eq 0)
    {
        STACK_OF(X509)* certs = X509_STORE_get_certs((X509_STORE*)store);
        UTIL_print_certs(bio, certs);
        sk_X509_pop_free(certs, X509_free);
    }
    else
    {
        BIO_printf(bio, "    (no certificate store)\n");
        BIO_flush(bio);
    }
}

int UTIL_store_certs_num(const X509_STORE* store)
{
    if(store is_eq 0)
    {
        return 0;
    }

    int result = 0;
    STACK_OF(X509)* certs = X509_STORE_get_certs((X509_STORE*)store);
    if(certs)
    {
        result = sk_X509_num(certs);
        sk_X509_pop_free(certs, X509_free);
    }

    return result;
}


/* start of definitions borrowed from OpenSSL:crypto/cmp/cmp_lib.c */
static int X509_cmp_from_ptrs(const struct x509_st* const* a, const struct x509_st* const* b)
{
    return X509_cmp(*a, *b);
}

bool UTIL_sk_X509_add1_cert(STACK_OF(X509) * sk, X509* cert, bool no_duplicate)
{
    if(no_duplicate)
    {
        sk_X509_set_cmp_func(sk, &X509_cmp_from_ptrs);
        if(sk_X509_find(sk, cert) >= 0)
        {
            return 1;
        }
    }
    if(0 is_eq sk_X509_push(sk, cert))
    {
        return 0;
    }
    return X509_up_ref(cert);
}

int UTIL_sk_X509_add1_certs(STACK_OF(X509) * sk, OPTIONAL const STACK_OF(X509) * certs, int no_self_signed,
                            int no_duplicates)
{
    int i = 0;

    if(sk is_eq 0)
    {
        return 0;
    }

    if(certs is_eq 0)
    {
        return 1;
    }
    const int n = sk_X509_num(certs);
    for(i = 0; i < n; i++)
    {
        X509* cert = sk_X509_value(certs, i);
        if((not no_self_signed or X509_check_issued(cert, cert) not_eq X509_V_OK)
           and (not UTIL_sk_X509_add1_cert(sk, cert, no_duplicates)))
        {
            return 0;
        }
    }
    return 1;
}
/* end of definitions borrowed from OpenSSL:crypto/cmp/cmp_lib.c */


/* Copy a NUL-terminated string from the given source
 * into an optional destination buffer, or calculate how large it needs to be.
 * Copy at most destination_len bytes including the terminating NUL.
 */
size_t UTIL_safe_string_copy(const char *source, OPTIONAL char *destination,
                             size_t destination_len, OPTIONAL size_t *size_needed)
{
    if (source == NULL) {
        return 0;
    }
    if (destination != NULL && destination_len == 0) {
        /* buffer size too small, not even the terminating NUL can be written */
        return 0;
    }

    if (destination == NULL && size_needed == NULL) {
        /* neither buffer nor size output given, nothing to do */
        return 0;
    }

    if (destination != NULL) {
        /* reserve one byte for the terminating NUL, destination_len is assured > 0 above */
        --destination_len;
    }

    size_t i, needed;  /* index into target buffer and record the size needed */
    for (i=0,needed=0; source[needed] != 0; /* inc needed before loop body */) {
        ++needed;
        if (destination != NULL && destination_len >= needed) {
            destination[i] = source[i];
            ++i;
        }
    }

    /* terminating NUL */
    ++needed;
    if (destination != NULL) {
        destination[i] = '\0';
    }

    if (size_needed != NULL) {
        *size_needed = needed;
    }

    return i;
}

/* implementation of the function url_encode */
size_t UTIL_url_encode(
    const char  *source,
    char        *destination,
    size_t      destination_len,
    size_t      *size_needed)
{
    /* characters that are not reserved and may be taken literally */
    static const int unreserved[] = {
        /* A B C D E F G H I J K L M N O P Q R S T U V W X Y Z      */
        /* a b c d e f g h i j k l m n o p q r s t u v w x y z      */
        /* 0 1 2 3 4 5 6 7 8 9 - _ . ~                              */
        /*                                                          */
        /*         00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  */
        /* 00 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 10 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 20 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
        /* 30 */   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        /* 40 */   0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        /* 50 */   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
        /* 60 */   0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        /* 70 */   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
        /* 80 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    static const char hex[] = "0123456789ABCDEF";

    if (destination != NULL && destination_len == 0) {
        /* buffer size too small, not even the terminating NUL can be written */
        return 0;
    }

    if (destination == NULL && size_needed == NULL) {
        /* neither buffer nor size output given, nothing to do */
        return 0;
    }

    if (destination) {
        /* if output buffer given reserve one byte for the terminating NUL */
        --destination_len;
    }

    size_t is,id; /* counter for source and dest */
    size_t needed = 0; /* record the size needed */

    for (is=0,id=0; source[is]!=0; ++is) {
        if (unreserved[(int)source[is]]) {
            /* character is part of the unreserved ones */
            ++needed;
            if (destination && destination_len >= needed) {
                destination[id++] = source[is];
            }
        }
        else {
            needed += 3;
            if (destination && destination_len >= needed) {
                /* at least 3 bytes for %XX are needed this guaranties that there are no invalid % escapes */
                destination[id++] = '%';
                destination[id++] = hex[ (source[is]>>4) & 0xF ];
                destination[id++] = hex[ source[is] & 0xF ];
            }
        }
    }

    /* terminating NUL */
    if (destination) {
        destination[id] = 0;
    }

    if (size_needed) {
        *size_needed = needed + 1; /* add 1 for terminating NUL */
    }

    return id;
}


size_t UTIL_bintohex(
    const unsigned char *in,
    size_t              count,
    const bool          uppercase,
    const char          separator,
    const unsigned int  separator_count,
    char                *out,
    size_t              out_len,
    size_t              *size_needed)
{
    static const char hex[] = "0123456789abcdef";
    static const char HEX[] = "0123456789ABCDEF";

    const char *hexCase = uppercase ? HEX : hex;

    if (out != NULL && out_len == 0) {
        /* buffer size too small, not even the terminating NUL can be written */
        return 0;
    }

    if (out == NULL && size_needed == NULL) {
        /* neither buffer nor size output given, nothing to do */
        return 0;
    }

    /* reserve one byte for the terminating NUL */
    if (out != NULL) {
        /* reserve one byte for the terminating NUL, out_len is assured > 0 */
        --out_len;
    }

    size_t ii,io,needed;
    for (ii=0,io=0,needed=0; ii<count; ++ii) {
        if (separator_count != 0 && ii && (ii % separator_count == 0)) {
            /* write separator, not first pos, separator pos reached */
            if (out != NULL && io < out_len) {
                out[io++] = separator;
            }
            ++needed;
        }

        if (out != NULL && io + 1 < out_len) {
            out[io++] = hexCase[ (in[ii]>>4) & 0xF ];
            out[io++] = hexCase[ in[ii] & 0xF ];
        }
        needed += 2;
    }

    /* terminating NUL */
    if (out != NULL) {
        out[io] = '\0';
    }
    ++needed;

    if (size_needed != NULL) {
        *size_needed = needed;
    }

    return io;
}

bool UTIL_hex_to_bytes(const char** in_p, unsigned char* out, unsigned int num_out)
{
    unsigned int v = 0;
    unsigned int i = 0;
    unsigned char byte = 0;

    num_out *= HEX_CHARS_PER_BYTE;
    for(i = 0; i < num_out; i++)
    {
        char c = *((*in_p)++);
        if(('0' <= c) and (c <= '9'))
        {
            v = c - '0';
        }
        else if(('A' <= c) and (c <= 'F'))
        {
            v = (c - 'A') + (MAX_DIGIT + 1);
        }
        else if(('a' <= c) and (c <= 'f'))
        {
            v = (c - 'a') + (MAX_DIGIT + 1);
        }
        else
        {
            return false;
        }
        byte = ((unsigned char)(((unsigned char)(byte bitand HEX_MASK)) << HEX_BITS)) bitor v;
        if((i % HEX_CHARS_PER_BYTE) is_eq 1)
        {
            *out++ = byte;
        }
    }
    return true;
}


int UTIL_base64_encode_to_buf(const unsigned char* data, int len, char* buf, int buf_size)
{
    BUF_MEM* bptr = 0;
    BIO* bio_b64 = BIO_new(BIO_f_base64());
    if(0 is_eq bio_b64)
    {
        return -1;
    }
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL); /* We don't ever insert new lines */
    BIO* bio_mem = BIO_new(BIO_s_mem());
    if(0 is_eq bio_mem)
    {
        BIO_free(bio_b64);
        return -1;
    }
    bio_mem = BIO_push(bio_b64, bio_mem);
    BIO_write(bio_mem, data, len);
    (void)BIO_flush(bio_mem);
    BIO_get_mem_ptr(bio_mem, &bptr);
    int encoded_len = bptr->length;
    if(encoded_len < buf_size)
    {
        memcpy(buf, bptr->data, encoded_len);
        buf[encoded_len] = '\0';
    }
    else
    {
        encoded_len = -1 - 1;
    }
    BIO_free_all(bio_mem);
    return encoded_len;
}


unsigned char* UTIL_base64_decode(const char* b64_data, int b64_len, int* decoded_len)
{
    if(0 is_eq b64_data or 0 is_eq decoded_len)
    {
        return 0;
    }

    if(b64_len < 0)
    {
        b64_len = strlen(b64_data);
    }
    if((b64_len * B64_BITS) % BITS_PER_BYTE)
    {
        LOG_err("Illegal length of base64 encoding - wrong padding?");
        return 0;
    }

    *decoded_len = (b64_len * B64_BITS) / BITS_PER_BYTE;
    if((b64_len >= 1) and (b64_data[b64_len - 1] is_eq '='))
    {
        (*decoded_len)--;
    }
    if((b64_len >= (1 + 1)) and (b64_data[b64_len - (1 + 1)] is_eq '='))
    {
        (*decoded_len)--;
    }

    /* Create a base64 filter */
    BIO* bio_b64 = BIO_new(BIO_f_base64());
    if(0 is_eq bio_b64)
    {
        return 0;
    }
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL); /* needed at least for JWT header */

    /*
     * Create a bio memory; bio state is set to read only state.
     * Unless the memory BIO is read only any data read from it is deleted from the BIO
     * */
    BIO* bio_mem = BIO_new_mem_buf(b64_data, b64_len);
    if(0 is_eq bio_mem)
    {
        BIO_free(bio_b64);
        return 0;
    }

    /* Connect the bio_mem buffer with the base 64 filter.
     * Notice the order filter and source are required: filter->source
     */
    BIO_push(bio_b64, bio_mem);

    /* Execute the base 64 decoding and store the output in the decoded_data memory++*/
    unsigned char* decoded_data = OPENSSL_malloc(*decoded_len + 1);
    if(decoded_data is_eq 0)
    {
        LOG_err("Failure allocate memory for base64 decoding");
    }
    else
    {
        /* reading the form the chained bio_b64 returns the decoded length */
        if(BIO_read(bio_b64, decoded_data, *decoded_len) not_eq *decoded_len)
        {
            LOG_err("Failure base64 decoding");
            OPENSSL_free(decoded_data);
            decoded_data = 0;
        }
        else
        {
            decoded_data[*decoded_len] = '\0'; /* for convenience in case result is non-binary */
        }
    }
    BIO_free_all(bio_b64);
    return decoded_data;
}
