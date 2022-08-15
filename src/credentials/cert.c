/**
* @file cert.c
* 
* @brief Certificate utility functions
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

#include <openssl/x509.h>

#include <credentials/cert.h>
#include <storage/files.h>
#include <util/log.h>

#include <operators.h>


X509 *CERT_load(const char *file, OPTIONAL const char *source,
                OPTIONAL const char *desc,
                int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    X509 *cert = FILES_load_cert(file, FILES_get_format(file), source, desc);
    if (!CERT_check(file, cert, type_CA, vpm) && vpm != NULL) {
        X509_free(cert);
        cert = NULL;
    }
    return cert;
}

bool CERT_save(const X509 *cert, const char *file, OPTIONAL const char *desc)
{
    file_format_t format = FILES_get_format(file);
    if (format == FORMAT_UNDEF) {
        LOG(FL_ERR, "Failed to determine format from file name ending of '%s'", file);
        return false;
    }
    return FILES_store_cert(cert, file, format, desc);
}

STACK_OF(X509) *CERTS_load(const char *files, OPTIONAL const char *desc,
                           int type_CA, const OPTIONAL X509_VERIFY_PARAM *vpm)
{
    STACK_OF(X509) *certs =
        FILES_load_certs_multi(files, FORMAT_PEM, NULL /* pwd source */, desc);
    if (!CERT_check_all(files, certs, type_CA, vpm) && vpm != NULL) {
        CERTS_free(certs);
        certs = NULL;
    }
    return certs;
}

int CERTS_save(OPTIONAL const STACK_OF(X509) *certs, const char *file, OPTIONAL const char *desc)
{
    file_format_t format = FILES_get_format(file);
    if (format == FORMAT_UNDEF) {
        LOG(FL_ERR, "Failed to determine format from file name ending of '%s'", file);
        return -1;
    }
    return FILES_store_certs(certs, file, format, desc);
}

void CERTS_free(OPTIONAL STACK_OF(X509) *certs)
{
    sk_X509_pop_free(certs, X509_free);
}


void CERT_print(OPTIONAL const X509* cert, OPTIONAL BIO* bio, unsigned long neg_cflags)
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


void CERTS_print(OPTIONAL const STACK_OF(X509) * certs, OPTIONAL BIO* bio)
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
                CERT_print(cert, bio, X509_FLAG_NO_EXTENSIONS);
            }
        }
    }
    else
    {
        BIO_printf(bio, "    (no certificates)\n");
        BIO_flush(bio);
    }
}


/* This is similar to static warn_cert_msg()  */
void LOG_cert(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
              const char* msg, const X509* cert)
{
    if (msg == NULL)
        LOG_err("null pointer msg argument");
    if (cert == NULL)
        LOG_err("null pointer cert argument");
    char* subj = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    LOG(func, file, lineno, level, "%s cert with subject = %s", msg, subj);
    OPENSSL_free(subj);
}


/* This is similar to LOG_cert() */
static void cert_msg(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                     const char *uri, X509 *cert, const char *msg)
{
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    LOG(func, file, lineno, level, "Certificate from '%s' with subject '%s' %s", uri, subj, msg);
    OPENSSL_free(subj);
}


bool CERT_check(const char *uri, OPTIONAL X509 *cert, int type_CA,
                OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    if (cert == NULL)
        return true;
    int res = 0;

#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
    res = X509_cmp_timeframe(vpm, X509_get0_notBefore(cert),
                             X509_get0_notAfter(cert));
#else
    unsigned long flags = vpm == NULL ? 0 :
        X509_VERIFY_PARAM_get_flags((X509_VERIFY_PARAM *)vpm);
    if ((flags & X509_V_FLAG_NO_CHECK_TIME) == 0) {
        time_t ref_time;
        time_t *time = NULL;
        if ((flags & X509_V_FLAG_USE_CHECK_TIME) != 0) {
            ref_time = X509_VERIFY_PARAM_get_time(vpm);
            time = &ref_time;
        }
        if (X509_cmp_time(X509_get0_notAfter(cert), time) < 0)
            res = 1;
        else if (X509_cmp_time(X509_get0_notBefore(cert), time) > 0)
            res = -1;
    }
#endif
    bool ret = res == 0;
    severity level = vpm == NULL ? LOG_WARNING : LOG_ERR;
    if (!ret)
        cert_msg(LOG_FUNC_FILE_LINE, level,
                 uri, cert, res > 0 ? "has expired" : "not yet valid");
    uint32_t ex_flags = X509_get_extension_flags(cert);
    if (type_CA >= 0 && (ex_flags & EXFLAG_V1) == 0) {
        bool is_CA = (ex_flags & EXFLAG_CA) != 0;
        if ((type_CA == 1) != is_CA) {
            cert_msg(LOG_FUNC_FILE_LINE, level, uri, cert,
                     is_CA ? "is not an EE cert" : "is not a CA cert");
            ret = false;
        }
    }
    return ret;
}


bool CERT_check_all(const char *uri, OPTIONAL STACK_OF(X509) *certs, int type_CA,
                    OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    int i;
    bool ret = true;

    for (i = 0; i < sk_X509_num(certs /* may be NULL */); i++)
        ret = CERT_check(uri, sk_X509_value(certs, i), type_CA, vpm)
            && ret; /* Having 'ret' after the '&&', all certs are checked. */
    return ret;
}
