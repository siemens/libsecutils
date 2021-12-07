/** 
* @file store.c
* 
* @brief Certificate store, used for verification
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

#include <openssl/x509v3.h>

#include <credentials/store.h>
#include <credentials/verify.h>
#include <certstatus/crls.h> /* for CONN_load_crl_http() */
#include <storage/files.h>
#include <storage/files_icv.h>
#include <connections/conn.h>
#include <util/log.h>
#include <util/util.h>

#include <operators.h>

typedef struct STORE_ex_st
{
#ifndef SECUTILS_NO_TLS
    BIO* tls_bio; /* indicates CMP_PKIMESSAGE_http_perform() with TLS is active */
#endif
    const char* host; /* expected host name in cert, for diagnostic purposes */
    CONN_load_crl_cb_t crl_cb;
    OPTIONAL void* crl_cb_arg;
    revstatus_access cdps;
    revstatus_access ocsp;
} STORE_EX; /* extension data for OpenSSL X509_STORE */

static int STORE_EX_data_idx = -1;

static
#if OPENSSL_VERSION_NUMBER < 0x10100000L
       int
#else
       void
#endif
STORE_EX_new(X509_STORE* ts, STORE_EX* ex_data, CRYPTO_EX_DATA* ad,
                         int idx, long argl, void* argp)
{
    int res = 1;
    if((ex_data = OPENSSL_zalloc(sizeof(*ex_data))) is_eq 0)
    {
        LOG_err("out of memory allocating ex_data of X509_STORE");
        res = 0; /* TODO maybe better exit on error*/
    }
    else if(not X509_STORE_set_ex_data(ts, idx, (void*)ex_data))
    {
        LOG_err("cannot set ex_data of X509_STORE");
        OPENSSL_free(ex_data);
        res = 0; /* TODO maybe better exit on error*/
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return res;
#else
    (void)res; /* prevent compiler warning on unused variable */
    return;
#endif
}

static void STORE_EX_free(X509_STORE* ts, STORE_EX* ex_data, CRYPTO_EX_DATA* ad,
                          int idx, long argl, void* argp)
{
    if(0 not_eq ex_data)
    {
        OPENSSL_free((char*)ex_data->host);
        OPENSSL_free((char*)ex_data->cdps.urls);
        OPENSSL_free((char*)ex_data->ocsp.urls);
        OPENSSL_free(ex_data);
    }
}

bool STORE_EX_check_index(void)
{
    return STORE_EX_data_idx not_eq -1;
}

__attribute__ ((constructor))
static void STORE_EX_init_index(void)
{
    UTIL_setup_openssl(OPENSSL_VERSION_NUMBER, UTIL_SECUTILS_NAME);

    if(STORE_EX_data_idx < 0)
    {
        STORE_EX_data_idx =
            CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, 0, 0,
                                    (CRYPTO_EX_new *)&STORE_EX_new, 0,
                                    (CRYPTO_EX_free*)&STORE_EX_free);
        if(STORE_EX_data_idx is_eq -1)
        {
            LOG_err("cannot get index for ex_data of X509_STORE");
        }
    }
}

__attribute__ ((destructor))
static void STORE_EX_free_index(void)
{
    if(-1 not_eq STORE_EX_data_idx)
    {
        CRYPTO_free_ex_index(CRYPTO_EX_INDEX_X509_STORE, STORE_EX_data_idx);
        STORE_EX_data_idx = -1;
    }
}

static STORE_EX* STORE_get_ex_data(X509_STORE* store)
{
    STORE_EX* res = 0;
    if(store is_eq 0)
    {
        LOG(FL_ERR, "null argument");
    }
    else
    {
        res = X509_STORE_get_ex_data(store, STORE_EX_data_idx);
        if(res is_eq 0)
        {
            LOG(FL_ERR, "STORE_EX not found");
        }
    }
    return res;
}

/* all params may be null pointer; does not consume cert or certs */
X509_STORE* STORE_create(OPTIONAL X509_STORE* store, OPTIONAL const X509* cert, OPTIONAL const STACK_OF(X509) * certs)
{
    int i;

    if(0 is_eq store)
    {
        if(not STORE_EX_check_index())
        {
            return 0;
        }

        store = X509_STORE_new();
        if(0 is_eq store)
        {
            goto oom;
        }
    }
    X509_STORE_set_verify_cb(store, CREDENTIALS_print_cert_verify_cb);

#if 0 /* better not trust unclear default store */
    if(X509_STORE_set_default_paths(store) not_eq 1)
    {
        LOG_err("Cannot load the system-wide trusted certificates");
        STORE_free(store);
        return 0;
    }
#endif

    int n = certs ? sk_X509_num(certs) : 0;
    for(i = cert ? -1 : 0; i < n; i++)
    {
        if(i not_eq -1)
        {
            cert = sk_X509_value(certs, i);
        }
        if(0 is_eq X509_STORE_add_cert(store, (X509*)cert))
        {
#if OPENSSL_VERSION_NUMBER < 0x10101000L /* from 1.1.1, duplicates are ignored */
            if(ERR_GET_REASON(ERR_peek_error()) is_eq X509_R_CERT_ALREADY_IN_HASH_TABLE)
            {
                ERR_clear_error();
            }
            else
#endif
            {
                STORE_free(store);
                goto oom;
            }
        }
    }
    return store;

oom:
    LOG_err("Out of memory creating trust store");
    return 0;
}


#if 0
/* consumes certs */
bool X509_STORE_add0_certs(X509_STORE* store, STACK_OF(X509) * certs)
{
    if(0 is_eq certs)
    {
        return true;
    }
    int i, n = sk_X509_num(certs);
    for(i = 0; i < n; i++)
    {
        if(0 is_eq X509_STORE_add_cert(store, sk_X509_value(certs, i)))
        {
            sk_X509_pop_free(certs, X509_free);
            return false;
        }
    }
    sk_X509_pop_free(certs, X509_free);
    return true;
}
#endif

/*
 * extend or create cert store structure with cert(s) read from file
 */
bool STORE_load_more(X509_STORE** pstore, const char* file, file_format_t format, OPTIONAL const char* desc,
                     OPTIONAL uta_ctx* ctx)
{
    if(pstore is_eq 0 or file is_eq 0)
    {
        LOG_err("null pointer argument");
        goto err;
    }

#ifdef DEBUG
    LOG(FL_DEBUG, "Loading %s from file '%s'", desc not_eq 0 ? desc : "?", file);
#endif

    if(ctx is_eq 0 or FILES_check_icv(ctx, file))
    {
        STACK_OF(X509)* certs = FILES_load_certs_autofmt(file, format, 0 /* source */, desc);
        if(0 is_eq certs)
        {
            goto err;
        }

        UTIL_warn_certs(file, certs, 1, NULL /* unfortunately no VPM available */);
        *pstore = STORE_create(*pstore, 0, certs);
        sk_X509_pop_free(certs, X509_free);
        return *pstore not_eq 0;
    }

err:
    LOG(FL_ERR, "Could not load %s", desc not_eq 0 ? desc : file);
    return false;
}


X509_STORE* STORE_load_trusted(const char* files, OPTIONAL const char* desc, OPTIONAL uta_ctx* ctx)
{
    X509_STORE* store = 0;

    if(files is_eq 0)
    {
        LOG_err("null pointer files arg");
        return 0;
    }

    char* names = OPENSSL_strdup(files);
    if(names is_eq 0)
    {
        LOG_err("Out of memory");
        return 0;
    }

    char* file;
    char* next;
    for(file = names; file not_eq 0; file = next)
    {
        next = UTIL_next_item(file); /* must do this here to split string */
        if(not STORE_load_more(&store, file, FORMAT_PEM, desc, ctx))
        {
            X509_STORE_free(store);
            store = 0;
            break;
        }
    }

    OPENSSL_free(names);
    return store;
}


bool STORE_load_trusted_dir(X509_STORE** pstore, const char* trust_dir, OPTIONAL const char* desc, bool recursive,
                            OPTIONAL uta_ctx* ctx)
{
    DIR* p_dir = 0;
    bool found = false;

    if(0 is_eq pstore or 0 is_eq trust_dir)
    {
        LOG_err("null pointer argument");
        goto err;
    }

    p_dir = opendir(trust_dir);
    if(0 is_eq p_dir)
    {
        LOG(FL_ERR, "cannot read directory '%s'", trust_dir);
        goto err;
    }

    struct dirent* p_dirent = readdir(p_dir);
    while(0 not_eq p_dirent)
    {
        char full_path[UTIL_max_path_len + 1];
        snprintf(full_path, sizeof(full_path), "%s/%s", trust_dir, p_dirent->d_name);

        struct stat f_stat;
        memset(&f_stat, 0x00, sizeof(struct stat));
        if(-1 is_eq stat(full_path, &f_stat))
        {
            LOG(FL_INFO, "cannot read status of %s - %s", full_path, strerror(errno));
        }
        else
        {
            if(f_stat.st_mode bitand S_IFREG)
            {
                if(STORE_load_more(pstore, full_path, FORMAT_PEM, 0 /* do not report load errors twice */, ctx))
                {
                    found = true;
                }
            }
            else if(recursive and (f_stat.st_mode bitand S_IFDIR) and (0 not_eq strncmp(p_dirent->d_name, ".", 1)))
            {
                if(not STORE_load_trusted_dir(pstore, full_path, desc, recursive, ctx))
                {
                    found = false;
                    goto err;
                }
            }
        }
        p_dirent = readdir(p_dir);
    }

    if(not found)
    {
        LOG(FL_ERR,
            "no %s %s"
            "found in directory '%s'",
            desc not_eq 0 ? desc : "trusted certs", ctx not_eq 0 ? "with valid ICV " : "", trust_dir);
    }
err:
    if(p_dir not_eq 0)
    {
        closedir(p_dir);
    }

    int cert_num = UTIL_store_certs_num(*pstore);
    if(not found and cert_num is_eq 0)
    {
        STORE_free(*pstore);
        *pstore = 0;
    }
    return found;
}

bool STORE_load_crl_dir(X509_STORE* pstore, const char* crl_dir, OPTIONAL const char* desc, bool recursive, OPTIONAL uta_ctx* ctx)
{
    DIR* p_dir = 0;
    bool found = false;

    if(0 is_eq pstore or 0 is_eq crl_dir)
    {
        LOG(FL_ERR, "null pointer argument");
        goto err;
    }

    p_dir = opendir(crl_dir);
    if(0 is_eq p_dir)
    {
        LOG(FL_ERR, "cannot access directory '%s'", crl_dir);
        goto err;
    }

    struct dirent* p_dirent = readdir(p_dir);
    while(0 not_eq p_dirent)
    {
        char full_path[UTIL_max_path_len + 1];
        snprintf(full_path, sizeof(full_path), "%s/%s", crl_dir, p_dirent->d_name);

        struct stat f_stat;
        memset(&f_stat, 0x00, sizeof(struct stat));
        if(-1 is_eq stat(full_path, &f_stat))
        {
            LOG(FL_INFO, "cannot read status of %s - %s", full_path, strerror(errno));
        }
        else
        {
            if(f_stat.st_mode bitand S_IFREG)
            {
                if (FILES_check_icv(ctx, full_path))
                {
                    STACK_OF(X509_CRL)* crls = FILES_load_crls_autofmt(full_path, FORMAT_PEM, 0 /* timeout not relevant for files */, desc);
                    if(0 not_eq crls)
                    {
                        if(not STORE_add_crls(pstore, crls))
                        {
                            LOG(FL_ERR, "Adding CRLs to trust store failed");
                            goto err;
                        }
                        sk_X509_CRL_pop_free(crls, X509_CRL_free);
                        found = true;
                    }
                }
                else
                {
                    LOG(FL_ERR, "ICV check failed for CRL %s", p_dirent->d_name);
                }
            }
            else if(recursive and (f_stat.st_mode bitand S_IFDIR) and (0 not_eq strncmp(p_dirent->d_name, ".", 1)))
            {
                if(not STORE_load_crl_dir(pstore, full_path, desc, recursive, ctx))
                {
                    found = false;
                    goto err;
                }
            }
        }
        p_dirent = readdir(p_dir);
    }

    // set up cert CRL check callback for checking full chain
    if(found)
    {
        X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(pstore), X509_V_FLAG_STATUS_CHECK_ALL);
        X509_STORE_set_check_revocation(pstore, &check_revocation_any_method);
    }

err:
    if(p_dir not_eq 0)
    {
        closedir(p_dir);
    }
    return found;
}


bool STORE_set1_host_ip(X509_STORE* ts, const char* name, const char* ip)
{
    if(ts is_eq 0)
    {
        LOG_err("null pointer argument");
        return false;
    }
    X509_VERIFY_PARAM* ts_vpm = X509_STORE_get0_param(ts);

    /* first clear any host names, IP addresses, and email addresses */
    if(not STORE_set1_host(ts, 0) or
       0 is_eq X509_VERIFY_PARAM_set1_host(ts_vpm, 0, 0) or
       0 is_eq X509_VERIFY_PARAM_set1_ip(ts_vpm, 0, 0) or
       0 is_eq X509_VERIFY_PARAM_set1_email(ts_vpm, 0, 0))
    {
        LOG_err("Could not clear host name and IP address from store");
        return false;
    }

    if(0 is_eq name and 0 is_eq ip)
    {
        return true;
    }

    char* name_str = CONN_get_host(name);
    if(name not_eq 0 and name_str is_eq 0)
    {
        return false;
    }

    char* ip_str = CONN_get_host(ip);
    if(ip not_eq 0 and ip_str is_eq 0)
    {
        OPENSSL_free(name_str);
        return false;
    }

    X509_VERIFY_PARAM_set_hostflags(ts_vpm,
                                    X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT |
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    bool res = true;
    if(ip_str not_eq 0 and X509_VERIFY_PARAM_set1_ip_asc(ts_vpm, ip_str) is_eq 0)
    {
        res = false;
    }
    if(name_str not_eq 0 and (ip_str is_eq 0 or (res is_eq false and strcmp(name, ip) is_eq 0)))
    {
        /* Unfortunately there is no OpenSSL API function for retrieving the
           hostname/ip entries in X509_VERIFY_PARAM. So we store the host value
           in ex_data for use in CREDENTIALS_print_cert_verify_cb(). */
        res = X509_VERIFY_PARAM_set1_host(ts_vpm, name_str, 0) not_eq 0;
        if(res not_eq false)
        {
            res = STORE_set1_host(ts, name_str);
        }
    }
    if(res is_eq false)
    {
        LOG(FL_ERR, "Could not set host name '%s' and/or IP address '%s' in store", name_str not_eq 0 ? name_str : "",
            ip_str not_eq 0 ? ip_str : "");
    }
    OPENSSL_free(ip_str);
    OPENSSL_free(name_str);
    return res;
}


static bool crl_expired(const X509_CRL* crl, const X509_VERIFY_PARAM* vpm)
{
    time_t check_time, *ptime = 0;
    unsigned long flags = X509_VERIFY_PARAM_get_flags((X509_VERIFY_PARAM*)vpm);

    if((flags bitand X509_V_FLAG_NO_CHECK_TIME) not_eq 0)
    {
        return false;
    }
    if((flags bitand X509_V_FLAG_USE_CHECK_TIME) not_eq 0)
    {
        check_time = X509_VERIFY_PARAM_get_time(vpm);
        ptime = &check_time;
    }
    const ASN1_TIME* crl_endtime = X509_CRL_get0_nextUpdate(crl);
    /* well, should ignore expiry of base CRL if delta CRL is valid */
    return (crl_endtime not_eq 0 and X509_cmp_time(crl_endtime, ptime) < 0);
}


/* extended from add_crls_store() in OpenSSL:apps/s_cb.c */
bool STORE_add_crls(X509_STORE* ts, OPTIONAL const STACK_OF(X509_CRL) * crls)
{
    X509_CRL* crl;
    int i;

    if(ts is_eq 0)
    {
        LOG_err("null pointer given as trust store argument");
        return false;
    }
    for(i = 0; i < sk_X509_CRL_num(crls); i++)
    {
        crl = sk_X509_CRL_value(crls, i);
        if(crl_expired(crl, X509_STORE_get0_param(ts)) not_eq 0)
        {
            char* issuer = X509_NAME_oneline(X509_CRL_get_issuer(crl), 0, 0);
            if(issuer not_eq 0)
            {
                LOG(FL_WARN, "CRL issued by %s has expired", issuer);
                OPENSSL_free(issuer);
            }
        }
        if(0 is_eq X509_STORE_add_crl(ts, crl))
        {
            LOG(FL_ERR, "Adding CRL to trust store failed");
#if OPENSSL_VERSION_NUMBER < 0x10101000L /* from 1.1.1, duplicates are ignored */
            if(ERR_GET_REASON(ERR_peek_error()) is_eq X509_R_CERT_ALREADY_IN_HASH_TABLE)
            {
                ERR_clear_error();
            }
            else
#endif
            {
                return false;
            }
        }
    }
    return X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(ts), X509_V_FLAG_CRL_CHECK);
}


bool STORE_set_parameters(X509_STORE* ts, OPTIONAL const X509_VERIFY_PARAM* vpm,
                          bool full_chain, bool stapling,
                          OPTIONAL const STACK_OF(X509_CRL) * crls,
                          bool use_CDP, OPTIONAL const char* cdps, int crls_timeout,

                          bool use_AIA, OPTIONAL const char* ocsp, int ocsp_timeout)
{
    if(0 is_eq ts)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }

    if(vpm not_eq 0 and 0 is_eq X509_STORE_set1_param(ts, (X509_VERIFY_PARAM*)vpm))
    {
        LOG_err("Cannot set verification parameters in trust store");
        return false;
    }
    X509_VERIFY_PARAM* ts_vpm = X509_STORE_get0_param(ts);
    X509_VERIFY_PARAM_clear_flags(ts_vpm, X509_V_FLAG_STATUS_CHECK_ALL);
    /* do not clear X509_V_FLAG_CRL_CHECK because there may already be local CRLs */
#ifndef OPENSSL_NO_OCSP
    X509_VERIFY_PARAM_clear_flags(ts_vpm, X509_V_FLAG_OCSP_CHECK);
#endif
#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= 0x1010001fL
    X509_VERIFY_PARAM_clear_flags(ts_vpm, X509_V_FLAG_OCSP_STAPLING);
#endif
    unsigned long flags = X509_VERIFY_PARAM_get_flags(ts_vpm);

    if(full_chain)
    {
        flags |= X509_V_FLAG_STATUS_CHECK_ALL;
    }
    bool check_any = (flags bitand X509_V_FLAG_STATUS_CHECK_ANY) not_eq 0;
    /* this status check flag can be set only indirectly via vpm parameter */
    if(check_any and full_chain)
    {
        LOG_warn("full_chain (check_all) overrides X509_V_FLAG_STATUS_CHECK_ANY");
    }
    if((full_chain or check_any)
       and crls is_eq NULL and not use_CDP and cdps is_eq NULL
       and not use_AIA and ocsp is_eq NULL)
    {
        LOG_err("Cannot use full_chain (check_all) or X509_V_FLAG_STATUS_CHECK_ANY without use of CRLs or OCSP being enabled");
        return false;
    }
    if((flags bitand X509_V_FLAG_OCSP_LAST) not_eq 0
        /* this status check flag can be set only indirectly via vpm parameter */
       and not use_AIA and ocsp is_eq NULL)
    {
        LOG_err("X509_V_FLAG_OCSP_LAST is set without any other option enabling OCSP-based cert status checking");
        return false;
    }

    if(crls not_eq 0 and 0 is_eq STORE_add_crls(ts, crls))
    {
        LOG_err("Cannot add CRLs to trust store");
        return false;
    }

    bool crl_check = crls not_eq 0 or use_CDP or cdps not_eq 0 or
        (flags bitand X509_V_FLAG_CRL_CHECK) not_eq 0;
    if(crl_check)
    {
        flags |= X509_V_FLAG_CRL_CHECK;
    }

    bool ocsp_check = use_AIA or ocsp not_eq 0;
    if(ocsp_check)
    {
#ifndef OPENSSL_NO_OCSP
        flags |= X509_V_FLAG_OCSP_CHECK;
#else
        LOG_err("OCSP is not supported by the OpenSSL build");
        return false;
#endif
    }

    if(stapling)
    {
#if !defined(OPENSSL_NO_OCSP) && OPENSSL_VERSION_NUMBER >= 0x1010001fL
        flags |= X509_V_FLAG_OCSP_STAPLING;
#else
        LOG_err("OCSP stapling is not supported by the OpenSSL version/build");
        return false;
#endif
    }

    /* extend vpm flags of ts w.r.t. any given cert status check options */
    X509_VERIFY_PARAM_set_flags(ts_vpm, flags); /* ORs with existing flags */

    if(not stapling and not crl_check and not ocsp_check)
    {
        if(full_chain)
        {
            LOG_err("full_chain (check_all) option is set but no checking method is enabled");
            return false;
        }
        if(check_any)
        {
            LOG_err("X509_V_FLAG_STATUS_CHECK_ANY is set but no checking method is enabled");
            return false;
        }
        return true;
    }

    /* some certificate status check is enabled, so set further ts attributes */
    X509_STORE_set_check_revocation(ts, &check_revocation_any_method);

    STORE_EX* ex_data = STORE_get_ex_data(ts);
    if(ex_data is_eq 0)
    {
        return false;
    }

    /* ex_data->tls_bio and ex_data->host are 0 */
    /* ex_data->crl_cb and ex_data->crl_cb_arg are 0 */

    ex_data->cdps.flags = use_CDP ? 0 : REVSTATUS_IGNORE_CERT_EXT;
    ex_data->cdps.urls = OPENSSL_strdup(cdps);
    ex_data->cdps.timeout = crls_timeout;

#ifndef OPENSSL_NO_OCSP
    ex_data->ocsp.flags = use_AIA ? 0 : REVSTATUS_IGNORE_CERT_EXT;
    ex_data->ocsp.urls = OPENSSL_strdup(ocsp);
    ex_data->ocsp.timeout = ocsp_timeout;
#endif

    return true;
}

bool STORE_set_crl_callback(X509_STORE* ts,
                            OPTIONAL CONN_load_crl_cb_t crl_cb,
                            OPTIONAL void* crl_cb_arg)
{
    if(0 is_eq ts)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }

    STORE_EX* ex_data = STORE_get_ex_data(ts);
    if(ex_data is_eq 0)
    {
        return false;
    }

    ex_data->crl_cb = crl_cb;
    ex_data->crl_cb_arg = crl_cb_arg;
    return true;
}

static X509_CRL *load_crl_http(OPTIONAL void *arg, OPTIONAL const char *url, int timeout,
                               OPTIONAL const X509 *cert, OPTIONAL const char *desc)
{
    if (desc is_eq 0)
    {
        desc = "(no description)";
    }
    LOG(FL_TRACE, "default_load_crl_cb() called with arg=%lx, url='%s', timeout=%d, desc='%s'", (long)arg, url, timeout, desc);
    if (url not_eq 0)
    {
        return CONN_load_crl_http(url, timeout, 0, desc);
    }
    if (cert not_eq 0)
    {
        LOG_cert(FL_DEBUG, "no CDP URL given and not using information from", cert);
    }
    return 0;
}

X509_CRL* STORE_fetch_crl(X509_STORE* ts, OPTIONAL const char* url, int timeout,
                          const X509* cert, OPTIONAL const char* desc)
{
    if (url not_eq 0 and strncmp(url, "file:", 5) is_eq 0)
    {
        return FILES_load_crl_autofmt(url, FORMAT_ASN1, timeout, desc);
    }
    if(0 is_eq ts)
    {
        LOG(FL_ERR, "null trust store argument");
        return 0;
    }

    STORE_EX* ex_data = STORE_get_ex_data(ts);
    if(ex_data is_eq 0)
    {
        return 0;
    }

    CONN_load_crl_cb_t crl_cb = ex_data->crl_cb;
    if (crl_cb is_eq 0)
    {
        if (url is_eq 0)
        {
            return 0;
        }
        crl_cb = load_crl_http;
    }
    return (*crl_cb)(ex_data->crl_cb_arg, url, timeout, cert, desc);
}

bool STORE_set1_host(X509_STORE* store, OPTIONAL const char* host)
{
    STORE_EX* ex_data = STORE_get_ex_data(store);
    if(ex_data is_eq 0)
    {
        return false;
    }
    OPENSSL_free((char*)ex_data->host);
    ex_data->host = OPENSSL_strdup(host);
    return true;
}

const char* STORE_get0_host(X509_STORE* store)
{
    const STORE_EX* ex_data = STORE_get_ex_data(store);
    return ex_data not_eq 0 ? ex_data->host : 0;
}

#ifndef SECUTILS_NO_TLS
bool STORE_set0_tls_bio(X509_STORE* store, OPTIONAL BIO* bio)
{
    STORE_EX* ex_data = STORE_get_ex_data(store);
    return ex_data not_eq 0 ? (ex_data->tls_bio = bio, true) : false;
}

BIO* STORE_get0_tls_bio(X509_STORE* store)
{
    const STORE_EX* ex_data = STORE_get_ex_data(store);
    return ex_data not_eq 0 ? ex_data->tls_bio : 0;
}
#endif /* !defined(SECUTILS_NO_TLS) */

const revstatus_access* STORE_get0_cdps(X509_STORE* store)
{
    const STORE_EX* ex_data = STORE_get_ex_data(store);
    return ex_data not_eq 0 ? &ex_data->cdps : 0;
}

const revstatus_access* STORE_get0_ocsp(X509_STORE* store)
{
    const STORE_EX* ex_data = STORE_get_ex_data(store);
    return ex_data not_eq 0 ? &ex_data->ocsp : 0;
}


void STORE_free(X509_STORE* store)
{
    X509_STORE_free(store);
}
