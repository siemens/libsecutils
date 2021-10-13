/** 
* @file crl_mgmt.c
* 
* @brief Handling CRLs during certificate revocation check
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

#include <certstatus/crl_mgmt.h>
#include <certstatus/cdp_util.h>
#include <certstatus/crls.h>
#include <certstatus/certstatus.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#if 0 /* likely would require backporting a lot of code */
int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str)
{
}
#endif
#endif

#define SN_crl_next_publish     "nextPublish"
#define LN_crl_next_publish     "Next CRL Publish"
#define NID_crl_next_publish    nidCrlNextPublish
#define OBJ_crl_next_publish    OBJ_id_ce,20L

typedef struct crlmgmt_data_st {
    const char      *proxy_url;
    unsigned long   max_download_size;
    const char      *crl_cache_dir;
    bool            use_url;
    bool            use_issuer;
    const char      *note;
} CRLMGMT_DATA;

static const char url_param_url[]       = "?url=";
static const char url_param_issuer[]    = "?issuer=";
static const char crl_suffix[]          = ".crl";
static int nidCrlNextPublish            = 0;


static bool chkmkdir(const char *dir) {
    struct stat s;
    if (stat(dir, &s) == 0) {
        // ok path exists, check, if it is a dir
        return S_ISDIR(s.st_mode) != 0;
    }
    if (errno == ENOENT) {
        // path is not existing
        return mkdir(dir, 0700) == 0;
    }
    return false;
}

static int get_cache_filename_from_url(const char * cache_dir, const char * url, char *buf, size_t buflen)
{
    if (cache_dir == NULL) {
        LOG(FL_DEBUG, "no cache directory is given, caching is disabled");
        return 0;
    }

    if (!chkmkdir(cache_dir)) {
        LOG(FL_ERR, "the cache directory does not exist or could not be created: %s",
            cache_dir);
        return 0;
    }

    size_t len = UTIL_safe_string_copy(cache_dir, buf, buflen, 0);

    // create sha256 from url
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)url, strlen(url), hash);
    len += UTIL_bintohex(hash, SHA256_DIGEST_LENGTH, false, 0, 0, buf+len, buflen-len, NULL);
    len += UTIL_safe_string_copy(crl_suffix, buf+len, buflen-len, 0);

    return len > 0;
}

static X509_CRL *get_crl_from_cache(const char * cachefile)
{
    X509_CRL    *crl = NULL;
    BIO         *in = NULL;
    char        time_buf[40];

    in = BIO_new_file(cachefile, "rb");
    if (in != NULL) {
        // read crl from ASN1 format
        crl = d2i_X509_CRL_bio(in, NULL);
        // the PEM format would be this, format detection is currently not supported
        // crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
        if (crl == NULL) {
            // do not unlink an unknown file that is not loadable as CRL
            LOG(FL_ERR, "error loading the CRL from cachefile: %s", cachefile);
        }
        BIO_free(in);
    }
    else {
        LOG(FL_INFO, "cache file could not be opened: %s", cachefile);
    }

    if (crl) {
        ASN1_TIME *now = ASN1_TIME_new();
        ASN1_TIME_set(now, time(NULL));
        const ASN1_TIME *lastUpdate = X509_CRL_get0_lastUpdate(crl);
        const ASN1_TIME *nextUpdate = X509_CRL_get0_nextUpdate(crl);

        CDP_get_x509_time(now, time_buf, sizeof(time_buf));
        LOG(FL_DEBUG, "current time: %s", time_buf);
        CDP_get_x509_time(lastUpdate, time_buf, sizeof(time_buf));
        LOG(FL_DEBUG, "CRL lastUpdate: %s", time_buf);
        CDP_get_x509_time(nextUpdate, time_buf, sizeof(time_buf));
        LOG(FL_DEBUG, "CRL nextUpdate: %s", time_buf);

        int isBeforeStart = ASN1_TIME_compare(now, lastUpdate) < 0;
        int isAfterEnd = ASN1_TIME_compare(nextUpdate, now) <= 0;
        int isAfterPublish = 0;

        int nextPublishIdx = X509_CRL_get_ext_by_NID(crl, NID_crl_next_publish, 0);
        if (nextPublishIdx >= 0) {
            X509_EXTENSION *ex = X509_CRL_get_ext(crl, nextPublishIdx);
            ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ex);
            if (B_ASN1_T61STRING == ASN1_STRING_type(data)) {
#if OPENSSL_VERSION_NUMBER < 0x10101000L
                    LOG(FL_ERR, "CRL nextPublish extension is present, but ASN1_TIME_set_string_X509 is not supported for OpenSSL version <1.1, sorry");
#else
                const char *nextPublishString = (const char*)ASN1_STRING_get0_data(data);
                while (*nextPublishString && !((*nextPublishString) & 0xE0)) {
                    ++nextPublishString;
                }
                ASN1_TIME *nextPublish = ASN1_TIME_new();
                if (ASN1_TIME_set_string_X509(nextPublish, nextPublishString)) {
                    CDP_get_x509_time(nextPublish, time_buf, sizeof(time_buf));
                    LOG(FL_DEBUG, "CRL nextPublish: %s", time_buf);
                    isAfterPublish = ASN1_TIME_compare(nextPublish, now) <= 0;
                }
                else {
                    LOG(FL_ERR, "CRL nextPublish extension is present, but time cannot be determined");
                }
                ASN1_TIME_free(nextPublish);
#endif
            }
        }
        else {
            LOG(FL_DEBUG, "Next Publish extension not present in CRL");
        }

        LOG(FL_DEBUG, "CRL timecheck: isBeforeStart: %d, isAfterEnd: %d, isAfterPublish: %d", isBeforeStart, isAfterEnd, isAfterPublish);
        if (isBeforeStart || isAfterEnd || isAfterPublish) {
            LOG(FL_INFO, "the CRL is expired, it is deleted from the cache");
            // crl not within time frame, remove it
            X509_CRL_free(crl);
            crl = NULL;
            // unlink the expired CRL file
            unlink(cachefile);
        }
        else {
            LOG(FL_INFO, "the CRL has been successfully loaded from the cache");
        }
        ASN1_TIME_free(now);
    }

    return crl;
}

static int put_crl_into_cache(X509_CRL * crl, const char * cachefile)
{
    int res = 0;

    BIO *out = BIO_new_file(cachefile, "wb");
    if (out != NULL) {
        // write the CRL into an ASN1 formatted file
        res = (int)i2d_X509_CRL_bio(out, crl);
        // PEM format would be this, different formats are currently not supported
        // res = PEM_write_bio_X509_CRL(out, crl);
        if (!res) {
            BIO_printf(bio_err, "unable to write CRL\n");
        }
        BIO_free(out);
    }

    return res;
}

static X509_CRL *get_crl_by_download_or_from_cache(const CRLMGMT_DATA *data,
                                                   const char *url, int timeout,
                                                   OPTIONAL const char* desc)
{
    char cachefile[FILENAME_MAX];
    bool usecache = get_cache_filename_from_url(data->crl_cache_dir, url,
        cachefile, sizeof(cachefile));

    X509_CRL *crl;
    if (usecache) {
        LOG(FL_TRACE, "trying to load CRL from cache file: %s", cachefile);
        crl = get_crl_from_cache(cachefile);
        if (crl != NULL) {
            LOG(FL_DEBUG, "got CRL for %s", desc);
            return crl;
        }
        LOG(FL_DEBUG, "did not get CRL from cache for %s", desc);
    }

    crl = CONN_load_crl_http(url, timeout, data->max_download_size, desc);
    if (usecache && crl != NULL) {
        put_crl_into_cache(crl, cachefile);
    }
    return crl;
}

CRLMGMT_DATA *CRLMGMT_DATA_new(void)
{
    if (nidCrlNextPublish==0) {
        // TODO this is not threadsafe
        nidCrlNextPublish = OBJ_create("1.3.6.1.4.1.311.21.4",
            SN_crl_next_publish, LN_crl_next_publish);
    }

    CRLMGMT_DATA *cmdat = OPENSSL_zalloc(sizeof(*cmdat));
    if (cmdat == NULL) {
        LOG(FL_ERR, "CRLMGMT_DATA_new failed to allocate memory");
        return NULL;
    }
    cmdat->proxy_url = NULL;
    cmdat->max_download_size = 0;
    cmdat->crl_cache_dir = NULL;
    cmdat->use_url = 1;
    cmdat->use_issuer = 1;
    cmdat->note = NULL;
    return cmdat;
}

void CRLMGMT_DATA_free(
    CRLMGMT_DATA *cmdat)
{
    OPENSSL_free(cmdat);
}

const char *CRLMGMT_DATA_get_proxy_url(
    CRLMGMT_DATA *cmdat)
{
    return cmdat->proxy_url;
}

void CRLMGMT_DATA_set_proxy_url(
    CRLMGMT_DATA    *cmdat,
    const char      *proxy_url)
{
    cmdat->proxy_url = proxy_url;
}

unsigned long CRLMGMT_DATA_get_crl_max_download_size(
    CRLMGMT_DATA *cmdat)
{
    return cmdat->max_download_size;
}
void CRLMGMT_DATA_set_crl_max_download_size(
    CRLMGMT_DATA    *cmdat,
    unsigned long   max_download_size)
{
    cmdat->max_download_size = max_download_size;
}

const char *CRLMGMT_DATA_get_crl_cache_dir(
    CRLMGMT_DATA *cmdat)
{
    return cmdat->crl_cache_dir;
}

void CRLMGMT_DATA_set_crl_cache_dir(
    CRLMGMT_DATA    *cmdat,
    const char      *crl_cache_dir)
{
    cmdat->crl_cache_dir = crl_cache_dir;
}

bool CRLMGMT_DATA_get_use_url(
    CRLMGMT_DATA *cmdat)
{
    return cmdat->use_url;
}

void CRLMGMT_DATA_set_use_url(
    CRLMGMT_DATA    *cmdat,
    bool            use_url)
{
    cmdat->use_url = use_url;
}

bool CRLMGMT_DATA_get_use_issuer(
    CRLMGMT_DATA *cmdat)
{
    return cmdat->use_issuer;
}

void CRLMGMT_DATA_set_use_issuer(
    CRLMGMT_DATA    *cmdat,
    bool            use_issuer)
{
    cmdat->use_issuer = use_issuer;
}

const char *CRLMGMT_DATA_get_note(
    CRLMGMT_DATA *cmdat)
{
    return cmdat->note;
}

void CRLMGMT_DATA_set_note(
    CRLMGMT_DATA    *cmdat,
    const char      *note)
{
    cmdat->note = note;
}

X509_CRL *CRLMGMT_load_crl_by_url(
    const CRLMGMT_DATA *data,
    const char *url,
    int timeout,
    OPTIONAL const X509 *cert,
    OPTIONAL const char *desc)
{
    (void) cert;
    LOG(FL_DEBUG, "url=%s, desc='%s'", url, desc? desc : "-no desc-");

    const char      *effective_uri  = url;
    const size_t    CDP_PROXY_LEN   = 4096;
    char            cdp_proxy[CDP_PROXY_LEN];

    if (data->proxy_url == NULL) {
        LOG(FL_DEBUG, "no cdp proxy given, using original url");
    }
    else {
        LOG(FL_DEBUG, "cdp proxy given, appending original url to proxy %s", data->proxy_url);
        size_t copied = UTIL_safe_string_copy(data->proxy_url, cdp_proxy, CDP_PROXY_LEN, NULL);
        copied += UTIL_safe_string_copy(url_param_url, cdp_proxy + copied, CDP_PROXY_LEN - (size_t)copied, NULL);
        copied += UTIL_url_encode(url, cdp_proxy + copied, CDP_PROXY_LEN - (size_t)copied, NULL);
        effective_uri = cdp_proxy;
    }

    return get_crl_by_download_or_from_cache(data, effective_uri, timeout, desc);
}

X509_CRL *CRLMGMT_load_crl_by_cert(
    const CRLMGMT_DATA *data,
    int timeout,
    OPTIONAL const X509 *cert,
    OPTIONAL const char *desc)
{
    if (data->proxy_url == NULL) {
        LOG(FL_DEBUG, "no cdp proxy given, cannot retrieve a CRL using issuer");
        return NULL;
    }

    const size_t    CDP_PROXY_LEN   = 4096;
    char            cdp_issuer[CDP_PROXY_LEN];

    if (!CDP_get_x509_name(X509_get_issuer_name(cert), cdp_issuer, CDP_PROXY_LEN, XN_FLAG_RFC2253)) {
        LOG(FL_ERR, "could not extract the certificate issuer");
        return NULL;
    }

    char cdp_proxy[CDP_PROXY_LEN];
    LOG(FL_INFO, "cdp proxy given, appending cert issuer to proxy %s", data->proxy_url);
    size_t copied = UTIL_safe_string_copy(data->proxy_url, cdp_proxy, CDP_PROXY_LEN, NULL);
    copied += UTIL_safe_string_copy(url_param_issuer, cdp_proxy + copied, CDP_PROXY_LEN - (size_t)copied, NULL);
    copied += UTIL_url_encode(cdp_issuer, cdp_proxy + copied, CDP_PROXY_LEN - (size_t)copied, NULL);

    return get_crl_by_download_or_from_cache(data, cdp_proxy, timeout, desc);
}

X509_CRL *CRLMGMT_load_crl_cb(
    OPTIONAL void *arg,
    const char *url,
    int timeout,
    OPTIONAL const X509 *cert,
    OPTIONAL const char *desc)
{
    if (desc == NULL) {
        desc = "(no description given)";
    }
    LOG(FL_TRACE, "CRL download callback called using %s", desc);
    if (cert != NULL) {
        LOG_cert_CDP(FL_TRACE, cert);
    }
    const CRLMGMT_DATA *cmdat = (const CRLMGMT_DATA *)arg;
    LOG(FL_DEBUG, "checking certificate for %s", cmdat->note);
    if (url != NULL) {
        return cmdat->use_url ?
            CRLMGMT_load_crl_by_url(cmdat, url, timeout, cert, desc)
            : NULL;
    }
    else if (cert != NULL) {
        return cmdat->use_issuer ?
            CRLMGMT_load_crl_by_cert(cmdat, timeout, cert, desc)
            : NULL;
    }
    LOG(FL_WARN, "callback called with neither url nor cert: %s", desc);
    return NULL;
}
