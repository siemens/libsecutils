/** 
* @file trusted.c
* 
* @brief Trust anchor configuration
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

#include "credentials/trusted.h"

#include <credentials/store.h>
#include <storage/files.h>
#include <storage/files_icv.h>
#include <util/log.h>

#include "secutils/operators.h"

static const char* config_file(void)
{
    const char* file = getenv(TRUST_CONFIG_ENV);
    if (file is_eq 0)
    {
        file = TRUST_CONFIG_DEFAULT;
    }
    return file;
}

static X509_STORE* load_trusted(component_creds_id cid, STACK_OF(CONF_VALUE) * nval, const char* opt_trusted, const char* desc,
                                OPTIONAL uta_ctx* ctx)
{
    X509_STORE* ts = 0;
    if(opt_trusted not_eq 0)
    {
        ts = STORE_load_trusted(opt_trusted, desc, ctx);
        if(0 is_eq ts)
        {
            return 0;
        }
    }
    int i = 0;
    int n_trusted = 0;
    const int n_entries = sk_CONF_VALUE_num(nval);
    for(i = 0; i < n_entries; i++)
    {
        CONF_VALUE* cnf = sk_CONF_VALUE_value(nval, i);
        if(0 is_eq strncmp(cnf->name, TRUST_CONFIG_ENTRY_TRUSTED,
                           strlen(TRUST_CONFIG_ENTRY_TRUSTED)))
        {
            if(not STORE_load_more(&ts, cnf->value, FORMAT_PEM, 0 /* ignore load errors */, ctx))
            {
                return 0;
            }
            else
            {
                n_trusted++;
            }
        }
    }
    if(0 is_eq opt_trusted and 0 is_eq n_trusted)
    {
        LOG(FL_ERR,
            "no \"%s = ...\" entry and no \"%s.<n> = ...\" entries found "
            "for '[%s]' section in trust config file '%s'",
            TRUST_CONFIG_ENTRY_TRUSTED, TRUST_CONFIG_ENTRY_TRUSTED, cid, config_file());
        STORE_free(ts);
        ts = 0;
    }
    return ts;
}

X509_STORE* CREDENTIALS_get_trust_store(component_creds_id cid, OPTIONAL X509_VERIFY_PARAM* vpm, OPTIONAL uta_ctx* ctx)
{
    CONF* conf = 0;
    STACK_OF(CONF_VALUE) * nval;
    int i = 0;
    X509_STORE* ts = 0;
    STACK_OF(X509_CRL)* crls = 0;
    const char* opt_trusted = 0;
    const char* opt_crls = 0;
    opt_t vars[3];
    vars[0] = (opt_t){TRUST_CONFIG_ENTRY_TRUSTED, OPT_TXT, {.txt = 0}, {&opt_trusted}, ""};
    vars[1] = (opt_t){TRUST_CONFIG_ENTRY_CRLS, OPT_TXT, {.txt = 0}, {&opt_crls}, ""};
    vars[2] = (opt_t){0};

    /* untrusted intermediate certs that could be helpful for path completion
       during verification
       are not loaded, anyway they would be too hard to configure statically */

    if(0 is_eq cid)
    {
        cid = TRUST_CONFIG_SECTION_DEFAULT;
        LOG(FL_WARN, "No component identifier given, using '%s'", cid);
    }
    const int buflen = 81;
    char desc[buflen];
    snprintf(desc, buflen, "trust store contents for component '%s'", cid);

    conf = CONF_load_options(ctx, config_file(), cid, vars);
    if(0 is_eq conf)
    {
        LOG(FL_ERR, "Could not read config file section for trust store of %s", cid);
        goto err;
    }
    nval = NCONF_get_section(conf, cid);

    ts = load_trusted(cid, nval, opt_trusted, desc, 0 /* no ICV check */);
    if(0 is_eq ts)
    {
        goto err;
    }

    if(0 not_eq opt_crls)
    {
        const int crls_timeout = -1; /* default */
        crls = FILES_load_crls_autofmt(opt_crls, FORMAT_PEM, crls_timeout, desc);
        if(0 is_eq crls)
        {
            LOG(FL_ERR, "loading CRL(s) for use in trust store of %s", cid);
            goto err;
        }
    }
    const bool full_chain = false;
    const bool use_CDPs = false;
    const char *CRLs_url = 0;
    const int crls_timeout = -1; /* default */
    const bool use_AIAs = false;
    const char *OCSP_url = 0;
    const int ocsp_timeout = -1; /* default */
    const bool try_stapling = (use_AIAs or OCSP_url not_eq 0) and OPENSSL_VERSION_NUMBER >= 0x1010001fL;
    int res = STORE_set_parameters(ts, vpm, full_chain, try_stapling, crls,
                                   use_CDPs, CRLs_url, crls_timeout,
                                   use_AIAs, OCSP_url, ocsp_timeout);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    if(0 is_eq res)
    {
        LOG(FL_ERR, "setting parameters of trust store of %s", cid);
        goto err;
    }
    const int n_entries = sk_CONF_VALUE_num(nval);
    for(i = 0; i < n_entries; i++)
    {
        CONF_VALUE* cnf = sk_CONF_VALUE_value(nval, i);
        if(0 is_eq strncmp(cnf->name, TRUST_CONFIG_ENTRY_CRLS, strlen(TRUST_CONFIG_ENTRY_CRLS)))
        {
            crls = FILES_load_crls_autofmt(cnf->value, FORMAT_PEM, crls_timeout, desc);
            if(0 is_eq crls)
            {
                LOG(FL_ERR, "loading CRL(s) for use in trust store of %s", cid);
                goto err;
            }
            if(0 is_eq STORE_add_crls(ts, crls))
            {
                LOG(FL_ERR, "filling trust store with trusted cert(s) of %s", cid);
                goto err;
            }
            sk_X509_CRL_pop_free(crls, X509_CRL_free);
        }
    }

    NCONF_free(conf);
    return ts;

err:
    NCONF_free(conf);
    STORE_free(ts);
    return 0;
}
