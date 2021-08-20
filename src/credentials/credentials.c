/** 
* @file credentials.c
* 
* @brief Credentials handling for all components
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

#include "credentials/credentials.h"

#include <stdlib.h>

#include <openssl/engine.h>

#include <credentials/store.h>
#include <credentials/verify.h>
#include <storage/files.h>
#include <storage/files_dv.h>
#include <util/log.h>
#include <util/util.h>

#include <operators.h>

/* this type is part of the genCMPClient API */
struct credentials
{
    OPTIONAL EVP_PKEY* pkey;         /*!< can refer to HW key store via engine */
    OPTIONAL X509* cert;             /*!< related certificate */
    OPTIONAL STACK_OF(X509) * chain; /*!< intermediate/extra certs for cert */
    OPTIONAL char* pwd;              /*!< alternative: password (shared secret) */
    OPTIONAL char* pwdref;           /*!< reference identifying the password */
} /* CREDENTIALS */;


CREDENTIALS* CREDENTIALS_new(OPTIONAL const EVP_PKEY* pkey, const OPTIONAL X509* cert,
                             OPTIONAL const STACK_OF(X509) * chain, OPTIONAL const char* pwd,
                             OPTIONAL const char* pwdref)
{
    const char* pass = pwd;
    if (pwd not_eq 0 and strncmp(pwd, sec_PASS_STR, strlen(sec_PASS_STR)) is_eq 0)
    {
        pass = pwd + strlen(sec_PASS_STR);
    }

    if(pkey not_eq 0 and cert not_eq 0 and X509_check_private_key((X509*)cert, (EVP_PKEY*)pkey) is_eq 0)
    {
        LOG_err("Private key and public key in cert do not match");
        return 0;
    }

    CREDENTIALS* res = OPENSSL_malloc(sizeof(*res));
    if(0 is_eq res)
    {
        LOG(FL_ERR, "Out of memory");
        return 0;
    }

    res->pkey = (EVP_PKEY*)pkey;
    if(pkey not_eq 0)
    {
        if(0 is_eq EVP_PKEY_up_ref(res->pkey))
        {
            res->pkey = 0;
        }
    }
    res->cert = (X509*)cert;
    if(cert not_eq 0)
    {
        if(0 is_eq X509_up_ref(res->cert))
        {
            res->cert = 0;
        }
    }
    res->chain = 0;
    if(chain not_eq 0)
    {
        res->chain = X509_chain_up_ref((STACK_OF(X509)*)chain);
    }
    res->pwd = OPENSSL_strdup(pass);
    res->pwdref = OPENSSL_strdup(pwdref);

    if((pkey not_eq 0 and res->pkey is_eq 0) or (cert not_eq 0 and res->cert is_eq 0)
       or (chain not_eq 0 and res->chain is_eq 0) or (pass not_eq 0 and res->pwd is_eq 0)
       or (pwdref not_eq 0 and res->pwdref is_eq 0))
    {
        CREDENTIALS_free(res);
        LOG(FL_ERR, "Out of memory");
        res = 0;
    }
    return res;
}


EVP_PKEY* CREDENTIALS_get_pkey(const CREDENTIALS* creds)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }
    return creds->pkey;
}

X509* CREDENTIALS_get_cert(const CREDENTIALS* creds)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }
    return creds->cert;
}

STACK_OF(X509) * CREDENTIALS_get_chain(const CREDENTIALS* creds)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }
    return creds->chain;
}

char* CREDENTIALS_get_pwd(const CREDENTIALS* creds)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }
    return creds->pwd;
}

char* CREDENTIALS_get_pwdref(const CREDENTIALS* creds)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }
    return creds->pwdref;
}


bool CREDENTIALS_set_pkey(CREDENTIALS* creds, EVP_PKEY* pkey)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }
    creds->pkey = pkey;
    return true;
}

bool CREDENTIALS_set_cert(CREDENTIALS* creds, X509* cert)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }
    creds->cert = cert;
    return true;
}

bool CREDENTIALS_set_chain(CREDENTIALS* creds, STACK_OF(X509) * chain)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }
    creds->chain = chain;
    return true;
}

bool CREDENTIALS_set_pwd(CREDENTIALS* creds, char* pwd)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }
    creds->pwd = pwd;
    return true;
}

bool CREDENTIALS_set_pwdref(CREDENTIALS* creds, char* pwdref)
{
    if(creds is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }
    creds->pwdref = pwdref;
    return true;
}


void CREDENTIALS_free(OPTIONAL CREDENTIALS* creds)
{
    if(creds not_eq 0)
    {
        EVP_PKEY_free(creds->pkey);
        X509_free(creds->cert);
        sk_X509_pop_free(creds->chain, X509_free);
        UTIL_cleanse(creds->pwd);
        OPENSSL_free(creds->pwd);
        OPENSSL_free(creds->pwdref);
        OPENSSL_free(creds);
    }
}


/**
 * @brief map component identifier to file (path) name;
 * @param cid component credentials identifier
 * @return allocated relative file path name. Must be free()ed by caller. 0 on failure.
 */
static char* component_creds_id2file(component_creds_id cid)
{
    char* res = 0;

    if(cid is_eq 0)
    {
        LOG_err("null pointer argument");
        return res;
    }

    const char* path = getenv(CREDS_DIR_ENV);
    if(path is_eq 0)
    {
        path = CREDS_DIR_DEFAULT;
    }

    res = malloc(strlen(path) + strlen("/") + strlen(cid) + strlen(".p12") + 1);
    if(res is_eq 0)
    {
        LOG_err("out of memory");
        return 0;
    }

    sprintf(res, "%s/%s.p12", path, cid);
    return res;
}


CREDENTIALS* CREDENTIALS_load(OPTIONAL const char* certs, OPTIONAL const char* key, OPTIONAL const char* source,
                              OPTIONAL const char* desc)
{
    const char* engine = 0;
    EVP_PKEY* pkey = 0;
    X509* cert = 0;
    STACK_OF(X509)* chain = 0;

    if(source not_eq 0 and strncmp(source, sec_ENGINE_STR, strlen(sec_ENGINE_STR)) is_eq 0)
    {
        engine = source + strlen(sec_ENGINE_STR);
        source = 0;
    }

    if(not FILES_load_credentials(certs, key, FORMAT_PEM /* overridden by PKCS12 if certs=key */, source, engine, desc,
                                  &pkey, &cert, &chain))
    {
        return 0;
    }
    CREDENTIALS* res = CREDENTIALS_new(pkey, cert, chain, 0, 0);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(chain, X509_free);
    return res;
}


CREDENTIALS* CREDENTIALS_load_dv(OPTIONAL const char* certs, OPTIONAL const char* key, OPTIONAL uta_ctx* ctx,
                                 OPTIONAL const char* desc)
{
    CREDENTIALS* creds = 0;
    char pass_buf[strlen(sec_PASS_STR) + MAX_UTA_PASS_LEN];
    strcpy(pass_buf, sec_PASS_STR);
    if(FILES_get_pass_dv(pass_buf + strlen(sec_PASS_STR), ctx, key, false /* read */, desc))
    {
        creds = CREDENTIALS_load(certs, key, pass_buf, desc);
    }
    UTIL_erase_mem(pass_buf, sizeof(pass_buf));
    return creds;
}

typedef struct update_cb_node
{
    struct update_cb_node* next;
    const char* tag;
    CREDENTIALS_update_cb* fn;
} update_cb_node;

static struct update_cb_node update_cb_head /*!< this struct variable is shared between threads */
    = {0, 0, 0};


/* find node just before the one related to the given tag assuming mutex */
/*! @todo does not work if callers use different secutils instances */
static update_cb_node* find_update_cb(const char* tag)
{
    update_cb_node* prev = &update_cb_head;
    while(prev->next not_eq 0 and strcmp(prev->next->tag, tag) not_eq 0)
    {
        prev = prev->next;
    }
    return prev;
}


bool CREDENTIALS_save(const CREDENTIALS* creds, OPTIONAL const char* certs, OPTIONAL const char* key,
                      OPTIONAL const char* source, OPTIONAL const char* desc)
{
    EVP_PKEY* pkey = 0;

    if(creds is_eq 0 or (certs is_eq 0 and key is_eq 0))
    {
        LOG_err("null pointer argument");
        return false;
    }
    if(source is_eq 0 or strncmp(source, sec_ENGINE_STR, strlen(sec_ENGINE_STR)) not_eq 0)
    {
        pkey = creds->pkey;
    } else {
        /* source refers to engine, so cannot save private key */
        source = 0;
    }

    file_format_t format = key not_eq 0 and strcmp(key, certs) is_eq 0 ? FORMAT_PKCS12 : FORMAT_PEM;
    bool res = FILES_store_credentials(pkey, creds->cert, creds->chain, key, certs, format, source, desc);
    if(0 is_eq res)
    {
        LOG(FL_ERR, "Could not save %s to %s and %s", desc not_eq 0 ? desc : "credentials", certs, key);
        return false;
    }

    /*! @todo make thread safe, e.g., by using some mutex on update_cb_head */
    update_cb_node* prev = find_update_cb(desc /* tag */);
    if(prev->next not_eq 0)
    {
        (*prev->next->fn)(desc /* tag */);
    }
    return true;
}


bool CREDENTIALS_save_dv(const CREDENTIALS* creds, OPTIONAL const char* certs, OPTIONAL const char* key,
                         OPTIONAL uta_ctx* ctx, OPTIONAL const char* desc)
{
    bool res = false;
    char pass_buf[strlen(sec_PASS_STR) + MAX_UTA_PASS_LEN];
    strcpy(pass_buf, sec_PASS_STR);
    if(FILES_get_pass_dv(pass_buf + strlen(sec_PASS_STR), ctx, key, true /* write */, desc))
    {
        res = CREDENTIALS_save(creds, certs, key, pass_buf, desc);
    }
    UTIL_erase_mem(pass_buf, sizeof(pass_buf));
    return res;
}


CREDENTIALS* CREDENTIALS_get(component_creds_id cid)
{
    char* filename = component_creds_id2file(cid);
    if(filename is_eq 0)
    {
        return 0;
    }

    CREDENTIALS* creds = CREDENTIALS_load(filename, filename, 0 /* pass */, cid /* desc */);
    free(filename);
    return creds;
}

bool CREDENTIALS_store(component_creds_id cid, const CREDENTIALS* creds)
{
    char* filename = component_creds_id2file(cid);
    if(filename is_eq 0)
    {
        return false;
    }

    bool res = CREDENTIALS_save(creds, filename, filename, 0 /* pass */, cid /* desc */);
    free(filename);
    return res;
}


bool CREDENTIALS_register_update_cb(const char* tag, OPTIONAL CREDENTIALS_update_cb* fn)
{
    if(tag is_eq 0)
    {
        return false;
    }
    /*! @todo must be made thread safe by using some mutex on update_cb_head */
    update_cb_node* prev = find_update_cb(tag);
    if(fn not_eq 0)
    {
        if(prev->next not_eq 0)
        {
            prev->next->fn = fn;
        }
        else
        {
            update_cb_node* new = OPENSSL_malloc(sizeof(*new));
            if(new is_eq 0)
            {
                LOG_err("Out of memory");
                return false;
            }
            new->next = 0;
            new->tag = tag;
            new->fn = fn;
            prev->next = new;
        }
    }
    else
    {
        if(prev->next not_eq 0)
        {
            update_cb_node* curr = prev->next;
            prev->next = curr->next;
            OPENSSL_free(curr);
        }
        else
        {
            LOG(FL_WARN, "No credentials update cb entry to clear for tag = %s", tag);
        }
    }
    return true;
}
