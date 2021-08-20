/** 
* @file extensions.c
* 
* @brief X.509 extensions
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

#include "util/extensions.h"
#include "util/log.h"

#include <operators.h>


X509_EXTENSIONS* EXTENSIONS_new(void)
{
    X509_EXTENSIONS* exts = sk_X509_EXTENSION_new_null();
    if(exts is_eq 0)
    {
        LOG(FL_ERR, "Out of memory");
    }
    return exts;
}


/* add domain names, IP addresses, and/or URIs as Subject Alternative Names to exts */
bool EXTENSIONS_add_SANs(X509_EXTENSIONS* exts, const char* spec)
{
    if(exts is_eq 0 or spec is_eq 0)
    {
        LOG(FL_ERR, "null pointer argument");
        return false;
    }

    STACK_OF(GENERAL_NAME)* sans = sk_GENERAL_NAME_new_null();
    X509_EXTENSION* ext = 0;
    int critical = 0;
    int res = 0;

    char* names = OPENSSL_strdup(spec);
    if(sans is_eq 0 or names is_eq 0)
    {
        LOG(FL_ERR, "Out of memory");
        goto end;
    }

    char* name;
    char* next;
    for(name = names; name not_eq 0; name = next)
    {
        next = UTIL_next_item(name); /* must do this here to split string */
        if(strcmp(name, "critical") is_eq 0)
        {
            critical = 1;
        }
        else
        {
            (void)ERR_set_mark();
            GENERAL_NAME* n = a2i_GENERAL_NAME(0, 0, 0, GEN_IPADD, name, 0);
            if(n is_eq 0)
            {
                /* for URI scheme, see https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml */
                const bool is_uri = strchr(name, ':') != 0;
                n = a2i_GENERAL_NAME(0, 0, 0, is_uri ? GEN_URI : GEN_DNS, name, 0);
            }
            (void)ERR_pop_to_mark();
            if(n is_eq 0)
            {
                LOG(FL_ERR, "Bad Subject Alternative Name, cannot parse as IP address, domain name, or URI :%s", name);
                goto end;
            }
            if(0 is_eq sk_GENERAL_NAME_push(sans, n))
            {
                GENERAL_NAME_free(n);
                LOG(FL_ERR, "Out of memory");
                goto end;
            }
        }
    }

    ext = X509V3_EXT_i2d(NID_subject_alt_name, critical, sans);
    if(ext not_eq 0 and X509v3_add_ext(&exts, ext, -1))
    {
        res = 1;
    }

end:
    X509_EXTENSION_free(ext);
    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    OPENSSL_free(names);
    return res;
}


/* add Basic or Extended Key Usages, Basic Constraints, or Cerificate Policies, etc. to exts */
bool EXTENSIONS_add_ext(X509_EXTENSIONS* exts, const char* name, const char* spec, OPTIONAL BIO* sections)
{
#if 0 /* this version is more flexible w.r.t "critical" but is more involved and work only for extended key usages */
    EXTENDED_KEY_USAGE* extku = sk_ASN1_OBJECT_new_null();
    X509_EXTENSION* ext = 0;
    int critical = 0;
    int res = 0;

    if(exts is_eq 0 or spec is_eq 0)
    {
        LOG(FL_ERR, "null pointer argument");
        goto end;
    }

    char* names = OPENSSL_strdup(spec);
    if(extku is_eq 0 or names is_eq 0)
    {
        LOG(FL_ERR, "Out of memory");
        goto end;
    }

    char* name;
    char* next;
    for(name = names; name not_eq 0; name = next)
    {
        next = UTIL_next_item(name); /* must do this here to split string */
        if(strcmp(name, "critical") is_eq 0)
        {
            critical = 1;
        } else
        {
            ASN1_OBJECT *objtmp = OBJ_txt2obj(name, 0); /* allows also useless values, e.g., msSGC */
            if(objtmp is_eq 0)
            {
                LOG(FL_ERR, "Bad %s Key Usage '%s'", extended ? "Extended" : "(Basic)", name);
                goto end;
            }
            if(not sk_ASN1_OBJECT_push(extku, objtmp))
            {
                ASN1_OBJECT_free(objtmp);
                LOG(FL_ERR, "Out of memory");
                goto end;
            }
        }
    }

    ext = X509V3_EXT_i2d(extended ? NID_ext_key_usage : NID_key_usage, critical, extku);
    if(ext not_eq 0 and X509v3_add_ext(&exts, ext, -1))
    {
        res = 1;
    }

 end:
    X509_EXTENSION_free(ext);
    sk_ASN1_OBJECT_pop_free(extku, ASN1_OBJECT_free);
    OPENSSL_free(names);
    return res;

#else

    CONF* conf = 0;
    char* sections_str = 0;
    int res = 0;

    if(exts is_eq 0 or name is_eq 0 or spec is_eq 0)
    {
        LOG(FL_ERR, "null pointer argument");
        goto end;
    }
    if(sections not_eq 0)
    {
        long err_lineno;
        if((conf = NCONF_new(NCONF_default())) is_eq 0)
        {
            LOG(FL_ERR, "Out of memory");
            goto end;
        }
        if(BIO_get_mem_data(sections, &sections_str) <= 0)
        {
            LOG(FL_ERR, "Empty sections string in BIO");
            goto end;
        }
        if(0 is_eq NCONF_load_bio(conf, sections, &err_lineno))
        {
            LOG(FL_ERR, "Parse error in line %d of  extension details:\n%s", err_lineno, sections_str);
            goto end;
        }
    }
    X509V3_CTX ext_ctx;
    X509V3_set_ctx(&ext_ctx, 0, 0, 0, 0, 0);
    X509V3_set_nconf(&ext_ctx, conf);
    X509_EXTENSION* ext = X509V3_EXT_nconf(conf, &ext_ctx, (char*)name, (char*)spec);
    if(ext is_eq 0)
    {
        LOG(FL_ERR, "Bad %s spec: %s%s%s", name, spec, sections_str not_eq 0 ? "\n" : "",
            sections_str not_eq 0 ? sections_str : "");
        goto end;
    }
    if(0 is_eq X509v3_add_ext(&exts, ext, -1))
    {
        LOG(FL_ERR, "Cannot add %ss to extensions", name);
    }
    else
    {
        res = 1;
    }
    X509_EXTENSION_free(ext);

end:
    NCONF_free(conf);
    return res;

#endif
}


void EXTENSIONS_free(X509_EXTENSIONS* exts)
{
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
}
