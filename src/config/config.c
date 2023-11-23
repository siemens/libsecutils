/** 
* @file config.c
* 
* @brief OpenSSL-style configuration file use (also used for DV files)
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

#include <util/log.h>
#include <config/config.h>

#include <openssl/x509v3.h>

#include <credentials/verify.h>
#include <storage/files_icv.h>

#include <operators.h>

/* adapted from OpenSSL:apps/include/apps.h */
static opt_t vpm_opts[] = { OPT_V_OPTIONS, OPT_END };

/* Parse a long integer, put it into *result; return false on failure */
static bool parse_long(const char* str, long* result)
{
    int errno_bak = errno;
    long res = 0;
    char* endp = 0;

    if(str is_eq 0 or result is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }
    errno = 0;
    res = strtol(str, &endp, 0);
    if(*endp not_eq '\0' or endp is_eq str
       or ((res is_eq LONG_MAX or res is_eq LONG_MIN) and errno is_eq ERANGE)
       or (res is_eq 0 and errno not_eq 0))
    {
        LOG(FL_ERR, "Can't parse \"%s\" as a long number", str);
        errno = errno_bak;
        return false;
    }
    *result = res;
    errno = errno_bak;
    return true;
}

CONF* CONF_load_config(OPTIONAL ossl_unused uta_ctx* ctx, const char* file)
{
    CONF* conf = 0;

    if(0 not_eq file
#ifdef SECUTILS_USE_ICV
       and FILES_check_icv(ctx, file) not_eq 0
#endif
      )
    {
        long errorline = -1; /* line in the config file where a failure occurred */
#ifdef DEBUG
        LOG(FL_ERR, "using configuration from '%s'", file);
#endif
        conf = NCONF_new(NCONF_default());
        if(conf is_eq 0)
        {
            LOG(FL_ERR, "out of memory");
            return 0;
        }
        if(NCONF_load(conf, file, &errorline) <= 0)  /* load the config file */
        {
            if(errorline <= 0)
            {
                LOG(FL_ERR, "cannot open the config file '%s'", file);
            }
            else
            {
                LOG(FL_ERR, "error on line %ld in config file '%s'", errorline, file);
            }
            NCONF_free(conf);
            conf = 0;
        }
    }
    return conf;
}


#define SECTION_NAME_MAX 40 /* max length of section name */
static char opt_item[SECTION_NAME_MAX+1];
/* get previous name from a comma-separated list of names */
static const char* prev_item(const char* opt, const char* end)
{
    if(end is_eq opt)
    {
        return 0;
    }
    const char* beg = end;
    while(beg not_eq opt and beg[-1] not_eq ',' and not isspace(beg[-1]))
    {
        beg--;
    }
    int len = (int)(end - beg);
    if(len > SECTION_NAME_MAX)
    {
        len = SECTION_NAME_MAX;
    }
    if(len not_eq 0)
    {
        strncpy(opt_item, beg, len);
    }
    opt_item[len] = '\0';
    if(end - beg > SECTION_NAME_MAX)
    {
        LOG(FL_WARN,
            "using only first %d characters of section name starting with \"%s\"",
            SECTION_NAME_MAX, opt_item);
    }
    while(beg not_eq opt and (beg[-1] is_eq ',' or isspace(beg[-1])))
    {
        beg--;
    }
    return beg;
}

/* get str value for name from a comma-separated hierarchy of config sections */
static const char* conf_get_string(const CONF* src_conf, const char* sections,
                                   const char* name)
{
    const char* end = sections + strlen(sections);
    while((end = prev_item(sections, end)) not_eq 0)
    {
        const char* res;
        if((res = NCONF_get_string(src_conf, opt_item, name)) not_eq 0)
        {
            return res;
        }
    }
    return 0;
}

/* get long val for name from a comma-separated hierarchy of config sections */
static bool conf_get_number_e(const CONF* conf_, const char* sections,
                              const char* name, long* p_result)
{
    const char* str = conf_get_string(conf_, sections, name);
    return str is_eq 0 ? false : parse_long(str, p_result);
}

bool CONF_update_vpm(CONF* conf, const char* sections, X509_VERIFY_PARAM* vpm)
{
    opt_t* vopt;
    if(conf is_eq 0 or sections is_eq 0 or vpm is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }
    for(vopt = vpm_opts; vopt->name not_eq 0; vopt++)
    {
        static const char* val;
        if((val = conf_get_string(conf, sections, vopt->name)) not_eq 0)
        {
            if(vopt->type is_eq OPT_BOOL and UTIL_atoint(val) is_eq 0)
            {
                continue; /* OPT_update_vpm can only set option positively */
            }
            if(not OPT_update_vpm(vopt->default_value.num, val, vpm))
            {
                return false;
            }
        }
        else
        {
            ERR_clear_error(); /* option not provided */
        }
    }
    return true;
}


bool CONF_read_options(CONF* conf, const char* sections, opt_t* opt)
{
    const char* str;
    long val = 0;
    if(conf is_eq 0 or sections is_eq 0 or opt is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }

    for(; opt->name not_eq 0; opt++)
    {
        if(opt->varref_u.txt is_eq 0)
        {
            continue; /* skip if no variable reference given */
        }
        switch(opt->type)
        {
            case OPT_NUM:
                /* restores default value if empty string is given */
                str = conf_get_string(conf, sections, opt->name);
                if(str not_eq 0)
                {
                    if(str[0] is_eq '\0')
                    {
                        *opt->varref_u.num = opt->default_value.num;
                        break;
                    }
                    /* stores the value from the key opt->name into the opt->varref_u.num */
                    if(not conf_get_number_e(conf, sections, opt->name, opt->varref_u.num))
                    {
                        return false;
                    }
                }
                else
                {
                    ERR_clear_error(); /* option not provided */
                }
                break;
            case OPT_TXT:
                /* stores the value from the key opt->name in opt->varref_u.txt */
                str = conf_get_string(conf, sections, opt->name);
                if(str not_eq 0)
                {
                    *opt->varref_u.txt = str[0] is_eq '\0' ? opt->default_value.txt : str;
                }
                else
                {
                    ERR_clear_error(); /* option not provided */
                }
                break;
            case OPT_BOOL:
                /* restores default value if empty string is given */
                str = conf_get_string(conf, sections, opt->name);
                if(str not_eq 0)
                {
                    if(str[0] is_eq '\0')
                    {
                        *opt->varref_u.bit = opt->default_value.bit;
                        break;
                    }
                    if(not conf_get_number_e(conf, sections, opt->name, &val))
                    {
                        return false;
                    }
                    if(val < 0 or val > 1)
                    {
                        LOG(FL_ERR, "value %ld is out of range for Boolean; must be 0 or 1", val);
                        return false;
                    }
                    *opt->varref_u.bit = (int)val;
                }
                else
                {
                    ERR_clear_error(); /* option not provided */
                }
                break;
            default:
                LOG(FL_ERR, "internal: unsupported type '%d' for option '%s'", opt->type, opt->name);
                return false;
                break;
        }
    }

    return true;
}


CONF* CONF_load_options(OPTIONAL uta_ctx* ctx, const char* file,
                        const char* sections, OPTIONAL opt_t* opts)
{
    if(sections is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }
    CONF* conf = CONF_load_config(ctx, file);
    if(0 is_eq conf)
    {
        return 0;
    }

    const char *end = sections + strlen(sections);
    while((end = prev_item(sections, end)) not_eq 0)
    {
        if(0 is_eq NCONF_get_section(conf, opt_item))
        {
            LOG(FL_ERR,
                "no [%s] section found in config file '%s'", opt_item, file);
            /* could also issue just a warning, adding the hint that 
               thus will use just [default] and unnamed section if present */
            goto err;
        }
    }

    if(opts is_eq 0 or CONF_read_options(conf, sections, opts) not_eq 0)
    {
        return conf;
    }
err:
    NCONF_free(conf);
    return 0;
}


/* caller must free string */
char* CONF_load_string(OPTIONAL uta_ctx* ctx, const char* file,
                       const char* sections, const char* key)
{
    const char* val = 0;
    char* retval = 0;
    if(key is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return 0;
    }

    opt_t opts[] = {{key, OPT_TXT, {.txt = 0}, {&val}, ""}, {0}};
    CONF* conf = CONF_load_options(ctx, file, sections, opts);
    if(0 is_eq conf)
    {
        LOG(FL_ERR, "could not load the [%s] sections of file '%s'", sections, file);
        return 0;
    }
    if(0 is_eq val)
    {
        LOG(FL_ERR, "no '%s = ...' entry found in [%s] sections of file '%s'", key, sections, file);
    }
    else
    {
        retval = OPENSSL_strdup(val);
    }

    NCONF_free(conf);
    return retval;
}
