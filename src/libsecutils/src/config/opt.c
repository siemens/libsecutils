/** 
* @file opt.c
* 
* @brief OpenSSL-style command-line options, used for configuring applications
*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
* @copyright Copyright (c) Siemens Mobility GmbH, 2021
*
* @author David von Oheimb <david.von.oheimb@siemens.com>
*
* This work is licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <config/opt.h>
#include <util/log.h>

#include <inttypes.h> /* for strtoimax on Linux */

#include <operators.h>

const char OPT_more_str[] = "-M";
const char OPT_section_str[] = "-S";
const char OPT_param_str[] = "-M";

/* adapted from OpenSSL:apps/lib/opt.c */
/* return a string describing the parameter type */
static const char* valtype2param(const opttype_t type)
{
    switch(type)
    {
        case OPT_TXT:
            return "str";
        case OPT_NUM:
            return "num";
        case OPT_BOOL:
            return "";
        default:
            LOG(FL_ERR, "unexpected option type");
            return 0;
    }
}

/* adapted from OpenSSL:apps/lib/opt.c */
#define SIZE_START (80 + 1)
static void opt_print(BIO* bio, const opt_t* options, int doingparams, int width)
{
    const char* help;
    char start[SIZE_START];
    char* p;

    help = options->help_str ? options->help_str : "(No additional info)";

    /* pad out prefix */
    memset(start, ' ', sizeof(start) - 1);
    start[sizeof(start) - 1] = '\0';

    if(options->name is_eq OPT_more_str)
    {
        /* continuation of previous line; pad and print */
        start[width] = '\0';
        BIO_printf(bio, "%s  %s\n", start, help);
        return;
    }

    if(options->name is_eq OPT_section_str)
    {
        /* print section in new line */
        BIO_printf(bio, "\n%s\n", help);
        return;
    }

    /* build up the "-flag [param]" part */
    p = start;
    *p++ = ' ';
    if(not doingparams)
    {
        *p++ = '-';
    }
    if(options->help_str not_eq 0)
    {
        p += strlen(strcpy(p, options->name));
    }
    else
    {
        *p++ = '*';
    }

    const char *param_desc = valtype2param(options->type);
    if(param_desc not_eq 0)
    {
        *p++ = ' ';
        p += strlen(strcpy(p, param_desc));
    }
    *p = ' ';
    if((int)(p - start) >= OPT_MAX_HELP_COL1_WIDTH)
    {
        *p = '\0';
        BIO_printf(bio, "%s\n", start);
        memset(start, ' ', sizeof(start));
    }

    /* Finally print "-flag [param] help string" part */
    start[width] = '\0';
    BIO_printf(bio, "%s  %s\n", start, help);
}

/* adapted from OpenSSL:apps/lib/opt.c */
bool OPT_help(opt_t options[], BIO* bio)
{
    opt_t* o = options;
    int i;
    int width = 5;

    if(options is_eq 0 or bio is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }

    /* find the widest option name and parameter info */
    for(; options->name not_eq 0; options++)
    {
        if(options->varref_u.bit not_eq 0
                or options->varref_u.num not_eq 0
                or options->varref_u.txt not_eq 0)
        {
            i = 2 + (int)strlen(options->name);
            const char *param_desc = valtype2param(options->type);
            if(param_desc not_eq 0)
            {
                i += 1 + (int)strlen(param_desc);
            }
            if(i < OPT_MAX_HELP_COL1_WIDTH and i > width)
            {
                width = i;
            }
            if(i > SIZE_START)
            {
                LOG(FL_ERR, "help message length exceeds buffer size %d > %d", i, SIZE_START);
            }
        }
    }

    /* now let's print */
    if(options->name not_eq 0 and strcmp(options->name, OPT_section_str) not_eq 0)
    {
        BIO_printf(bio, "\nValid options are:\n");
    }
    int sawparams = 0;
    for(options = o; options->name not_eq 0; options++)
    {
        if (options->name is_eq OPT_param_str)
            sawparams = 1;
        opt_print(bio, options, sawparams, width);
    }
    return true;
}

/* adapted from OpenSSL:apps/lib/opt.c */
/* initialize options with corresponding default values */
bool OPT_init(opt_t options[])
{
    if(options is_eq 0)
    {
        LOG(FL_ERR, "null argument");
        return false;
    }

    for(; options->name not_eq 0; options++)
    {
        if(options->varref_u.txt not_eq 0)
        {
            switch(options->type)
            {
            case OPT_TXT:
                *options->varref_u.txt = options->default_value.txt;
                break;
            case OPT_NUM:
                *options->varref_u.num = options->default_value.num;
                break;
            case OPT_BOOL:
                *options->varref_u.bit = options->default_value.bit;
                break;
            default:
                LOG(FL_ERR, "unexpected option type");
                return false;
            }
        }
    }
    return true;
}


/* read CLI arguments, updating option variables and cert verifications options */
int OPT_read(opt_t options[], char** argv, X509_VERIFY_PARAM* vpm)
{
    const char* opt;
    const char* arg;
    int i;

    while((opt = *argv) not_eq 0)
    {
        if(*opt not_eq '-')
        {
            LOG(FL_ERR, "Option '%s' does not start with '-'", opt);
            return 0;
        }
        /* chop '-' and any following '-' */
        if(*++opt is_eq '-')
        {
            opt++;
        }
        argv++;

        i = 0;
        while(options[i].name not_eq 0 and strcmp(opt, options[i].name) not_eq 0)
        {
            i++;
        }

        if(options[i].name is_eq 0)
        {
            LOG(FL_ERR, "Unknown option '-%s'", opt);
            return 0;
        }
        arg = 0;
        if(options[i].type not_eq OPT_BOOL)
        {
            /* non-Boolean option must have an argument */
            if((arg = *argv) is_eq 0)
            {
                LOG(FL_ERR, "Option '-%s' needs an argument", opt);
                return 0;
            }
            argv++;
        }
        if(options[i].varref_u.txt is_eq 0) /* not a regular variable */
        {
            if(options[i].default_value.num < 0) /* typically used for "help" */
            {
                return options[i].default_value.num;
            }
            if(options[i].default_value.num > 0) /* cert verification option */
            {
                if(not OPT_update_vpm(options[i].default_value.num, arg, vpm))
                    return 0;
            }
            /* else header or option to be ignored/skipped */
        }
        else
        {
            switch(options[i].type)
            {
            case OPT_TXT:
                *options[i].varref_u.txt =
                    *arg is_eq '\0' ? options[i].default_value.txt : arg;
                break;
            case OPT_NUM:
                *options[i].varref_u.num =
                    *arg is_eq '\0' ? options[i].default_value.num : UTIL_atoint(arg);
                if(*options[i].varref_u.num is_eq INT_MIN)
                {
                    LOG(FL_ERR, "Cannot parse '-%s' option argument '%s' as integer", opt, arg);
                    return 0;
                }
                break;
            case OPT_BOOL:
                *options[i].varref_u.bit = true;
                break;
            default:
                LOG(FL_ERR, "Internal error: unexpected '-%s' option type %d", opt, options[i].type);
                return 0;
            }
        }
    }
    return 1;
}

/* adapted from OpenSSL:apps/lib/opt.c */
/* Parse an intmax_t, put it into *result; return false on failure */
static bool opt_intmax(const char* str, intmax_t* result, const char* desc)
{
    int errno_bak = errno;
    intmax_t res = 0;
    char* endp = 0;

    errno = 0;
    res = strtoimax(str, &endp, 0);
    if(*endp not_eq '\0' or endp is_eq str
       or ((res is_eq INTMAX_MAX or res is_eq INTMAX_MIN) and errno is_eq ERANGE)
       or (res is_eq 0 and errno not_eq 0))
    {
        LOG(FL_ERR, "Cannot parse \"%s\" as an intmax number for %s", str, desc);
        errno = errno_bak;
        return false;
    }
    *result = res;
    errno = errno_bak;
    return true;
}

/* adapted from opt_verify() in OpenSSL:apps/lib/opt.c */
bool OPT_update_vpm(int opt, const char* val, X509_VERIFY_PARAM* vpm)
{
    int i = 0;
    intmax_t t = 0;
    ASN1_OBJECT* otmp = 0;
    X509_PURPOSE* xptmp = 0;
    const X509_VERIFY_PARAM* vtmp = 0;

    if(vpm is_eq 0)
    {
        LOG_err("null pointer argument for vpm");
        return false;
    }
    if(opt <= OPT_V__FIRST or opt >= OPT_V__LAST)
    {
        LOG(FL_ERR, "Internal error - option ID out of range: %d", opt);
        return false;
    }

    /*
     * We pass opt as an int but cast it to vpm_opt so that all the
     * items in the OPT_V_ENUM enumeration are caught; this makes -Wswitch
     * in gcc do the right thing.
     */
    switch((vpm_opt)opt)
    {
        case OPT_V__FIRST:
        case OPT_V__LAST:
            return false;
        case OPT_V_POLICY:
            otmp = OBJ_txt2obj(val, 0);
            if(otmp is_eq 0)
            {
                LOG(FL_ERR, "Invalid Policy %s", val);
                return false;
            }
            X509_VERIFY_PARAM_add0_policy(vpm, otmp);
            break;
        case OPT_V_PURPOSE:
            /* purpose name -> purpose index */
            i = X509_PURPOSE_get_by_sname((char *)val);
            if(i < 0)
            {
                LOG(FL_ERR, "Invalid purpose %s", val);
                return false;
            }

            /* purpose index -> purpose object */
            xptmp = X509_PURPOSE_get0(i);

            /* purpose object -> purpose value */
            i = X509_PURPOSE_get_id(xptmp);

            if(0 is_eq X509_VERIFY_PARAM_set_purpose(vpm, i))
            {
                LOG(FL_ERR, "Internal error setting purpose %s", val);
                return false;
            }
            break;
        case OPT_V_VERIFY_NAME:
            vtmp = X509_VERIFY_PARAM_lookup(val);
            if(vtmp is_eq 0)
            {
                LOG(FL_ERR, "Invalid verify name %s", val);
                return false;
            }
            X509_VERIFY_PARAM_set1(vpm, vtmp);
            break;
        case OPT_V_VERIFY_DEPTH:
            i = UTIL_atoint(val);
            if(i >= 0)
                X509_VERIFY_PARAM_set_depth(vpm, i);
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        case OPT_V_VERIFY_AUTH_LEVEL:
            i = UTIL_atoint(val);
            if(i >= 0)
                X509_VERIFY_PARAM_set_auth_level(vpm, i);
            break;
#endif
        case OPT_V_ATTIME:
            if(0 is_eq opt_intmax(val, &t, "-attime option"))
                return false;
            if(t not_eq (time_t) t)
            {
                LOG(FL_ERR, "epoch time out of range: %s", val);
                return false;
            }
            X509_VERIFY_PARAM_set_time(vpm, (time_t)t);
            break;
        case OPT_V_VERIFY_HOSTNAME:
            if(0 is_eq X509_VERIFY_PARAM_set1_host(vpm, val, 0))
                return false;
            break;
        case OPT_V_VERIFY_EMAIL:
            if(0 is_eq X509_VERIFY_PARAM_set1_email(vpm, val, 0))
                return false;
            break;
        case OPT_V_VERIFY_IP:
            if(0 is_eq X509_VERIFY_PARAM_set1_ip_asc(vpm, val))
                return false;
            break;
        case OPT_V_IGNORE_CRITICAL:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_IGNORE_CRITICAL);
            break;
        case OPT_V_ISSUER_CHECKS: /* deprecated by OpenSSL */
            /* NOP */
            break;
        case OPT_V_CRL_CHECK: /* not actually used */
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK);
            break;
        case OPT_V_CRL_CHECK_ALL: /* not actually used */
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK bitor X509_V_FLAG_CRL_CHECK_ALL);
            break;
        case OPT_V_POLICY_CHECK:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_POLICY_CHECK);
            break;
        case OPT_V_EXPLICIT_POLICY:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_EXPLICIT_POLICY);
            break;
        case OPT_V_INHIBIT_ANY:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_ANY);
            break;
        case OPT_V_INHIBIT_MAP:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_MAP);
            break;
        case OPT_V_X509_STRICT:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_X509_STRICT);
            break;
        case OPT_V_EXTENDED_CRL:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_EXTENDED_CRL_SUPPORT);
            break;
        case OPT_V_USE_DELTAS:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_USE_DELTAS);
            break;
        case OPT_V_POLICY_PRINT:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NOTIFY_POLICY);
            break;
        case OPT_V_CHECK_SS_SIG:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CHECK_SS_SIGNATURE);
            break;
        case OPT_V_TRUSTED_FIRST:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_TRUSTED_FIRST);
            break;
        case OPT_V_SUITEB_128_ONLY:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_128_LOS_ONLY);
            break;
        case OPT_V_SUITEB_128:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_128_LOS);
            break;
        case OPT_V_SUITEB_192:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_192_LOS);
            break;
        case OPT_V_PARTIAL_CHAIN:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);
            break;
        case OPT_V_NO_ALT_CHAINS: /* deprecated by OpenSSL */
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_ALT_CHAINS);
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        case OPT_V_NO_CHECK_TIME:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_CHECK_TIME);
            break;
#endif
        case OPT_V_ALLOW_PROXY_CERTS:
            X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_ALLOW_PROXY_CERTS);
            break;
    }
    return true;
}
