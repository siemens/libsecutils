/** 
* @file opt.h
* 
* @brief OpenSSL-style command-line options, used for configuring applications
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

#include "../util/util.h"
#include <openssl/bio.h>

#ifndef SECUTILS_OPT_H_
#define SECUTILS_OPT_H_

/* all these definitions are used by the genCMPClient CLI implementation */

extern const char OPT_more_str[]; /** indicates further line of help text for current option */
extern const char OPT_section_str[]; /** marks a section header in help text */
extern const char OPT_param_str[]; /** marks a parameter option in help text */
#define OPT_MORE(text)    { OPT_more_str   , OPT_BOOL, {.num = 0}, {0}, text }
#define OPT_HEADER(title) { OPT_section_str, OPT_BOOL, {.num = 0}, {0}, title" options:" }
#define OPT_END           { 0              , OPT_BOOL, {.num = 0}, {0}, 0}
#define OPT_MAX_HELP_COL1_WIDTH 30 /** max width of 1st column in help output */

typedef enum
{
    OPT_TXT, /** String variable receives a pointer to the option argument */
    OPT_NUM, /** Integer variable receives the decimal number given as argument */
    OPT_BOOL /** Boolean variable receives a truth value */
} opttype_t; /** all possible selector values for union in below varref_union */

union varval_union {
    const char* txt; /** String value */
    long num;  /** Integer value, or vpm_opt */
    int bit;  /** Boolean value */
};

union varref_union {
    const char** txt; /** Pointer to string variable, or null */
    long* num;  /** Pointer to integer variable */
    int* bit;  /** Pointer to Boolean variable */
};

typedef struct opt_t
{
    const char* name; /** option name */
    opttype_t type;   /** option type, selects in below unions */
    union varval_union default_value; /** default value for the option */
    union varref_union varref_u; /** reference to the variable holding the value */
    const char* help_str; /** a short description of the option for help output */
} opt_t; /** an option with its name, type, default value, variable, and help string */

/*!
 * @brief initialize option/config variables to their default values
 * @param options list of options, terminated by a {0} entry
 * @return false on error (e.g., options is null), else true
 */
bool OPT_init(opt_t options[]);

/*!
 * @brief print the help strings for option/config variables to the given BIO
 * @param options list of options, terminated by a {0} entry
 * @param bio the OpenSSL BIO to print to (may be linked, e.g., to stdout)
 * @return false on error (e.g., options or BIO is null), else true
 */
bool OPT_help(opt_t options[], BIO* bio);

/*!
 * @brief read CLI arguments, updating option variables and cert verifications options
 * @param options list of options, terminated by a {0} entry
 * @param argv list of arguments, terminated by a null entry
 * @param vpm verification parameters to update
 * @return 1 on success, 0 on error, < 0 to stop with success, typically on -help
 */
int OPT_read(opt_t options[], char** argv, X509_VERIFY_PARAM* vpm);

typedef enum
    {
     OPT_V__FIRST = 2000,
     OPT_V_POLICY, OPT_V_PURPOSE, OPT_V_VERIFY_NAME, OPT_V_VERIFY_DEPTH,
     OPT_V_ATTIME, OPT_V_VERIFY_HOSTNAME, OPT_V_VERIFY_EMAIL,
     OPT_V_VERIFY_IP, OPT_V_IGNORE_CRITICAL, OPT_V_ISSUER_CHECKS,
     OPT_V_CRL_CHECK, OPT_V_CRL_CHECK_ALL, OPT_V_POLICY_CHECK,
     OPT_V_EXPLICIT_POLICY, OPT_V_INHIBIT_ANY, OPT_V_INHIBIT_MAP,
     OPT_V_X509_STRICT, OPT_V_EXTENDED_CRL, OPT_V_USE_DELTAS,
     OPT_V_POLICY_PRINT, OPT_V_CHECK_SS_SIG, OPT_V_TRUSTED_FIRST,
     OPT_V_SUITEB_128_ONLY, OPT_V_SUITEB_128, OPT_V_SUITEB_192,
     OPT_V_PARTIAL_CHAIN, OPT_V_NO_ALT_CHAINS,
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
     OPT_V_NO_CHECK_TIME,
     OPT_V_VERIFY_AUTH_LEVEL,
#endif
     OPT_V_ALLOW_PROXY_CERTS,
     OPT_V__LAST
    } vpm_opt;

#define OPT_V_OPTIONS                                                         \
    OPT_HEADER("Certificate validation"),                                     \
    { "policy", OPT_TXT, {.num = OPT_V_POLICY}, { 0 },                        \
            "adds policy to the acceptable policy set"},                      \
    { "purpose", OPT_TXT, {.num = OPT_V_PURPOSE}, { 0 },                      \
            "certificate chain purpose"},                                     \
    { "verify_name", OPT_TXT, {.num = OPT_V_VERIFY_NAME}, { 0 },              \
            "verification policy name"},                                      \
    { "verify_depth", OPT_NUM, {.num = OPT_V_VERIFY_DEPTH}, { 0 },            \
            "chain depth limit" },                                            \
    { "attime", OPT_NUM, {.num = OPT_V_ATTIME}, { 0 },                        \
            "verification epoch time" },                                      \
    { "verify_hostname", OPT_TXT, {.num = OPT_V_VERIFY_HOSTNAME}, { 0 },      \
            "expected peer hostname" },                                       \
    { "verify_email", OPT_TXT, {.num = OPT_V_VERIFY_EMAIL}, { 0 },            \
            "expected peer email" },                                          \
    { "verify_ip", OPT_TXT, {.num = OPT_V_VERIFY_IP}, { 0 },                  \
            "expected peer IP address" },                                     \
    { "ignore_critical", OPT_BOOL, {.num = OPT_V_IGNORE_CRITICAL}, { 0 },     \
            "permit unhandled critical extensions"},                          \
/*  { "issuer_checks", OPT_BOOL, {.num = OPT_V_ISSUER_CHECKS}, { 0 },         \
            "(deprecated)"},                                               */ \
/* superseded begin                                                           \
    { "crl_check", OPT_BOOL, {.num = OPT_V_CRL_CHECK}, { 0 },                 \
            "check leaf certificate revocation" },                            \
    { "crl_check_all", OPT_BOOL, {.num = OPT_V_CRL_CHECK_ALL}, { 0 },         \
            "check full chain revocation" },                                  \
  superseded end */                                                           \
    { "policy_check", OPT_BOOL, {.num = OPT_V_POLICY_CHECK}, { 0 },           \
            "perform rfc5280 policy checks"},                                 \
    { "explicit_policy", OPT_BOOL, {.num = OPT_V_EXPLICIT_POLICY}, { 0 },     \
            "set policy variable require-explicit-policy"},                   \
    { "inhibit_any", OPT_BOOL, {.num = OPT_V_INHIBIT_ANY}, { 0 },             \
             "set policy variable inhibit-any-policy"},                       \
    { "inhibit_map", OPT_BOOL, {.num = OPT_V_INHIBIT_MAP}, { 0 },             \
            "set policy variable inhibit-policy-mapping"},                    \
    { "x509_strict", OPT_BOOL, {.num = OPT_V_X509_STRICT}, { 0 },             \
            "disable certificate compatibility work-arounds"},                \
    { "extended_crl", OPT_BOOL, {.num = OPT_V_EXTENDED_CRL}, { 0 },           \
            "enable extended CRL features"},                                  \
    { "use_deltas", OPT_BOOL, {.num = OPT_V_USE_DELTAS}, { 0 },               \
            "use delta CRLs"},                                                \
    { "policy_print", OPT_BOOL, {.num = OPT_V_POLICY_PRINT}, { 0 },           \
            "print policy processing diagnostics"},                           \
    { "check_ss_sig", OPT_BOOL, {.num = OPT_V_CHECK_SS_SIG}, { 0 },           \
            "check root CA self-signatures"},                                 \
    { "trusted_first", OPT_BOOL, {.num = OPT_V_TRUSTED_FIRST}, { 0 },         \
            "search trust store first (default)" },                           \
    { "suiteB_128_only", OPT_BOOL, {.num = OPT_V_SUITEB_128_ONLY}, { 0 },     \
            "Suite B 128-bit-only mode"},                                     \
    { "suiteB_128", OPT_BOOL, {.num = OPT_V_SUITEB_128}, { 0 },               \
            "Suite B 128-bit mode allowing 192-bit algorithms"},              \
    { "suiteB_192", OPT_BOOL, {.num = OPT_V_SUITEB_192}, { 0 },               \
            "Suite B 192-bit-only mode" },                                    \
    { "partial_chain", OPT_BOOL, {.num = OPT_V_PARTIAL_CHAIN}, { 0 },         \
            "accept chains anchored by intermediate trust-store CAs"},        \
/*  { "no_alt_chains", OPT_BOOL, {.num = OPT_V_NO_ALT_CHAINS}, { 0 },         \
            "(deprecated)" },                                              */ \
    OPT_V_OPTIONS_V_1_1                                                       \
    { "allow_proxy_certs", OPT_BOOL, {.num = OPT_V_ALLOW_PROXY_CERTS}, { 0 }, \
            "allow the use of proxy certificates" }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define OPT_V_OPTIONS_V_1_1                                                   \
    { "no_check_time", OPT_BOOL, {.num = OPT_V_NO_CHECK_TIME}, { 0 },         \
            "ignore certificate validity time" },                             \
    { "auth_level", OPT_NUM, {.num = OPT_V_VERIFY_AUTH_LEVEL}, { 0 },         \
            "chain authentication security level" },
#else
#define OPT_V_OPTIONS_V_1_1
#endif

/*!
 * @brief update OpenSSL cert verification parameters from the given option
 * @param opt index of option, see above type vpm_opt
 * @param val value of the option to be set
 * @param vpm verification parameters to update
 * @return false on error (e.g., opt out of range), else true
 */
bool OPT_update_vpm(int opt, const char* val, X509_VERIFY_PARAM* vpm);

#endif /* SECUTILS_OPT_H_ */
