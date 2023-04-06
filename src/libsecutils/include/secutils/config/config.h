/** 
* @file config.h
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

#ifndef SECUTILS_CONFIG_H_
#define SECUTILS_CONFIG_H_

#include "../basic.h"
#include "../storage/uta_api.h"
#include "opt.h"

#include <openssl/conf.h>
#include <openssl/x509_vfy.h>

/*!
 * @brief load configuration file, checking its ICV if SECUTILS_USE_ICV is defined
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file config file to be loaded
 * @return configuration structure containing options on success, else false
 */
CONF* CONF_load_config(OPTIONAL uta_ctx* ctx, const char* file);

/*!
 * @brief read options from configuration section(s)
 * @param conf configuration structure to read from
 * @param sections comma-separated list of names of the section(s) to read
 * @param opts pointer to the table of the config options
 * @return true on success, else false
 */
bool CONF_read_options(CONF* conf, const char* sections, opt_t* opts);

/*!
 * @brief update OpenSSL cert verification parameters from the given configuration section(s)
 * @param conf configuration structure to read from
 * @param sections comma-separated list of names of the section(s) to read
 * @param vpm verification parameters to update
 * @note vpm parameter may be initialized by caller using X509_VERIFY_PARAM_new()
 * @return true on success, else false
 */
bool CONF_update_vpm(CONF* conf, const char* sections, X509_VERIFY_PARAM* vpm);

/*!
 * @brief read options from section(s) of configuration file, checking its ICV if SECUTILS_USE_ICV is defined
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file config file to be loaded
 * @param sections comma-separated list of names of the section(s) to read
 * @param opts pointer to the table of the config options
 * @return configuration structure, to be freed by caller, or 0 on error
 */
CONF* CONF_load_options(OPTIONAL uta_ctx* ctx, const char* file,
                        const char* sections, OPTIONAL opt_t* opts);

/*!
 * @brief read string value from section(s) of configuration file, checking its ICV if SECUTILS_USE_ICV is defined
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file config file to be loaded
 * @param sections comma-separated list of names of the section(s) to read
 * @param key name of the (string) option to be read
 * @return string value, to be OPENSSL_free()-d by caller, or 0 on error
 */
/* used by FILES_load_key_autofmt_dv and FILES_get_dv() (via read_dv()) if USE_DVFILE is enabled */
char* CONF_load_string(OPTIONAL uta_ctx* ctx, const char* file,
                       const char* sections, const char* key);

#endif /* SECUTILS_CONFIG_H_ */
