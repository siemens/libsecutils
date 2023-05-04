/** 
* @file config_update.h
* 
* @brief OpenSSL-style configuration file update (also used for DV files)
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

#ifndef SECUTILS_CONFIG_UPDATE_H_
#define SECUTILS_CONFIG_UPDATE_H_

#include "../basic.h"
#include "../storage/uta_api.h"

typedef struct
{
    const char* key;
    const char* val;
} key_val_pair;

typedef struct
{
    char* name;
    int count;
    key_val_pair* pairs; /* array of length 'count' */
} key_val_section;

static const int UPDATE_CONFIG_EXCLUDE_NONE = -1; /* must be out of range of valid key indices */

/* update config file, checking and updating its ICV if SECUTILS_USE_ICV is defined */
/* used by FILES_store_credentials_dv() (via store_dv()) if USE_DVFILE is enabled */
int CONF_update_config(OPTIONAL uta_ctx* ctx, const char* const filename_p,
                       const key_val_section* const key_val_section, int exclude);

#endif /* SECUTILS_CONFIG_UPDATE_H_ */
