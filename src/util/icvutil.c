/** 
* @file icvutil.c
* 
* @brief ICV protection management utility
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

#include <stdlib.h> /* for EXIT_SUCCESS */

#include "log.h"
#include "../include/secutils/storage/files_icv.h"
#include "../include/secutils/storage/uta_api.h"

#define ARG_OPTION    1
#define ARG_FILE      2
#define ARG_FILE_LOC  3

int main(int argc, char *argv[]) {
    int ret = EXIT_FAILURE;

#ifdef SECUTILS_USE_UTA
    uta_ctx *uta_ctx = NULL;

    if ((uta_ctx = uta_open()) == NULL) {
        LOG(FL_EMERG, "failure getting UTA ctx");
        return ret;
    }

    const char *prog = argv[0];
    const char *option = (argc > ARG_OPTION) ? argv[ARG_OPTION] : "";
    const char *file   = (argc > ARG_FILE  ) ? argv[ARG_FILE  ] : NULL;
    const char *file_loc = (argc > ARG_FILE_LOC) ? argv[ARG_FILE_LOC] : NULL;

#ifdef SECUTILS_USE_ICV
    if (strcmp(option, "-protect_icv") == 0 && file) {
        if (FILES_protect_icv_at(uta_ctx, file, file_loc)) {
            ret = EXIT_SUCCESS;
            printf("File protected successfully\n");
        }
        else {
            printf("File could not be protected\n");
        }
    }
    else if (strcmp(option, "-check_icv") == 0 && file) {
        if (FILES_check_icv_at(uta_ctx, file, file_loc)) {
            ret = EXIT_SUCCESS;
            printf("ICV verified successfully\n");
        }
        else {
            printf("ICV could not be verified\n");
        }
    }
    else {
        fprintf(stderr, "       %s usage:\n", prog);
        fprintf(stderr, "       %s -protect_icv <file> [<file_location>]\n", prog);
        fprintf(stderr, "       %s -check_icv <file> [<file_location>]\n", prog);
        fprintf(stderr, "       %s -help\n", prog);
    }
#else
    LOG(FL_WARN, "Not using ICV protection because SECUTILS_USE_ICV was not defined");
#endif

    uta_close(uta_ctx);
#else
    LOG(FL_WARN, "Not using UTA lib because SECUTILS_USE_UTA was not defined");
#endif
    return ret;
}
