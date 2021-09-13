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

#include "../include/secutils/util/log.h"
#include "../include/secutils/storage/files_icv.h"
#include "../include/secutils/storage/uta_api.h"

#ifndef SECUTILS_USE_UTA
# error Use of UTA lib is not enabled; need to define SECUTILS_USE_UTA
#endif

#define ARG_OPTION    1
#define ARG_FILE      2
#define ARG_FILE_LOC  3

int main(int argc, char *argv[]) {
    int ret = EXIT_FAILURE;
    uta_ctx *uta_ctx = uta_open();

    if (NULL == uta_ctx) {
        LOG(FL_EMERG, "failure getting UTA ctx");
        return ret;
    }

    const char *prog = argv[0];
    const char *option = (argc > ARG_OPTION) ? argv[ARG_OPTION] : "";
    const char *file   = (argc > ARG_FILE  ) ? argv[ARG_FILE  ] : NULL;
    const char *file_loc = (argc > ARG_FILE_LOC) ? argv[ARG_FILE_LOC] : NULL;

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

    uta_close(uta_ctx);
    return ret;
}
