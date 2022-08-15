/** 
* @file files_icv.c
* 
* @brief ICV protection for any type of file (including binary)
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

#include <linux/limits.h>
#include <openssl/hmac.h>

#include <credentials/verify.h>
#include <storage/files.h>
#include <storage/files_icv.h>
#include <storage/uta_api.h>
#include <util/log.h>

#include "secutils/operators.h"


#define ICVLEN 16
#define ICV_TAG "# ICV: "
#define ICV_HEX_LEN 2 * ICVLEN
#define ICV_LINE_LEN (strlen(ICV_TAG) + ICV_HEX_LEN + 1)


/*
 * derive integrity protection hash for data with given len, using name as DV for key
 * optionally uses ctx pointer to UTA context, which typically is part of the libsecutils context
 * if returns true, hash value is placed in buf, which must be of size ICV_HEX_LEN+1
 */
static bool calculate_icv_hex(OPTIONAL uta_ctx* ctx, const void* data, size_t len, const char* name, char* buf)
{
    unsigned char md[SHA256_DIGEST_LENGTH];

    if (false is_eq UTIL_calculate_icv_impl(ctx, data, len, name, md))
    {
        return false;
    }

    return UTIL_bytes_to_hex(buf, ICV_HEX_LEN + 1, md, ICVLEN);
}

/*!
 * @brief function has two modes depending on parameter protect function:
 *        1) protects integrity of specified file by ICV.
 *        2) check integrity of specified file.
 *
 * @param ctx pointer to UTA context, which typically is part of the libsecutils context, or null
 * @param file (path) name of the input file
 * @param location assumed for the given input file. Is used in the calculation of the checksum.
 *        No canonicalization is done. Needs to be provided correctly by caller.
 *        If null if provided, the input of file will be converted to an absolute path.
 * @param protect mode of function.
 *        **true**   protects integrity of specified file by ICV
 *        **false**  check integrity of specified file.
 * @return depends on parameter protect.
 * @retval true - file has been signed by ICV/file is not corrupted
 *         file - can't sign file/file is corrupted or error
 */
static bool protect_or_check_icv(OPTIONAL uta_ctx* ctx, const char* file, const char* location, bool protect)
{
    FILE* f = 0;
    long fsize = 0;
    unsigned char* buf = 0;
    bool res = false;
    char abs_path[PATH_MAX];

    if(location is_eq 0)
    {
        if(0 is_eq realpath(file, abs_path))
        {
            LOG(FL_ERR, "Could not resolve absolute path from: %s", file);
            return res;
        }
        location = abs_path;
    }

    f = fopen(file, protect ? "rb+" : "rb");
    if(f is_eq 0)
    {
        LOG(FL_ERR, "Could not open file '%s' for %s", file, protect ? "appending" : "reading");
        return res;
    }

    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if(fsize < 0)
    {
        LOG(FL_ERR, "Could not get size of file '%s'", file);
    }
    else if(fsize is_eq 0)
    {
        LOG(FL_ERR, "File '%s' is empty", file);
    }
    else
    {
        buf = OPENSSL_malloc((size_t)fsize);
        if(buf is_eq 0)
        {
            LOG(FL_ERR, "Out of memory reading file '%s'", file);
            goto err;
        }
        if((size_t)fsize not_eq fread(buf, 1, (size_t)fsize, f))
        {
            LOG(FL_ERR, "Could not read file '%s'", file);
            goto err;
        }

        char icv_hex[ICV_HEX_LEN + 1];
        bool found =
            fsize >= ICV_LINE_LEN and strncmp((char*)(buf + fsize - ICV_LINE_LEN), ICV_TAG, strlen(ICV_TAG)) is_eq 0;

        if(protect)
        {
            if(found)
            {
                fsize -= (long)ICV_LINE_LEN; /* strip existing ICV */
                if(fseek(f, fsize, SEEK_SET) is_eq EOF)
                {
                    LOG(FL_ERR, "Could not strip ICV from file '%s'", file);
                    goto err;
                }
            }
        }
        else
        {
            if(0 is_eq found)
            {
                LOG(FL_ERR, "Could not find ICV at end of file '%s'", file);
                goto err;
            }
        }
        if(not calculate_icv_hex(ctx, buf, (size_t)(fsize - (protect ? 0 : (long)ICV_LINE_LEN)), location, icv_hex))
        {
            LOG(FL_ERR, "Could not calculate ICV for file '%s'", file);
            goto err;
        }
        if(protect)
        {
            if(fprintf(f, ICV_TAG "%s\n", icv_hex) < 0)
            {
                LOG(FL_ERR, "Could not append ICV to file '%s'", file);
                goto err;
            }
        }
        else
        {
            if(memcmp(buf + fsize - ICV_HEX_LEN - 1, icv_hex, ICV_HEX_LEN) not_eq 0)
            {
                LOG(FL_ALERT, "Invalid ICV in file '%s'", file);
                goto err;
            }
        }
        res = true;
    err:
        OPENSSL_free(buf);
    }
    fclose(f);

    return res;
}


bool FILES_protect_icv(OPTIONAL uta_ctx* ctx, const char* file)
{
    return protect_or_check_icv(ctx, file, 0, true);
}

bool FILES_protect_icv_at(OPTIONAL uta_ctx* ctx, const char* file, const char* location)
{
    return protect_or_check_icv(ctx, file, location, true);
}

bool FILES_protect_icv_config_trusted(const char* file, OPTIONAL uta_ctx* ctx)
{
    static const int ext_len = 4;
    int str_len = strlen(file);
    const char* name_tail = file + str_len - (str_len >= ext_len ? ext_len : 0);
    if(0 is_eq strcmp(name_tail, ".pem") or 0 is_eq strcmp(name_tail, ".crt")
#ifdef SECUTILS_CONFIG_USE_ICV
       or 0 is_eq strcmp(name_tail, ".cnf") /* OpenSSL-style config file */
#endif
    )
    {
        LOG(FL_INFO, "making sure that file '%s' has an ICV", file);
        return FILES_protect_icv(ctx, file);
    }
    else
    {
        return true;
    }
}


bool FILES_check_icv(OPTIONAL uta_ctx* ctx, const char* file)
{
    return protect_or_check_icv(ctx, file, 0, false);
}

bool FILES_check_icv_at(OPTIONAL uta_ctx* ctx, const char* file, const char* location)
{
    return protect_or_check_icv(ctx, file, location, false);
}


X509* FILES_load_cert_pem_icv(OPTIONAL uta_ctx* ctx, const char* file, const char* desc)
{
    if(not FILES_check_icv(ctx, file))
    {
        return 0;
    }
    return FILES_load_cert(file, FORMAT_PEM, 0 /* password source */, desc);
}


bool FILES_store_cert_pem_icv(OPTIONAL uta_ctx* ctx, const X509* cert, const char* file, OPTIONAL const char* desc)
{
    if(not FILES_store_cert(cert, file, FORMAT_PEM, desc) or not FILES_protect_icv(ctx, file))
    {
        LOG(FL_ERR, "Failed writing cert to protected file '%s'", file);
        return false;
    }
    return true;
}


bool FILES_store_cert_pem(OPTIONAL uta_ctx* ctx, const X509* cert, const char* file, OPTIONAL const char* desc,
                          bool add_icv)
{
    bool retVal = false;
    if(add_icv)
    {
        retVal = FILES_store_cert_pem_icv(ctx, cert, file, desc);
    }
    else
    {
        retVal = FILES_store_cert(cert, file, FORMAT_PEM, desc);
    }
    return retVal;
}

bool FILES_store_crl_pem_icv(OPTIONAL uta_ctx* ctx, const X509_CRL* crl, const char* file, OPTIONAL const char* desc)
{
    if(not FILES_store_crl(crl, file, FORMAT_PEM, desc) or not FILES_protect_icv(ctx, file))
    {
        LOG(FL_ERR, "Failed writing cert to protected file '%s'", file);
        return false;
    }
    return true;
}

static inline long get_file_size(FILE* f)
{
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    return fsize;
}

OPENSSL_STRING FILE_get_file_content_if_existing_icv_is_valid(uta_ctx* ctx, const char* path)
{
    if(0 is_eq ctx)
    {
        LOG(FL_ERR, "No context");
        return 0;
    }

    if(0 is_eq path)
    {
        LOG(FL_ERR, "No path to ICV file");
        return 0;
    }

    char absolute_path[PATH_MAX];
    if(0 is_eq realpath(path, absolute_path))
    {
        LOG(FL_ERR, "Could not resolve absolute path from: %s", path);
        return 0;
    }

    // open file
    FILE* file = fopen(absolute_path, "rb");
    if(0 is_eq file)
    {
        LOG(FL_ERR, "Could not open file '%s'", absolute_path);
        return 0;
    }

    const long file_size = get_file_size(file);

    if(file_size < 0)
    {
        LOG(FL_ERR, "Could not get size of file '%s'", absolute_path);
    }
    else if(0 is_eq file_size)
    {
        LOG(FL_ERR, "File '%s' is empty", absolute_path);
    }
    else
    {
        OPENSSL_STRING content = OPENSSL_malloc((size_t)file_size + 1);
        if(0 is_eq content)
        {
            LOG(FL_ERR, "Out of memory reading file '%s'", absolute_path);
            goto error;
        }
        if((size_t)file_size not_eq fread(content, sizeof *content, (size_t)file_size, file))
        {
            LOG(FL_ERR, "Could not read file '%s'", absolute_path);
            goto error;
        }
        content[file_size] = '\0';

        const long icv_tag_start_index = file_size - (long)ICV_LINE_LEN;
        const char* icv_tag_start = content + icv_tag_start_index;
        const char* icv_hex_start = content + file_size - ICV_HEX_LEN - 1;

        const bool found = (file_size >= ICV_LINE_LEN) and (0 is_eq strncmp(icv_tag_start, ICV_TAG, strlen(ICV_TAG)));
        if(false is_eq found)
        {
            LOG(FL_ERR, "Could not find ICV at end of file '%s'", absolute_path);
            goto error;
        }

        // read original ICV
        char original_icv_hex[ICV_HEX_LEN + 1] = {'\0'};
        strncpy(original_icv_hex, icv_hex_start, ICV_HEX_LEN);

        // calculate ICV
        char icv_hex[ICV_HEX_LEN + 1] = {'\0'};
        if(not calculate_icv_hex(ctx, content, (size_t)icv_tag_start_index, absolute_path, icv_hex))
        {
            LOG(FL_ERR, "Could not calculate ICV for file '%s'", absolute_path);
            goto error;
        }

        // if ICVs are equal then return whole file content without ICV
        if(0 is_eq strncmp(original_icv_hex, icv_hex, ICV_HEX_LEN))
        {
            fclose(file);
            // "remove" ICV part in string content
            content[icv_tag_start_index] = '\0';
            return content;
        }
    error:
        OPENSSL_free(content);
    }

    fclose(file);
    return 0;
}
