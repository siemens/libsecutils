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

#include <secutils/static_config.h>
#ifdef SECUTILS_USE_ICV

#include <openssl/hmac.h>

#include <storage/files.h>
#include <storage/files_icv.h>
#include <storage/uta_api.h>
#include <util/log.h>
#include <credentials/verify.h>

#include <operators.h>


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
    unsigned char key[TA_OUTLEN];
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len;

/* Derive an ICV key from the trust anchor */
#ifdef SECUTILS_USE_UTA 
    bool uta_res = uta_getkey(ctx, (const unsigned char*)name, strnlen(name, UTIL_max_path_len), key, TA_OUTLEN);

    if(not uta_res)
    {
        LOG(FL_ERR, "Could not get key for '%s' from UTA", name);
        return false;
    }
#else
    if(ctx not_eq 0)
    {
        LOG(FL_ERR, "UTA not available");
        return false;
    }
    /* some trivial emulation of trust anchor */
#if TA_OUTLEN != SHA256_DIGEST_LENGTH
#error Cannot produce KEY with length other than SHA256_DIGEST_LENGTH
#endif
    if(0 is_eq SHA256((const unsigned char*)name, strlen(name), key))
    {
        LOG(FL_ERR, "ERROR during SHA256 calculation from: %s", name);
        return false;
    }
    unsigned char tmp = key[3];
    key[3] = key[25];
    key[25] = key[10];
    key[10] = tmp;
#endif

    if(0 is_eq HMAC(EVP_sha256(), key, TA_OUTLEN, data, len, md, &md_len) or md_len < ICVLEN)
    {
        LOG(FL_ERR, "Could not calculate HMAC used as ICV for '%s'", name);
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
        buf = OPENSSL_malloc(fsize);
        if(buf is_eq 0)
        {
            LOG(FL_ERR, "Out of memory reading file '%s'", file);
            goto err;
        }
        if((size_t)fsize not_eq fread(buf, 1, fsize, f))
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
                fsize -= ICV_LINE_LEN; /* strip existing ICV */
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
        if(not calculate_icv_hex(ctx, buf, fsize - (protect ? 0 : ICV_LINE_LEN), location, icv_hex))
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
#ifdef SECUTILS_USE_ICV
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

#else
typedef int make_iso_compilers_happy_on_empty_translation_unit;
#endif /* defined SECUTILS_USE_ICV */
