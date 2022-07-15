/** 
* @file files_dv.c
* 
* @brief Credential file handling using HW/SW derived key for protection
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

#ifdef USE_DVFILE
static const char* const DVFILE_EV = "DVFILE"; /*! name file containing DV seeds, by default: "./config/dv.cnf" */
#endif
static const char* const DV_SECTION = "dv"; /*! name of DVFILE section with DV seeds */

#include <assert.h>
#include <libgen.h> /* for basename */
#include <openssl/rand.h>
#include <sys/stat.h>

#include <config/config.h>
#include <config/config_update.h>
#include <storage/files_dv.h>
#include <util/log.h>

#include "secutils/operators.h"

/* Get device-specific password (base64 encoded) */
static bool getBase64Password(OPTIONAL uta_ctx* ctx, const unsigned char* dv, char* pw)
{
    unsigned char key[TA_OUTLEN];
    int len;

#ifdef SECUTILS_USE_UTA 
    if(0 is_eq uta_getkey(ctx, dv, DVLEN, key, TA_OUTLEN))
    {
        return false;
    }
#else
    if(ctx not_eq 0)
    {
        LOG(FL_ERR, "UTA not available");
        return false;
    }
    /* some emulation of trust anchor */
    memcpy(key, dv, DVLEN);
    unsigned char tmp = key[2];
    key[2] = key[6];
    key[6] = tmp;
#if TA_OUTLEN != SHA256_DIGEST_LENGTH
#error Cannot produce KEY with length other than SHA256_DIGEST_LENGTH
#endif
    if(0 is_eq SHA256((const unsigned char*)key, DVLEN, key))
    {
        LOG(FL_ERR, "ERROR during SHA256 calculation on DV");
        return false;
    }
#endif
    len = UTIL_base64_encode_to_buf(key, TA_OUTLEN, pw, MAX_B64_CHARS_PER_BYTE * TA_OUTLEN);

    LOG(FL_TRACE, "DV-based password: %s", pw);
    return len >= 0;
}


/*!
 * @brief write derivation value (DV) to config file
 * @param ctx (optional) pointer to UTA context for checking file integrity&authenticity using ICV
 * @param dvfile OpenSSL-style config file containing [dv] section to read from
 * @param name key to tool up in [dv] section; usually an absolute file path name
 * @param dv_val derivation value to write; must contain DVLEN bytes
 * @return 0 on failure, 1 on success
 */
/****************************************************
 * Store DV in file, used if USE_DVFILE is defined
 ***************************************************/
static bool store_dv(OPTIONAL uta_ctx* ctx, const char* dvfile, const char* name, const unsigned char* dv_val)
{
    char dv_hex[HEX_CHARS_PER_BYTE * DVLEN + 1];
    key_val_pair key_val_pair[1];
    key_val_section key_val_section;
    key_val_section.pairs = key_val_pair;

    if(0 is_eq dvfile or 0 is_eq name or 0 is_eq dv_val)
    {
        LOG_err("null pointer argument");
        return false;
    }
    LOG(FL_TRACE, "Writing DV for '%s' to file '%s'", name, dvfile);

    struct stat st;
    if(stat(dvfile, &st) < 0) /* file does not (yet) exist */
    {
        FILE* fp = fopen(dvfile, "w");
        if(fp is_eq 0)
        {
            LOG(FL_ERR, "Could not create initial DV file %s", dvfile);
            return false;
        }
        int file_len = fprintf(fp, "[%s]\n", DV_SECTION);
        fclose(fp);
        if(file_len not_eq strlen("[") + strlen(DV_SECTION) + strlen("]") + 1)
        {
            LOG(FL_ERR, "Error writing initial DV file '%s'", dvfile);
            return false;
        }
    }

    (void)UTIL_bytes_to_hex(dv_hex, HEX_CHARS_PER_BYTE * DVLEN + 1, dv_val, DVLEN);

    key_val_section.name = (char*)DV_SECTION;
    key_val_section.count = 1;
    key_val_section.pairs[0].key = (char*)name;
    key_val_section.pairs[0].val = dv_hex;

    if(CONF_update_config(ctx, dvfile, &key_val_section, UPDATE_CONFIG_EXCLUDE_NONE) <= 0)
    {
        LOG(FL_ERR, "Could not store the DV for file '%s' in file '%s'", name, dvfile);
        return false;
    }
    else
    {
        return true;
    }
}


/*!
 * @brief read derivation value (DV) from config file
 * @param ctx (optional) pointer to UTA context for checking file integrity&authenticity using ICV
 * @param dvfile OpenSSL-style config file containing [dv] section to read from
 * @param name key to tool up in [dv] section; usually an absolute file path name
 * @param dv_val_out place to store the derivation value; must have DVLEN bytes of space
 * @return 0 on failure, 1 on success
 */
/****************************************************
 * Read DV from dvfile, used if USE_DVFILE is defined
 ***************************************************/
static bool read_dv(OPTIONAL uta_ctx* ctx, const char* dvfile, const char* name, unsigned char* dv_val_out)
{
    char* dv_hex = 0;
    const char* dvtemp;
    int success = false;

    if(0 is_eq dvfile or 0 is_eq name or 0 is_eq dv_val_out)
    {
        LOG_err("null pointer argument to read_dv");
        goto error;
    }
    LOG(FL_TRACE, "Reading DV for '%s' from DV file '%s'", name, dvfile);

    if(0 is_eq(dv_hex = CONF_load_string(ctx, dvfile, DV_SECTION, name)))
    { /* strip any file path prefix */
        LOG(FL_ERR, "Cannot find DV for key '%s' in file '%s'", name, dvfile);
        goto error;
    }
    if(strlen(dv_hex) not_eq (HEX_CHARS_PER_BYTE * DVLEN))
    {
        LOG(FL_ERR, "Length of DV hex encoding is not %i bytes", DVLEN);
        goto error;
    }
    dvtemp = (const char*)dv_hex;
    if(0 is_eq UTIL_hex_to_bytes(&dvtemp, dv_val_out, DVLEN))
    {
        LOG(FL_ERR, "Bad char in DV for '%s = %s'", name, dv_hex);
        goto error;
    }
    success = true;
error:
    OPENSSL_free(dv_hex);
    if(0 is_eq success)
    {
        LOG(FL_ERR, "Could not read the DV for file '%s' in file '%s'", name, dvfile);
    }
    return success;
}


/* get path name of DV file if USE_DVFILE is defined, else null */
static const char* get_dvfile(void)
{
    const char* dvfile = 0;
#ifdef USE_DVFILE
    char* dvfile = getenv(DVFILE_EV); /* file where the DVs are kept, shared between threads */
    if(dvfile is_eq 0 or *dvfile is_eq '\0')
    {
        dvfile = "config/dv.cnf"; /* default relative path name of DV file */
    }
    struct stat st;
    if(stat(dvfile, &st) < 0)
    {
        LOG(FL_ERR, "DV file '%s' does not exist", dvfile);
        dvfile = 0;
    }
#endif
    return dvfile;
}

/**
 * @brief returns substring up to the final '/' (not including), this
 *        substring represents dirname part of path
 * @return dirname part of path, or null pointer on failure.
 * @note the pointer has to be freed by OPENSSL_free()
 */
static char* get_dirname(const char* path)
{
    char* ret_val;

    if((1 >= strlen(path)) or (0 is_eq(ret_val = OPENSSL_strdup(path))))
    {
        return 0;
    }

    char* pos = 0;

    if(0 not_eq (pos = strrchr(ret_val, '/')))
    {
        if(pos is_eq ret_val)
        {
            *(pos + 1) = '\0';
        }
        else
        {
            *pos = '\0';
        }
    }
    else
    { /* '/' not found => only basename part */
        *ret_val = '.';
        *(ret_val + 1) = '\0';
    }

    return ret_val;
}

/**
 * @brief returns substring following the final '/' (not including), this
 *        substring represents filename part of path
 * @return filename part of path, or null pointer on failure.
 * @note the pointer has to be freed by OPENSSL_free()
 */
static char* get_basename(const char* path)
{
    char* ret_val;
    char* pos;

    if(0 not_eq (pos = strrchr(path, '/')))
    {
        ret_val = OPENSSL_strdup(pos + 1);
    }
    else
    { /* '/' not found => only basename part */
        ret_val = OPENSSL_strdup(path);
    }

    return ret_val;
}

/**
 * @brief returns canonicalized absolute path
 * @param path path which should be canonicalized
 * @param canonicalized
 * @note  the pointer has to be freed by OPENSSL_free()
 */
static char* get_canonicalized(const char* path, char* canonicalized)
{
    char* ret_val = 0;

    char* dir_part = get_dirname(path);
    char* name_part = get_basename(path);

    if((0 not_eq dir_part) and (0 not_eq name_part))
    {
        if(0 is_eq realpath(dir_part, canonicalized))
        {
            ret_val = 0;
        }
        else
        {
            strcat(canonicalized, "/");
            strcat(canonicalized, name_part);
            ret_val = canonicalized;
        }
    }

    OPENSSL_free(dir_part);
    OPENSSL_free(name_part);
    return ret_val;
}

bool FILES_get_dv(const char* filename, unsigned char* dv_out)
{
    if(filename is_eq 0 or dv_out is_eq 0)
    {
        LOG_err("null pointer argument");
        return false;
    }
    char abs_path[PATH_MAX];
    if(0 is_eq realpath(filename, abs_path))
    {
        if(errno not_eq ENOENT)
        { /* for no-exist file the path can be resolved */
            LOG(FL_ERR, "Could not resolve absolute path from: %s", filename);
            return false;
        }

        if(0 is_eq get_canonicalized(filename, abs_path))
        { /* for no-exist file the path can be resolved */
            LOG(FL_ERR, "Could not resolve absolute path from: %s", filename);
            return false;
        }
    }
    LOG(FL_TRACE, "Hashing absolute file path name '%s' to obtain DV", abs_path);
#if DVLEN > SHA256_DIGEST_LENGTH
#error Cannot produce DV with length DVLEN larger than SHA256_DIGEST_LENGTH
#endif
    unsigned char md[SHA256_DIGEST_LENGTH];
    if(0 is_eq SHA256((const unsigned char*)abs_path, strlen(abs_path), md))
    {
        LOG(FL_ERR, "ERROR during SHA256 calculation of DV from: %s", abs_path);
        return false;
    }
    memcpy(dv_out, md, DVLEN);
    return true;
}


/* also writes new (random) DV to dvfile if write==true and USE_DVFILE is defined */
bool FILES_get_pass_dv(char* pass_buf, uta_ctx* ctx, const char* filename, bool write, OPTIONAL const char* desc)
{
    if(0 is_eq filename)
    {
        LOG_err("null pointer filename argument");
        return false;
    }
    char abs_path[PATH_MAX];
    memset(abs_path, 0x00, PATH_MAX);

    if(0 is_eq realpath(filename, abs_path))
    {
        if(errno not_eq ENOENT)
        { /* for no-exist file the path can be resolved */
            LOG(FL_ERR, "Could not resolve absolute path from: %s", filename);
            return false;
        }

        if(0 is_eq get_canonicalized(filename, abs_path))
        { /* for no-exist file the path can be resolved */
            LOG(FL_ERR, "Could not resolve absolute path from: %s", filename);
            return false;
        }
    }
    const char* any_desc = desc not_eq 0 ? desc : filename;

    unsigned char dv_val[DVLEN];
    const char* dvfile = get_dvfile();
    if(write and dvfile not_eq 0)
    {
        LOG(FL_TRACE, "Deriving password from random DV and storing it in DV file '%s'", dvfile);
        /* create and store a new DV */
        if(not UTIL_get_random(dv_val, DVLEN))
        {
            LOG_err("Could not obtain random DV"); /* @todo: maybe use other RNG? */
            return false;
        }
        if(0 not_eq dvfile and not store_dv(ctx, dvfile, abs_path, dv_val))
        {
            LOG(FL_ERR, "Failed to write DV for '%s' to DV file '%s'", filename, dvfile);
            return false;
        }
    }
    else
    {
        LOG(FL_TRACE, "Getting password via DV and UTA for '%s' containing %s", filename, any_desc);
        if(not(dvfile is_eq 0 ? FILES_get_dv(filename, dv_val) : read_dv(ctx, dvfile, abs_path, dv_val)))
        {
            LOG(FL_ERR, "Could not get DV for '%s' containing %s", filename, any_desc);
            return false;
        }
    }
    LOG(FL_TRACE, "Obtaining password from UTA for %s '%s'", write ? "writing" : "reading", filename);
    if(not getBase64Password(ctx, dv_val, pass_buf))
    {
        LOG(FL_ERR, "Could not derive password from DV via UTA for %s '%s' containing %s",
            write ? "writing" : "reading", filename, any_desc);
        return false;
    }
    return true;
}


bool FILES_store_key_dv(const EVP_PKEY* pkey, const char* file, file_format_t format, OPTIONAL const char* pass,
                        OPTIONAL uta_ctx* ctx, OPTIONAL const char* desc)
{
    bool res = false;
    char pass_buf[strlen(sec_PASS_STR) + MAX_UTA_PASS_LEN];
    char *source = 0;
    if(pass is_eq 0 and ctx not_eq 0)
    {
        strcpy(pass_buf, sec_PASS_STR);
        if(FILES_get_pass_dv(pass_buf + strlen(sec_PASS_STR), ctx, file, true /* write */, desc))
        {
            source = pass_buf;
        }
        else
        {
            return false;
        }
    }
    res = FILES_store_key(pkey, file, format, source, desc);
    UTIL_erase_mem(pass_buf, sizeof(pass_buf));
    return res;
}


EVP_PKEY* FILES_load_key_autofmt_dv(const char* key, file_format_t file_format, OPTIONAL const char* pass,
                                    OPTIONAL uta_ctx* ctx, OPTIONAL const char* engine, OPTIONAL const char* desc)
{
    EVP_PKEY* pkey = 0;
    char pass_buf[strlen(sec_PASS_STR) + MAX_UTA_PASS_LEN];
    char *source = 0;
    if(pass is_eq 0 and ctx not_eq 0)
    {
        strcpy(pass_buf, sec_PASS_STR);
        if(FILES_get_pass_dv(pass_buf + strlen(sec_PASS_STR), ctx, key, false /* read*/, desc))
        {
            source = pass_buf;
        }
        else
        {
            return false;
        }
    }
    pkey = FILES_load_key_autofmt(key, file_format, false /* no stdin */, source, engine, desc);
    UTIL_erase_mem(pass_buf, sizeof(pass_buf));
    return pkey;
}


STACK_OF(X509)
    * FILES_load_certs_autofmt_dv(const char* file, file_format_t format, OPTIONAL const char* pass,
                                  OPTIONAL uta_ctx* ctx, OPTIONAL const char* desc)
{
    STACK_OF(X509)* certs = 0;
    char pass_buf[strlen(sec_PASS_STR) + MAX_UTA_PASS_LEN];
    char* source = 0;
    if(pass is_eq 0 and ctx not_eq 0)
    {
        strcpy(pass_buf, sec_PASS_STR);
        if(FILES_get_pass_dv(pass_buf + strlen(sec_PASS_STR), ctx, file, false /* read*/, desc))
        {
            source = pass_buf;
        }
        else
        {
            return false;
        }
    }
    certs = FILES_load_certs_autofmt(file, format, source, desc);
    UTIL_erase_mem(pass_buf, sizeof(pass_buf));
    return certs;
}
