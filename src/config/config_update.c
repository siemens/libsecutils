/** 
* @file config_update.c
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

#include <assert.h>
#include <config/config_update.h>
#include <storage/files_icv.h>
#include <util/log.h>

#include <operators.h>


static void skip_space(char** p)
{
    while(isspace(**p))
    {
        (*p)++;
    }
}


static bool copy_line_substring(char* dest, const char* src, size_t* offset, size_t max_dest_len)
{
    size_t copy_len = strnlen(src, max_dest_len);
    if(*offset + copy_len > max_dest_len)
    {
        return false;
    }
    strncpy(dest + *offset, src, copy_len + 1);
    (*offset) += copy_len;
    return true;
}


static int file_modified;


/*
 * copy the src line to the dest line (with max len), replacing value
 * if line has the format "key = old_value[ # comment]" for given key.
 * Keeps any end-of-line comment.
 * Returns the length of the resulting line, or 0 in case of error.
 */
static int refactor_entry(char* const src_p, char* dest_p, const char* const key_p, const char* const val_p, size_t max_dest_len)
{
    size_t line_len = 0;
    char* pos_p = src_p;

    if(0 is_eq src_p or 0 is_eq key_p or 0 is_eq val_p)
    {
        LOG(FL_ERR, "Error refactor_entry, null pointer as function parameter");
        return -1;
    }

    /* copy the whole line proactively */
    if(not copy_line_substring(dest_p, src_p, &line_len, max_dest_len))
    {
        goto len_err;
    }

    skip_space(&pos_p);
    if(strncmp(pos_p, key_p, strlen(key_p)))
    {
        return line_len; /* key not found */
    }
    pos_p += strlen(key_p);
    skip_space(&pos_p);
    if(*pos_p++ not_eq '=')
    {
        return line_len; /* '=' not found */
    }
    skip_space(&pos_p);

    /* found "key = ", copy in the new value */
    const size_t val_len = strnlen(val_p, max_dest_len);
    assert(pos_p >= src_p);
    line_len = (size_t)(pos_p - src_p);
    if(not copy_line_substring(dest_p, val_p, &line_len, max_dest_len))
    {
        goto len_err;
    }
    const char* pos_start = pos_p;

    /* set pointer just before any comment or the new line, and before any preceding whitespace */
    int nquotes = 0;
    while((nquotes % (1 + 1) is_eq 1 or *pos_p not_eq '#') and *pos_p not_eq '\n' and *pos_p not_eq '\0')
    {
        if(*pos_p is_eq '\"')
        {
            nquotes++;
        }
        pos_p++;
    }
    while(isspace(*(pos_p - 1)))
    {
        pos_p--;
    }
    if(pos_p - pos_start not_eq val_len or strncmp(pos_start, val_p, val_len))
    {
        file_modified = 1;
    }

    /* copy the rest of the comment */
    if(not copy_line_substring(dest_p, pos_p, &line_len, max_dest_len))
    {
        goto len_err;
    }

    return line_len;

len_err:
    LOG(FL_ERR, "Failed updating line, is longer than %d bytes:\n%s", max_dest_len - 1, src_p);
    return -1;
}


#define c_file_buf_size 16384 /* 16 kB including trailing '\0' */
#define c_line_buf_size 512   /* .5 kB including '\0' */

/*
 * @warning security note: `file_buffer` is a `tained` value in the sense of
 * https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings
 */
static char file_buffer[c_file_buf_size] = {0};
static char input_line[c_line_buf_size];
static char updated_line[c_line_buf_size];

#define copy_file_line(dest, src, offset)                                                                              \
    if(line_len > c_line_buf_size - 1)                                                                                 \
    {                                                                                                                  \
        return 0;                                                                                                      \
    }                                                                                                                  \
    file_len += line_len;                                                                                              \
    if(file_len > c_file_buf_size - 1)                                                                                 \
    {                                                                                                                  \
        return file_len;                                                                                               \
    }                                                                                                                  \
    strncpy(dest + file_len - line_len, src, line_len + 1)


static size_t read_config_until_section(FILE* file_p, const char* file_name, const char* section_name)
{
    size_t file_len = 0;
    char* pos_p = 0;
    const size_t section_name_len = strlen(section_name);
    LOG(FL_TRACE, "Reading configuration until section is found or end of file reached");
    while(0 not_eq fgets(input_line, c_line_buf_size, file_p))
    {
        size_t line_len = strnlen(input_line, c_line_buf_size);
        copy_file_line(file_buffer, input_line, line_len);

        /* break if line matches "\ *\[\ *section_name\ *\]" */
        pos_p = input_line;
        skip_space(&pos_p);
        if(*pos_p++ is_eq '[')
        {
            skip_space(&pos_p);
            if(0 is_eq strncmp(pos_p, section_name, section_name_len))
            {
                pos_p += section_name_len;
                skip_space(&pos_p);
                if(*pos_p is_eq ']')
                {
                    break;
                }
            }
        }
    }
    if(feof(file_p) not_eq 0)
    {
        LOG(FL_ERR, "Cannot find section '%s' in config file '%s'", section_name, file_name);
        return 0;
    }
    return file_len;
}


static size_t add_to_config_section(size_t file_len, const key_val_section* const key_val_section, int exclude,
                                    char* found)
{
    int i = 0;
    key_val_pair* pair = key_val_section->pairs;

    LOG(FL_TRACE, "Checking if entries are missing and adding them to the file");
    for(i = 0; i < key_val_section->count; pair++, i++)
    {
        if(i is_eq exclude)
        {
            continue;
        }
        if(pair->key and not found[i])
        {
            int line_len_aux = snprintf(updated_line, c_line_buf_size, "%s = %s\n", pair->key, pair->val);
            if (line_len_aux < 0)
            {
                LOG(FL_ERR, "Failed to write string");
                return 0;
            }
            size_t line_len = (size_t)line_len_aux;
            copy_file_line(file_buffer, updated_line, line_len);
            LOG(FL_TRACE, "Adding in config file: %s" /*\n*/, updated_line);
            file_modified = 1;
        }
    }

    return file_len;
}


static size_t update_config_section(FILE* file_p, const char* file_name, size_t file_len,
                                    const key_val_section* const key_val_section, int exclude, char* found)
{
    char* pos_p = 0;
    int i = 0;

    file_modified = 0;
/* manipulate the file_buffer */
    LOG(FL_TRACE, "Replacing 'key = value' pairs in the section");
    while(0 not_eq fgets(input_line, c_line_buf_size, file_p))
    {
        size_t line_len = strnlen(input_line, c_line_buf_size);
        if(line_len > c_line_buf_size - 1)
        {
            return 0;
        }
        /* check if the section ends */
        pos_p = input_line;
        skip_space(&pos_p);
        if(*pos_p is_eq '[')
        {
            break;
        }

        /* look if any of the pairs from the update already exists in the config section line */
        key_val_pair* pair = key_val_section->pairs;
        for(i = 0; i < key_val_section->count; pair++, i++)
        {
            if(i is_eq exclude)
            {
                continue;
            }
            if(pair->key and not strncmp(pos_p, pair->key, strlen(pair->key)))
            {
                char* pos_p1 = pos_p + strlen(pair->key);
                skip_space(&pos_p1);
                if(*pos_p1 is_eq '=')
                {
                    break;
                }
            }
        }
        if(i < key_val_section->count)
        { /* key found */
            pair = &key_val_section->pairs[i];
            if(found[i] not_eq 0)
            {
                LOG(FL_ERR, "Error: Duplicate key entry for '%s' in config file '%s'", pair->key, file_name);
                return 0;
            }
            found[i] = 1;
            int line_len_aux = refactor_entry(input_line, updated_line, pair->key, pair->val, c_line_buf_size - 1);
            if (line_len_aux < 0)
            {
                // error already logged
                return 0;
            }
            line_len = (size_t)line_len_aux;
            copy_file_line(file_buffer, updated_line, line_len);
            LOG(FL_TRACE, "Updating in config file: %s" /*\n*/, updated_line);
        }
        else
        {
            /* keep the line from the file */
            copy_file_line(file_buffer, input_line, line_len);
            LOG(FL_TRACE, "Keeping line in config: %s" /*\n*/, input_line);
        }
    }
    if(feof(file_p) not_eq 0)
    { /* special case: section is last one */
        input_line[0] = '\0';
    }

    /* the entries are changed, now add any missing entries to the config file */
    return add_to_config_section(file_len, key_val_section, exclude, found);
}


/* copy the rest of the file into the buffer */
static size_t copy_remaining_config(FILE* file_p, size_t file_len, char* input_line)
{
    size_t line_len = strnlen(input_line, c_line_buf_size); /* first line of next section already read */
    copy_file_line(file_buffer, input_line, line_len);

    while(0 not_eq fgets(input_line, c_line_buf_size, file_p))
    {
        line_len = strnlen(input_line, c_line_buf_size);
        copy_file_line(file_buffer, input_line, line_len);
    }
    return file_len;
}


/* returns length of new file, or 0 in case of error */
int CONF_update_config(OPTIONAL uta_ctx* ctx, const char* file_name, const key_val_section* key_val_section,
                       int exclude)
{
    FILE* file_p = 0;
    size_t file_len = 0;
    int result = 0;
    int i = 0;

    if(0 is_eq file_name or 0 is_eq key_val_section)
    {
        LOG(FL_ERR, "Cannot update config, null pointer argument");
        return 0;
    }

    const char* section_name = key_val_section->name;
    LOG(FL_TRACE, "Handling configuration section '%s' in file '%s'", section_name, file_name);
    /*! @todo must be made thread safe by using some mutex on file */
#ifdef SECUTILS_CONFIG_USE_ICV
    if(0 is_eq FILES_check_icv(ctx, file_name))
    {
        return 0;
    }
#endif
    file_p = fopen(file_name, "r");
    if(0 is_eq file_p)
    {
        LOG(FL_ERR, "Error updating configuration, cannot open file '%s' for reading", file_name);
        return 0;
    }

    char* found = OPENSSL_malloc((size_t)key_val_section->count);
    if(found is_eq 0)
    {
        LOG(FL_ERR, "Cannot update config, out of memory");
        goto error;
    }
    for(i = 0; i < key_val_section->count; i++)
    {
        found[i] = 0;
    }

    file_buffer[0] = '\0';
    file_len = read_config_until_section(file_p, file_name, section_name);
    if(file_len is_eq 0 or c_file_buf_size - 1 < file_len)
    {
        goto error;
    }

    file_len = update_config_section(file_p, file_name, file_len, key_val_section, exclude, found);
    if(file_len is_eq 0 or c_file_buf_size - 1 < file_len)
    {
        goto error;
    }

    file_len = copy_remaining_config(file_p, file_len, input_line);
    if(file_len is_eq 0 or c_file_buf_size - 1 < file_len)
    {
        goto error;
    }

    /* store the new configuration to file */
    if(file_modified not_eq 0)
    {
        if(exclude not_eq UPDATE_CONFIG_EXCLUDE_NONE)
        { /* do not print info for DV files */
            LOG(FL_INFO, "Updating configuration file '%s' section '%s'", file_name, section_name);
        }
        fclose(file_p);
        file_p = fopen(file_name, "w");
        if(0 is_eq file_p)
        {
            LOG(FL_ERR, "Error opening config file '%s' for writing", file_name);
            goto error;
        }

        if(fprintf(file_p, "%s", file_buffer) not_eq file_len)
        {
            file_len = 0;
            LOG(FL_ERR, "Error writing config file '%s'", file_name);
            goto error;
        }
        OPENSSL_free(found);
        fclose(file_p);
#ifdef SECUTILS_CONFIG_USE_ICV
        if(not FILES_protect_icv(ctx, file_name))
        {
            return 0;
        }
#endif
        return file_len;
    }
    else
    {
        LOG(FL_TRACE, "Not necessary to update file '%s'", file_name);
    }
    result = (int)file_len;

error:
    if(file_len is_eq 0)
    {
        LOG(FL_ERR, "Failed updating config, input line longer than %d bytes:\n%s", c_line_buf_size - 1, input_line);
    }
    else if(file_len > c_file_buf_size - 1)
    {
        LOG(FL_ERR, "Failed updating config, file larger than %d bytes", c_file_buf_size - 1);
    }
    OPENSSL_free(found);
    fclose(file_p);
    return result;
}
