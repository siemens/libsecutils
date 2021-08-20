/** 
* @file crypto.c
* 
* @brief Encrypt/decrypt functions using AES256_GCM
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

#include <operators.h>

#include <util/log.h>
#include <crypto/crypto.h>

static EVP_CIPHER_CTX* AESGCM_ctx_init(int32_t iv_len, pAES_GCM get_cipher_fce)
{
    EVP_CIPHER_CTX* osslctx = EVP_CIPHER_CTX_new();
    if(osslctx is_eq 0)
    {
        LOG(FL_ERR, "Allocating cipher context failed");
        return 0;
    }

    if(EVP_EncryptInit_ex(osslctx, get_cipher_fce(), 0, 0, 0) not_eq 1)
    {
        LOG(FL_ERR, "Encryption init failed");
        EVP_CIPHER_CTX_free(osslctx);
        return 0;
    }

    if(EVP_CIPHER_CTX_ctrl(osslctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, 0) not_eq 1)
    {
        LOG(FL_ERR, "Could not set IV len");
        EVP_CIPHER_CTX_free(osslctx);
        return 0;
    }

    return osslctx;
}


EVP_CIPHER_CTX* AESGCM_init(const uint8_t* key, size_t key_len, const uint8_t* iv,
        size_t iv_len, pAES_GCM get_cipher_fce, pEVP_INIT_EX init_fce)
{
    EVP_CIPHER_CTX* osslctx = 0;

    if(key is_eq 0 or iv is_eq 0)
    {
        LOG(FL_ERR, "Invalid input");
        return 0;
    }

    osslctx = AESGCM_ctx_init(iv_len, get_cipher_fce);
    if(osslctx is_eq 0)
    {
        return 0;
    }

    int key_len_req = EVP_CIPHER_CTX_key_length(osslctx);
    if(key_len_req != key_len)
    {
        LOG(FL_ERR, "Length of provided key doesn't match required by cipher (%d != %d)",
                key_len, key_len_req);
        EVP_CIPHER_CTX_free(osslctx);
        return 0;
    }

    if(init_fce(osslctx, 0, 0, key, iv) not_eq 1)
    {
        LOG(FL_ERR, "Setting key and IV failed");
        EVP_CIPHER_CTX_free(osslctx);
        return 0;
    }

    return osslctx;
}


ssize_t AESGCM_encrypt(EVP_CIPHER_CTX* osslctx, uint8_t* cipher_buff, size_t cipher_buff_len,
        const uint8_t* plain, size_t plain_len)
{
    ssize_t ret = -1;

    if(osslctx is_eq 0 or cipher_buff is_eq 0 or plain is_eq 0)
    {
        LOG(FL_ERR, "Invalid input");
        return ret;
    }

    int32_t cipher_len = cipher_buff_len;
    if((EVP_EncryptUpdate(osslctx, cipher_buff, &cipher_len, plain, plain_len) not_eq 1) or (cipher_len not_eq plain_len))
    {/* The second condition - GCM is used, hence length(plain_text) == length(cipher_text) */
        LOG(FL_ERR, "Encryption failed");
        return ret;
    }

    ret = cipher_len;

    return ret;
}


ssize_t AESGCM_decrypt(EVP_CIPHER_CTX* osslctx, uint8_t* plain_buff, size_t plain_buff_len,
        const uint8_t* cipher, size_t cipher_len)
{
    ssize_t ret = -1;

    if(osslctx is_eq 0 or plain_buff is_eq 0 or cipher is_eq 0)
    {
        LOG(FL_ERR, "Invalid input");
        return ret;
    }

    int32_t plain_len = plain_buff_len;
    if((EVP_DecryptUpdate(osslctx, plain_buff, &plain_len, cipher, cipher_len) not_eq 1)
            or (plain_len not_eq cipher_len))
    {/* The second condition - GCM is used hence length(plain_text) == length(cipher_text) */
        LOG(FL_ERR, "Decryption failed");
        return ret;
    }

    ret = plain_len;

    return ret;
}


bool AESGCM_encrypt_final(EVP_CIPHER_CTX* osslctx, uint8_t* tag_buff, size_t tag_len)
{
    bool ret = false;

    if(osslctx is_eq 0 or (tag_buff is_eq 0 and tag_len not_eq 0) or
            (tag_buff not_eq 0 and tag_len is_eq 0))
    {
        LOG(FL_ERR, "Invalid input");
        return ret;
    }

    if(tag_len > EVP_GCM_TLS_TAG_LEN)
    {
        LOG(FL_ERR, "Required tag length is too big (%d > %d)", tag_len, EVP_GCM_TLS_TAG_LEN);
        return ret;
    }

    int final_len = 0;
    if((EVP_EncryptFinal_ex(osslctx, 0, &final_len) not_eq 1) or (final_len not_eq 0))
    {/* The second condition - GCM should't write any additional bytes */
        LOG(FL_ERR, "Finalization failed!");
        return ret;
    }

    if(tag_buff is_eq 0 and tag_len is_eq 0)
    {
        LOG(FL_INFO, "The tag generation is intentionally omitted - plaintext has been only encrypted!");
        return true;
    }

    if(EVP_CIPHER_CTX_ctrl(osslctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag_buff) not_eq 1)
    {
        LOG(FL_ERR, "Could not obtain the tag!");
        return ret;
    }

    return true;
}


bool AESGCM_decrypt_final(EVP_CIPHER_CTX* osslctx, const uint8_t* tag, size_t tag_len,
        uint8_t* plain_buff, size_t plain_buff_len)
{
    bool ret = false;

    if(osslctx is_eq 0 or (tag is_eq 0 and tag_len not_eq 0) or
            (tag not_eq 0 and tag_len is_eq 0))
    {
        LOG(FL_ERR, "Invalid input");
        return ret;
    }

    if(tag_len > EVP_GCM_TLS_TAG_LEN)
    {
        LOG(FL_ERR, "Required tag length is too big (%d > %d)", tag_len, EVP_GCM_TLS_TAG_LEN);
        return ret;
    }

    if(tag is_eq 0 and tag_len is_eq 0)
    {
        LOG(FL_INFO, "The authentication check is intentionally omitted - ciphertext has been only decrypted!");
        return true;
    }

    uint8_t local_tag[tag_len];
    memcpy(local_tag, tag, tag_len);
    if(EVP_CIPHER_CTX_ctrl(osslctx, EVP_CTRL_GCM_SET_TAG, tag_len, local_tag) not_eq 1)
    {
        LOG(FL_ERR, "Could not set the tag!");
        return ret;
    }

    int final_len = 0;
    if((EVP_DecryptFinal_ex(osslctx, 0, &final_len) not_eq 1) or (final_len not_eq 0))
    {/* The second condition - GCM should't write any additional bytes */
        LOG(FL_ERR, "Tag did not match!");
        if(plain_buff not_eq 0)
        {
            memset(plain_buff, 0x00, plain_buff_len);
        }
        return ret;
    }

    return true;
}


bool AESGCM_free_context(EVP_CIPHER_CTX** osslctx)
{
    if(osslctx is_eq 0)
    {
        LOG(FL_ERR, "Invalid input");
        return false;
    }

    EVP_CIPHER_CTX_free(*osslctx);
    *osslctx = 0;
    return true;
}
