/** 
* @file crypto.h
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

#ifndef SECUTILS_CRYPTO_H_
#define SECUTILS_CRYPTO_H_

#include <openssl/x509.h>

typedef int (*pEVP_INIT_EX)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, const unsigned char *key, const unsigned char *iv);

typedef const EVP_CIPHER* (*pAES_GCM)(void);

/*!
 * @brief The function creates and initialises the context of encryption/description
 *        operation. And after that the function sets length of initialization vector (IV)
 *
 * @param key key used for encryption and integrity protection
 * @param key_len size of key
 * @note  key size have to match key size required by chosen cipher (256b,192b,128b)
 * @param iv pointer to IV
 * @param iv_len size of IV
 * @param get_cipher_fce pointer to function returning cipher type
 *        (acceptable values - EVP_aes_256_gcm, EVP_aes_192_gcm, EVP_aes_128_gcm)
 * @param init_fce pointer to function which initializes encryption/decryption
 *        encryption - EVP_EncryptInit_ex
 *        decryption - EVP_DecryptInit_ex
 *
 * @return  pointer to initialized context of encryption operation
 *          0 on failure
 */
EVP_CIPHER_CTX* AESGCM_init(const uint8_t* key, size_t key_len, const uint8_t* iv,
        size_t iv_len, pAES_GCM get_cipher_fce, pEVP_INIT_EX init_fce);


/*!
 * @brief The function encrypts data by AESXXX_GCM cipher (XXX = 256,192,128).
 *
 * @param osslctx pointer to context of encryption operation
 * @param cipher_buff pointer to buffer used to store resulting cipher text
 * @param cipher_buff_len size of buffer used to store resulting cipher text
 * @param plain pointer to plain text to be encrypted
 * @param plain_len size of cipher text to be encrypted
 *
 * @return  size of resulting cipher text
 *          -1 on failure
 */
ssize_t AESGCM_encrypt(EVP_CIPHER_CTX* osslctx, uint8_t* cipher_buff, size_t cipher_buff_len,
        const uint8_t* plain, size_t plain_len);

/*!
 * @brief The function decrypts data encrypted by AESXXX_GCM cipher (XXX = 256,192,128).
 *        Used algorithm and key length depends on context initialization (see AESGCM_init)
 *
 * @param osslctx pointer to context of decryption operation
 * @param plain_buff pointer to buffer used to store resulting plain text
 * @param plain_buff_len size of buffer used to store resulting plain text
 * @param cipher pointer to cipher text to be decrypted
 * @param cipher_len size of cipher text to be decrypted
 *
 * @return  size of resulting plain text
 *          -1 on failure
 */
ssize_t AESGCM_decrypt(EVP_CIPHER_CTX* osslctx, uint8_t* plain_buff, size_t plain_buff_len,
        const uint8_t* cipher, size_t cipher_len);


/*!
 * @brief The function finalizes encryption and store tag (integrity protection value).
 *
 * @param osslctx pointer to context of decryption operation
 * @param tag_buff     pointer to buffer used to store tag
 * @param tag_len      size of resulting tag to be stored in tag_buff
 * @note  If tag_buff is set to null and tag_len is set to 0 then tag will not be generated
 *
 * @return  true  on success
 *          false on failure
 */
bool AESGCM_encrypt_final(EVP_CIPHER_CTX* osslctx, uint8_t* tag_buff, size_t tag_len);


/*!
 * @brief The function finalizes decryption and checks tag (integrity protection value).
 *
 * @param osslctx pointer to context of decryption operation
 * @param tag     pointer to tag
 * @param tag_len size of tag
 * @note  If tag_buff is set to null and tag_len is set 0 then authenticity will not be checked
 * @param plain   pointer to plain text obtained by calling AESGCM_decrypt or null
 * @note  on failure the function cleans plain text if parameter plain is not null
 * @param plain_len size of plain text
 *
 * @return  true  on success
 *          false on failure
 */
bool AESGCM_decrypt_final(EVP_CIPHER_CTX* osslctx, const uint8_t* tag, size_t tag_len,
        uint8_t* plain, size_t plain_len);


/*!
 * @brief The function clears all information from a cipher context and sets *ossctx to zero.
 *
 * @param osslctx pointer to pointer to context of encryption/decryption operation
 *
 * @return  true  on success
 *          false on failure
 */
bool AESGCM_free_context(EVP_CIPHER_CTX** osslctx);


#define AES256GCM_encrypt_init(key, key_len, iv, iv_len) AESGCM_init(key, key_len, iv, iv_len, EVP_aes_256_gcm, EVP_EncryptInit_ex)
#define AES256GCM_decrypt_init(key, key_len, iv, iv_len) AESGCM_init(key, key_len, iv, iv_len, EVP_aes_256_gcm, EVP_DecryptInit_ex)

#endif /* SECUTILS_CRYPTO_H_ */
