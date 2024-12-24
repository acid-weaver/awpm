/**
 * \file            encryption.c
 * \brief           Implementation of encryption utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the encryption and decryption functions declared in encryption.h.
 */

/* Copyright (C) 2024  Acid Weaver acid.weaver@gmail.com
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "encryption.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "memory.h"
#include "utils.h"

int binary_array_random(binary_array_t* bin_arr) {
    if (bin_arr->ptr == NULL || bin_arr->size == 0) {
        fprintf(stderr, "Invalid dynamic string: NULL pointer or zero size.\n");
        return -1;
    }

    if (RAND_bytes(bin_arr->ptr, bin_arr->size) != 1) {
        handle_errors("Failed to generate random data");
    }

    bin_arr->len = bin_arr->size;
    return 0;
}

int generate_key_from_password(const unsigned char* salt, const char* password,
                               unsigned char* key) {
    if (salt == NULL || password == NULL || strlen(password) == 0) {
        fprintf(stderr,
                "Incorrect input parameters to generate_key_from_password.\n");
        return -1;
    }

    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE,
                           ITERATIONS, EVP_sha256(), KEY_SIZE, key)) {
        handle_errors("Key derivation failed");
    }

    return 0;
}

int encrypt_string(const unsigned char* key, unsigned char* iv,
                   const binary_array_t plaintext, binary_array_t* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    if (ctx == NULL) {
        handle_errors("Failed to create encryption context");
    }

    if (key == NULL || iv == NULL || plaintext.ptr == NULL ||
        plaintext.size == 0 || plaintext.len == 0 || ciphertext == NULL) {
        fprintf(stderr,
                "Input parameters to encryption function are invalid.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Generate random IV
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        handle_errors("Failed to generate IV");
    }

    // Initialize AES encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_errors("Failed to initialize AES encryption");
    }

    // Prepare ciphertext buffer
    *ciphertext = binary_array_alloc(plaintext.len +
                                     EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (ciphertext->ptr == NULL) {
        handle_errors("Memory allocation for ciphertext failed");
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext->ptr, &len, plaintext.ptr,
                          plaintext.len) != 1) {
        handle_errors("Failed during AES encryption update");
    }
    ciphertext->len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext->ptr + len, &len) != 1) {
        handle_errors("Failed during AES encryption final step");
    }
    ciphertext->len += len;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int decrypt_string(const unsigned char* key, const unsigned char* iv,
                   const binary_array_t ciphertext, binary_array_t* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    if (!ctx) {
        handle_errors("Failed to create decryption context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_errors("Failed to initialize AES decryption");
    }

    *plaintext = binary_array_alloc(ciphertext.len + 1);
    if (plaintext == NULL) {
        handle_errors("Memory allocation for plaintext failed");
    }

    if (EVP_DecryptUpdate(ctx, plaintext->ptr, &len, ciphertext.ptr,
                          ciphertext.len) != 1) {
        handle_errors("Failed during AES decryption update");
    }
    plaintext->len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext->ptr + len, &len) != 1) {
        fprintf(stderr, "Failed during AES decryption final step.\n");
        return 1;
    }
    plaintext->len += len;

    (plaintext->ptr)[plaintext->len] = '\0';  // Null-terminate the string

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
