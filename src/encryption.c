#include "encryption.h"
#include "memory.h"
#include "utils.h"
#include "users.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>


int
binary_array_random(binary_array_t bin_arr) {
    if (bin_arr.ptr == NULL || bin_arr.size == 0) {
        fprintf(stderr, "Invalid dynamic string: NULL pointer or zero size.\n");
        return -1;
    }

    if (RAND_bytes(bin_arr.ptr, bin_arr.size) != 1) {
        handle_errors("Failed to generate random data");
    }
    return 0;
}

int
generate_key_from_password(struct sqlite3 *db, const int user_id,
                           const char *password, unsigned char *key) {
    unsigned char salt[SALT_SIZE];

    if (get_salt_by_user_id(db, user_id, salt) != 0) {
        fprintf(stderr, "Failed to retrieve salt for user: %d\n", user_id);
        return -1;
    }

    if (DEBUG) {
        printf("DEBUG generate_key_from_password\n");
        printf("\tSalt (Hex): ");
        for (int i = 0; i < SALT_SIZE; i++) {
            printf("%02x", salt[i]);
        }
        printf("\n");
    }

    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE,
                           ITERATIONS, EVP_sha256(), KEY_SIZE, key)) {
        handle_errors("Key derivation failed");
    }

    return 0;
}

int
encrypt_string(const unsigned char* key, unsigned char* iv,
               binary_array_t plaintext, binary_array_t* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;

    if (ctx == NULL) {
        handle_errors("Failed to create encryption context");
    }

    if (key == NULL || iv == NULL || plaintext.ptr == NULL ||
        plaintext.size == 0 || plaintext.len == 0 || ciphertext == NULL) {
        fprintf(stderr, "Input parameters to encryption function are invalid.\n");
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

    if (DEBUG) {
        printf("DEBUG encrypt_password data BEFORE ENCRYPTION:\n\tKey (Hex): ");
        for (int i = 0; i < KEY_SIZE; i++) printf("%02x", key[i]);
        printf("\n");
        printf("\tIV (Hex): ");
        for (size_t i = 0; i < IV_SIZE; i++) printf("%02x", iv[i]);
        printf("\n");
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext->ptr, &len, plaintext.ptr, plaintext.len) != 1) {
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

int decrypt_string(const unsigned char *key, const unsigned char *ciphertext,
                   int ciphertext_len, const unsigned char *iv, char **plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int plaintext_len = 0, len = 0;

    if (!ctx) {
        handle_errors("Failed to create decryption context");
    }

    if (DEBUG) {
        printf("DEBUG decrypt_password data BEFORE DECRYPTION:\n\tKey (Hex): ");
        for (int i = 0; i < KEY_SIZE; i++) printf("%02x", key[i]);
        printf("\n");
        printf("\tIV (Hex): ");
        for (size_t i = 0; i < IV_SIZE; i++) printf("%02x", iv[i]);
        printf("\n");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_errors("Failed to initialize AES decryption");
    }

    *plaintext = malloc(ciphertext_len + 1);
    if (!*plaintext) {
        handle_errors("Memory allocation for plaintext failed");
    }

    if (EVP_DecryptUpdate(ctx, (unsigned char *)*plaintext, &len, ciphertext, ciphertext_len) != 1) {
        handle_errors("Failed during AES decryption update");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)*plaintext + len, &len) != 1) {
        printf("Cannot decipher encrypted data with provided password!");
        handle_errors("Failed during AES decryption final step");
    }
    plaintext_len += len;

    (*plaintext)[plaintext_len] = '\0'; // Null-terminate the string

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

