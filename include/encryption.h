#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// #include "memory.h"
#include "memory.h"
struct sqlite3;
#include <openssl/evp.h>


int binary_array_random(binary_array_t* bin_arr);
int generate_key_from_password(struct sqlite3* db, const int user_id,
                               const char* password, unsigned char* key);
int encrypt_string(const unsigned char* key, unsigned char* iv,
                   binary_array_t plaintext, binary_array_t* ciphertext);
int decrypt_string(const unsigned char* key, const unsigned char* ciphertext,
                   int ciphertext_len, const unsigned char* iv, char** plaintext);

#endif // ENCRYPTION_H

