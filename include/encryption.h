#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "memory.h"


int binary_array_random(binary_array_t* bin_arr);
int generate_key_from_password(const unsigned char* salt, const char* password,
                               unsigned char* key);
int encrypt_string(const unsigned char* key, unsigned char* iv,
                   const binary_array_t plaintext, binary_array_t* ciphertext);
int decrypt_string(const unsigned char* key, const unsigned char* iv,
                   const binary_array_t ciphertext, binary_array_t* plaintext);

#endif // ENCRYPTION_H

