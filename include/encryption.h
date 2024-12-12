#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// #include "memory.h"
#include "memory.h"
struct sqlite3;
#include <openssl/evp.h>


int dynamic_string_random_bytes(dynamic_string_t dyn_str);
int generate_key_from_password(struct sqlite3 *db, const int user_id,
                               const char *password, unsigned char *key);
int encrypt_string(const unsigned char *key, dynamic_string_t plaintext,
                   unsigned char *iv, unsigned char **ciphertext,
                   size_t *ciphertext_len);
int decrypt_string(const unsigned char *key, const unsigned char *ciphertext,
                   int ciphertext_len, const unsigned char *iv, char **plaintext);

#endif // ENCRYPTION_H

