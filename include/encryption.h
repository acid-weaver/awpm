#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// #include "memory.h"
#include "memory.h"
struct sqlite3;
#include <openssl/evp.h>


int generate_key_from_password(struct sqlite3 *db, const char *username, const char *password, unsigned char *key);
int encrypt_password(const unsigned char *key, dynamic_string_t plaintext,
                 unsigned char *iv, unsigned char **ciphertext,
                 size_t *ciphertext_len);
int decrypt_password(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len, const unsigned char *iv, char **plaintext);

#endif // ENCRYPTION_H

