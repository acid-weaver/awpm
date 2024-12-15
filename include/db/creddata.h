#ifndef CREDDATA_H
#define CREDDATA_H

#include "memory.h"
#include "utils.h"
#include <sqlite3.h>

typedef struct {
    int id;
    int owner;
    char source[INPUT_BUFF_SIZE];
    char login[INPUT_BUFF_SIZE];
    char email[INPUT_BUFF_SIZE];
    unsigned char iv[IV_SIZE];
    binary_array_t pswd;
} cred_data_t;

void print_credential_data(cred_data_t *credential_data);
int add_credential(sqlite3 *db, cred_data_t credential_data, const unsigned char *key);
int retrieve_and_decipher_by_source(sqlite3 *db, const char *source, const unsigned char *key, char ***results, int *result_count);

#endif // CREDDATA_H

