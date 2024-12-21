#ifndef CREDDATA_H
#define CREDDATA_H

#include "memory.h"
#include "utils.h"
#include "db/users.h"
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

int populate_cred_data_from_row(sqlite3_stmt* stmt, cred_data_t* credential_data);
char* cred_data_to_string(const cred_data_t* credential_data);
int upsert_cred_data(sqlite3* db, const cred_data_t* credential_data);
int get_credentials_by_source(sqlite3* db, const user_t user, const char* source,
                              cred_data_t** results, int* result_count);
int retrieve_and_decipher_by_source(sqlite3* db, const char* source,
                                    const unsigned char* key, char*** results,
                                    int* result_count);

#endif // CREDDATA_H

