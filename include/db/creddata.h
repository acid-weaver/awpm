/**
 * \file            creddata.h
 * \brief           Credential management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Declares functions and data structures for managing credentials, including
 * adding, updating and retrieving.
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

