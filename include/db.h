/**
 * \file            db.h
 * \brief           Database managment utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * This file declares functions and structures to operate with data and SQLite
 * database.
 */

/* Copyright (C) 2024-2025  Acid Weaver <acid.weaver@gmail.com>
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

#ifndef DB_H
#define DB_H

#include <sqlite3.h>

#include "mem.h"
#include "utils.h"

#define ACCESS_GROUP "awpm"
#define USER_REGISTERED "Current user successfully registered to use AWPM.\n"
#define MSG_APPLY_GROUP_MEMBERSHIP                               \
    "To apply group membership shell session will be reloaded. " \
    "Repeat command after again.\n"

typedef struct {
    int id; // Primary key
    char username[INPUT_BUFF_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char master_iv[IV_SIZE];
    binary_array_t master_pswd;
    binary_array_t hash;
} user_t;

typedef struct {
    int id;
    int owner;
    char source[INPUT_BUFF_SIZE];
    char login[INPUT_BUFF_SIZE];
    char email[INPUT_BUFF_SIZE];
    unsigned char iv[IV_SIZE];
    binary_array_t pswd;
} cred_data_t;

/*
 * General
 */

int initialize_database(sqlite3** db);

/*
 * User related
 */

user_t user_init();
int user_set_master_pswd(user_t* user);
int user_verify_master_key(const user_t user, const unsigned char* master_key);
int populate_user_from_row(sqlite3_stmt* stmt, user_t* user);

int add_user(sqlite3* db, user_t* user);
int get_user(sqlite3* db, user_t* user);
int get_or_add_user(sqlite3* db, user_t* user);

/*
 * Credential data related
 */

int cred_data_populate(sqlite3_stmt* stmt, cred_data_t* credential_data);
char* cred_data_to_string(const cred_data_t* credential_data);
int upsert_cred_data(sqlite3* db, const cred_data_t* credential_data);
int get_cred_data_for_update(sqlite3* db, const user_t user, const int step,
                             const cred_data_t search_by, cred_data_t* result);
int get_cred_data_by_source(sqlite3* db, const user_t user, const char* source,
                            cred_data_t** results, int* result_count);
int delete_cred_data(sqlite3* db, const user_t user,
                     const cred_data_t to_delete);

#endif // DB_H
