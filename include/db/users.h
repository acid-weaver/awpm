/**
 * \file            users.h
 * \brief           User management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Declares functions and data structures for managing users, including
 * creating, querying, and verifying user records.
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

#ifndef USERS_H
#define USERS_H

#include <sqlite3.h>

#include "memory.h"
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

user_t user_init();
int user_set_master_pswd(user_t* user);
int user_verify_master_pswd(const user_t user, const unsigned char* master_key);
int populate_user_from_row(sqlite3_stmt* stmt, user_t* user);

int add_user(sqlite3* db, user_t* user);
int get_user(sqlite3* db, user_t* user);
int get_or_add_user(sqlite3* db, user_t* user);

#endif // USERS_H
