/**
 * \file            users.c
 * \brief           Implementation of user management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the user management functions declared in users.h.
 */

/* Copyright (C) 2024  Acid Weaver <acid.weaver@gmail.com>
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

#include "db/users.h"

#include <openssl/rand.h>
#include <pwd.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "encryption.h"
#include "memory.h"
#include "secure_memory.h"
#include "utils.h"

const char* get_current_username() {
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_name : NULL;
}

user_t user_init() {
    user_t user = {
        .id        = -1,
        .username  = "",
        .salt      = {0},
        .master_iv = {0},
        .master_pswd =
            {
                .size = 0,
                .len  = 0,
                .ptr  = NULL,
            },
    };
    const char* username = NULL;

    username = get_current_username();
    if (username != NULL) {
        strncpy(user.username, username, sizeof(user.username) - 1);
        user.username[sizeof(user.username) - 1] = '\0'; // Null-terminate
    } else {
        fprintf(stderr,
                "Error: Unable to determine current user's username.\n");
        user.username[0] =
            '\0'; // Set username to an empty string as a fallback
    }

    return user;
}

int user_set_master_pswd(user_t* user) {
    binary_array_t random_bytes =
                       {
                           .size = 0,
                           .len  = 0,
                           .ptr  = NULL,
                       },
                   secure_buffer =
                       {
                           .size = 0,
                           .len  = 0,
                           .ptr  = NULL,
                       },
                   hash =
                       {
                           .size = 0,
                           .len  = 0,
                           .ptr  = NULL,
                       },
                   confirm_hash = {
                       .size = 0,
                       .len  = 0,
                       .ptr  = NULL,
                   };
    unsigned char key[KEY_SIZE];

    random_bytes = binary_array_alloc(IV_SIZE);
    if (generate_random_bytes(random_bytes.ptr, random_bytes.size) != 0) {
        handle_errors("Failed to generate random data.");
    }
    random_bytes.len = random_bytes.size;

    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", "", (char*)secure_buffer.ptr,
                     secure_buffer.size)
        != 0) {
        fprintf(stderr, "Error reading master password.\n");
        return -1;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    hash = binary_array_alloc(HASH_SIZE);
    if (generate_hash((char*)secure_buffer.ptr, &hash) != 0) {
        handle_errors("Failed to generate hash from provided value.");
    }

    if (secure_input("master password", PSWD_CONFIRMATION,
                     (char*)secure_buffer.ptr, INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error reading confirmation of master password.\n");
        return -1;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    confirm_hash = binary_array_alloc(HASH_SIZE);
    if (generate_hash((char*)secure_buffer.ptr, &confirm_hash) != 0) {
        handle_errors("Failed to generate hash from provided value.");
    }

    if (hash.len != confirm_hash.len
        || memcmp(hash.ptr, confirm_hash.ptr, hash.len) != 0) {
        fprintf(stderr, "Entered values for master password are different!\n");
        return 1;
    }

    if (generate_key_from_password(user->salt, master_pswd, key) != 0) {
        fprintf(stderr, "Failed to generate key from master password.\n");
        return -1;
    }

    if (generate_random_bytes(user->master_iv, IV_SIZE) != 0) {
        handle_errors("Failed to generate IV.");
    }

    if (encrypt_data(key, user->master_iv, random_bytes, &user->master_pswd)
        != 0) {
        handle_errors("Failed to encrypt master password.");
    }

    return 0;
}

int user_verify_master_pswd(const user_t user, const unsigned char* key) {
    binary_array_t random_bytes = {
        .size = 0,
        .len  = 0,
        .ptr  = NULL,
    };

    if (decrypt_data(key, user.master_iv, user.master_pswd, &random_bytes)
        != 0) {
        fprintf(stderr,
                "Failed to verify your master password, ensure you entered "
                "right value.\n");
        return 1;
    } else {
        printf("Master password successfully verified!\n");
    }

    return 0;
}

int populate_user_from_row(sqlite3_stmt* stmt, user_t* user) {
    const char* username = NULL;
    const void* buffer   = NULL;
    int buffer_size      = 0;

    if (user == NULL) {
        fprintf(stderr, "Invalid user_t pointer provided.\n");
        return -1;
    }

    // Reset the user struct
    memset(user, 0, sizeof(user_t));

    // Populate `id`
    user->id = sqlite3_column_int(stmt, 0);

    // Populate `username`
    username = (const char*)sqlite3_column_text(stmt, 1);
    if (username) {
        strncpy(user->username, username, sizeof(user->username) - 1);
        user->username[sizeof(user->username) - 1] = '\0';
    }

    // Populate `salt`
    buffer      = sqlite3_column_blob(stmt, 2);
    buffer_size = sqlite3_column_bytes(stmt, 2);
    if (buffer != NULL && buffer_size == SALT_SIZE) {
        memcpy(user->salt, buffer, SALT_SIZE);
    } else {
        fprintf(stderr, "Invalid or missing salt for user: %s\n",
                user->username);
        return -1;
    }

    // Populate `master_iv`
    buffer      = sqlite3_column_blob(stmt, 3);
    buffer_size = sqlite3_column_bytes(stmt, 3);
    if (buffer != NULL && buffer_size == IV_SIZE) {
        memcpy(user->master_iv, buffer, IV_SIZE);
    } else {
        fprintf(stderr, "Invalid or missing master IV for user: %s\n",
                user->username);
        return -1;
    }

    // Populate `master_pswd`
    buffer      = sqlite3_column_blob(stmt, 4);
    buffer_size = sqlite3_column_bytes(stmt, 4);
    if (buffer != NULL && buffer_size > 0) {
        user->master_pswd = binary_array_alloc(buffer_size);
        memcpy(user->master_pswd.ptr, buffer, buffer_size);
        user->master_pswd.len = buffer_size;
    } else {
        fprintf(stderr, "Invalid or missing master password for user: %s\n",
                user->username);
        return -1;
    }

    return 0; // Success
}

int add_user(sqlite3* db, user_t* user) {
    sqlite3_stmt* stmt;
    const char* sql_insert =
        "INSERT INTO users (username, salt, master_iv, master_pswd) VALUES (?, "
        "?, ?, ?);";
    int rc;

    if (RAND_bytes(user->salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Failed to generate salt.\n");
        return -1;
    }

    if (user_set_master_pswd(user) != 0) {
        fprintf(stderr, "Failed to set master password, retry again.\n");
        return -1;
    }

    rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare insert statement: %s\n",
                sqlite3_errmsg(db));
        return rc;
    }

    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, user->salt, SALT_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, user->master_iv, IV_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, user->master_pswd.ptr, user->master_pswd.len,
                      SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert user: %s\n", sqlite3_errmsg(db));
    }

    user->id = sqlite3_last_insert_rowid(db);

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int get_user(sqlite3* db, user_t* user) {
    sqlite3_stmt* stmt = NULL;
    const char* sql_query =
        "SELECT id, username, salt, master_iv, master_pswd FROM users WHERE "
        "username = ?;";
    int rc = 0;

    if (user == NULL || strlen(user->username) == 0) {
        fprintf(stderr,
                "Invalid user_t user provided to get_user: username must be "
                "provided.\n");
        return -1;
    }

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Bind the username parameter
    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // user exists, populate it
        if (populate_user_from_row(stmt, user) != 0) {
            fprintf(stderr, "Failed to populate user_t from row.\n");
            sqlite3_finalize(stmt);
            return -1;
        }

        sqlite3_finalize(stmt);
        return 0;

    } else if (rc == SQLITE_DONE) {
        // user does not exist
        fprintf(stderr, "No user found with username: %s.\n", user->username);
        sqlite3_finalize(stmt);
        return 1;

    } else {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1; // Query failed
    }
    return 0;
}

int get_or_add_user(sqlite3* db, user_t* user) {
    int get_result = 0;

    if (user == NULL || strlen(user->username) == 0) {
        fprintf(stderr,
                "Invalid user_t user provided to get_or_add_user: username "
                "field must be provided.\n");
        return -1;
    }

    get_result = get_user(db, user);
    if (get_result == 0) {
        // user exists, get_user already provided info in user
        return 0;

    } else if (get_result == 1) {
        // user does not exist, add
        fprintf(stderr, "Adding %s to database.\n", user->username);

        if (add_user(db, user) != 0) {
            fprintf(stderr, "Failed to add new user with username: %s.\n",
                    user->username);
            return -1;
        }

        return 0;

    } else {
        // Unexpected error in get_user
        fprintf(stderr, "Error retrieving user '%s' from database.\n",
                user->username);
        return -1;
    }
}

int write_master_pswd(sqlite3* db, const int user_id,
                      const binary_array_t master_pswd,
                      const unsigned char* master_iv) {
    sqlite3_stmt* stmt;
    const char* sql_update =
        "UPDATE users SET master_iv = ?, master_pswd = ? WHERE id = ?;";

    int rc = sqlite3_prepare_v2(db, sql_update, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare update statement: %s\n",
                sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, master_iv, IV_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, master_pswd.ptr, master_pswd.len,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update master_pswd: %s\n",
                sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}
