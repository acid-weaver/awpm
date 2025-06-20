/**
 * \file            users.c
 * \brief           Implementation of user management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the user management functions declared in db.h.
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

#include <grp.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "db.h"
#include "encryption.h"
#include "mem.h"
#include "utils.h"

const char* get_current_username() {
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_name : NULL;
}

int is_user_in_group(const char* user, const char* group) {
    struct group* grp = getgrnam(group);

    if (!grp) {
        fprintf(stderr, "Group '%s' not found.\n", group);
        return -1; // Group does not exist
    }

    for (char** members = grp->gr_mem; *members; members++) {
        if (strcmp(*members, user) == 0) {
            return 1; // User is already in group
        }
    }

    return 0; // User is not in group
}

int add_user_to_group(const char* username, const char* group) {
    char command[INPUT_BUFF_SIZE * 3];

    snprintf(command, sizeof(command), "sudo usermod -aG %s %s", group,
             username);
    if (system(command) == -1) {
        perror("Failed to execute command");
        return -1;
    }

    printf("User %s added to group %s.\n", username, group);
    return 0;
}

int apply_group_membership(const char* group) {
    char command[INPUT_BUFF_SIZE * 2];

    printf(MSG_APPLY_GROUP_MEMBERSHIP);
    snprintf(command, sizeof(command), "newgrp %s", group);

    if (system(command) == -1) {
        perror("Failed to execute command");
        return -1;
    }

    return 0;
}

user_t user_init() {
    user_t user = {
        .id          = -1,
        .username    = "",
        .salt        = {0},
        .master_iv   = {0},
        .master_pswd = {0},
        .hash        = {0},
    };
    const char* username = NULL;

    username = get_current_username();
    if (username != NULL) {
        strncpy(user.username, username, sizeof(user.username) - 1);
        user.username[sizeof(user.username) - 1] = '\0'; // Null-terminate

        if (is_user_in_group(username, ACCESS_GROUP) == 0) {
            add_user_to_group(username, ACCESS_GROUP);
            apply_group_membership(ACCESS_GROUP);
        }
    } else {
        fprintf(stderr,
                "Error: Unable to determine current user's username.\n");
        user.username[0] =
            '\0'; // Set username to an empty string as a fallback
    }

    return user;
}

int user_set_master_pswd(user_t* user) {
    binary_array_t random_bytes = {0}, ciphered_random = {0},
                   secure_buffer = {0}, ciphered_buffer = {0},
                   session_key = {0}, master_key = {0};
    unsigned char session_iv[IV_SIZE];

    /*
     * Initialize some required later variables
     */

    if (generate_random_bytes(user->master_iv, IV_SIZE) != 0) {
        fprintf(stderr, "Failed to generate IV for master password.\n");
        return -1;
    }

    session_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_random_bytes(session_key.ptr, KEY_SIZE) != 0) {
        fprintf(stderr, "Failed to generate session key.\n");
        return -1;
    }
    session_key.len = KEY_SIZE;

    if (generate_random_bytes(session_iv, IV_SIZE) != 0) {
        binary_array_secure_free(&session_key);
        fprintf(stderr, "Failed to generate session IV.\n");
        return -1;
    }

    random_bytes = binary_array_secure_alloc(IV_SIZE);
    if (generate_random_bytes(random_bytes.ptr, random_bytes.size) != 0) {
        fprintf(stderr, "Failed to generate random data.\n");
        return -1;
    }
    random_bytes.len = random_bytes.size;

    user->hash = binary_array_alloc(HASH_SIZE);
    if (generate_hash(random_bytes.ptr, random_bytes.len, &user->hash) != 0) {
        fprintf(stderr, "Failed to generate hash from random bytes.\n");
    }

    if (encrypt_data(session_key.ptr, session_iv, random_bytes,
                     &ciphered_random)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&random_bytes);
        handle_errors("Failed temporarily encrypt memory data.");
    }
    binary_array_secure_free(&random_bytes);

    /*
     * Start of main logic - actually ask master password from user, ask to
     * confirm this value and cipher random bytes with derived from this
     * password key. Store cipher values.
     */

    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", "", (char*)secure_buffer.ptr,
                     secure_buffer.size)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&random_bytes);
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Error reading master password.\n");
        return -1;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    if (encrypt_data(session_key.ptr, session_iv, secure_buffer,
                     &ciphered_buffer)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&random_bytes);
        binary_array_secure_free(&secure_buffer);
        handle_errors("Failed to temporarily ciphrate data.");
    }
    binary_array_secure_free(&secure_buffer);

    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", PSWD_CONFIRMATION,
                     (char*)secure_buffer.ptr, INPUT_BUFF_SIZE)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&random_bytes);
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Error reading confirmation of master password.\n");
        return -1;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    if (decrypt_data(session_key.ptr, session_iv, ciphered_buffer,
                     &ciphered_buffer)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&random_bytes);
        binary_array_secure_free(&secure_buffer);
        handle_errors("Failed to decipher temporarily ciphered memory data.");
    }

    if (secure_buffer.len != ciphered_buffer.len
        || strncmp((char*)secure_buffer.ptr, (char*)ciphered_buffer.ptr,
                   secure_buffer.len)
               != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&random_bytes);
        binary_array_secure_free(&secure_buffer);
        binary_array_secure_free(&ciphered_buffer);
        fprintf(stderr, "Entered values are different! Try again.\n");
        return 1;
    }
    binary_array_secure_free(&ciphered_buffer);

    if (decrypt_data(session_key.ptr, session_iv, ciphered_random,
                     &random_bytes)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&random_bytes);
        binary_array_secure_free(&secure_buffer);
        handle_errors("Failed to decrypt temporarily encrypted memory data.");
    }
    binary_array_secure_free(&session_key);

    master_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_key_from_password(user->salt, (char*)secure_buffer.ptr,
                                   master_key.ptr)
        != 0) {
        binary_array_secure_free(&secure_buffer);
        binary_array_secure_free(&master_key);
        binary_array_free(&random_bytes);
        handle_errors("Failed to generate key from entered master password.\n");
    }
    binary_array_secure_free(&secure_buffer);
    master_key.len = KEY_SIZE;

    if (encrypt_data(master_key.ptr, user->master_iv, random_bytes,
                     &user->master_pswd)
        != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&random_bytes);
        handle_errors("Failed to cipher data.");
    }
    binary_array_secure_free(&master_key);
    binary_array_secure_free(&random_bytes);
    return 0;
}

int user_verify_master_key(const user_t user, const unsigned char* master_key) {
    binary_array_t random_bytes = {0}, hash = {0};

    if (master_key == NULL) {
        fprintf(stderr,
                "Missing password to verify in verify_master_pswd function.\n");
        return -1;
    }

    if (decrypt_data(master_key, user.master_iv, user.master_pswd,
                     &random_bytes)
        != 0) {
        binary_array_secure_free(&random_bytes);
        fprintf(
            stderr,
            "Failed to verify provided password at 1st verification step.\n");
        return 1;
    }

    hash = binary_array_alloc(HASH_SIZE);
    if (generate_hash(random_bytes.ptr, random_bytes.len, &hash) != 0) {
        binary_array_secure_free(&random_bytes);
        handle_errors("Failed to generate hash from decrypted random data.");
    }
    binary_array_secure_free(&random_bytes);

    if (user.hash.len != hash.len
        || memcmp(user.hash.ptr, hash.ptr, hash.len) != 0) {
        fprintf(stderr,
                "Failed to verify master password at 2nd verification step.\n");
        return 1;
    } else {
        printf("OK\n");
    }

    if (cfg.debug) {
        printf("==========\n");
        printf("DEBUG. Entered user_verify_master_pswd.\n");
        printf("DEBUG. user hash: %s\n", binary_array_to_string(&user.hash));
        printf("\thash from master_password: %s\n",
               binary_array_to_string(&hash));
        printf("==========\n");
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
        fprintf(stderr, "Invalid or missing master_iv for user: %s\n",
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
        fprintf(stderr, "Invalid or missing master_pswd for user: %s\n",
                user->username);
        return -1;
    }

    // Populate `hash`
    buffer      = sqlite3_column_blob(stmt, 5);
    buffer_size = sqlite3_column_bytes(stmt, 5);
    if (buffer != NULL && buffer_size > 0) {
        user->hash = binary_array_alloc(buffer_size);
        memcpy(user->hash.ptr, buffer, buffer_size);
        user->hash.len = buffer_size;
    } else {
        fprintf(stderr, "Invalid or missing hash for user: %s\n",
                user->username);
        return -1;
    }

    return 0; // Success
}

int add_user(sqlite3* db, user_t* user) {
    sqlite3_stmt* stmt;
    const char* sql_insert =
        "INSERT INTO users (username, salt, master_iv, master_pswd, hash) "
        "VALUES (?, ?, ?, ?, ?);";
    int rc;

    if (RAND_bytes(user->salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Failed to generate salt.\n");
        return -1;
    }

    printf(
        "You need to set your master password, which would be used via "
        "cryptographic algoritms to cypher and decipher your data. Pay "
        "ATTENTION that you will LOSE your data in case you forget it. For "
        "security reasons there is no way to restore data without master pass "
        "in acceptable terms.\n");

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
    sqlite3_bind_blob(stmt, 3, user->master_iv, IV_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, user->master_pswd.ptr, user->master_pswd.len,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, user->hash.ptr, user->hash.len,
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
        "SELECT id, username, salt, master_iv, master_pswd, hash FROM users "
        "WHERE username = ?;";
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
