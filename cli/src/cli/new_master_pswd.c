/**
 * \file            cli/new_master_pswd.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface function nahdle_new_master_pswd
 * declared in cli.h.
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

#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "cli/cli.h"
#include "cli/cli_utils.h"
#include "cli/msg.h"
#include "core/db.h"
#include "core/encryption.h"
#include "lib/awpm_utils.h"
#include "lib/mem.h"

void handle_new_master_pswd(struct sqlite3* db, user_t* user) {
    /*
     *  1. Ask current master password, verify it, temporarily cipher
     *  2. Ask new master pswd, generate key
     *  3. Create new db, init current user, set it's master pswd to new
     *  4. Decipher entry from old db, ciqher it with new key and write to new
     * db
     *  5. Clear memory
     *  6. Backup old db, replace it with new db
     */

    sqlite3* new_db           = NULL;
    user_t new_user           = {0};
    cred_data_t* results      = NULL;
    binary_array_t master_key = {0}, new_master_key = {0}, session_key = {0},
                   secure_buffer = {0};
    unsigned char session_iv[IV_SIZE];
    char new_db_path[INPUT_BUFF_SIZE * 2]                               = {0},
                                       old_db_path[INPUT_BUFF_SIZE * 2] = {0};
    int result_count = 0, status_code = 0;

    /*
     *  Does this user in DB and have master password to change it
     */

    status_code = get_user(db, user);
    if (status_code == 1) {
        fprintf(
            stderr,
            "Current user (%s) NOT registered in database, there is NO master "
            "password to change.\n",
            user->username);
        return;
    } else if (status_code != 0) {
        fprintf(stderr, "Unexpected error while executing get_user.\n");
        return;
    }

    if (cfg.debug) {
        printf("DEBUG. user id is: %d\n", user->id);
    }

    /*
     * 1. Verify MASTER password, generate master key and cipher it
     */

    if (verify_master_pswd(*user, &master_key) != 0) {
        binary_array_secure_free(&master_key);
        fprintf(stderr, "Master password was NOT verifyed. Exiting.\n");
        return;
    }

    session_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_random_bytes(session_key.ptr, session_key.size) != 0) {
        handle_errors(MSG_ERR_GENERATE_META);
    }
    session_key.len = session_key.size;

    if (generate_random_bytes(session_iv, IV_SIZE) != 0) {
        binary_array_secure_free(&session_key);
        handle_errors(MSG_ERR_GENERATE_META);
    }

    if (encrypt_data(session_key.ptr, session_iv, master_key, &master_key)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&secure_buffer);
        binary_array_secure_free(&master_key);
        fprintf(stderr, MSG_ERR_ENCRYPT_DATA);
        return;
    }

    /* Part of 4. Get all records from old db */
    if (get_all_cred_data(db, *user, &results, &result_count) != 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    /*
     * 2. Create new DB
     */

    strcat(new_db_path, cfg.db_path);
    strcat(new_db_path, ".new");

    status_code = open(new_db_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (status_code < 0) {
        if (errno == EEXIST) {
            printf(
                "Previous operation of changing master password ended "
                "unexpetedly.\n");
        } else {
            printf("Unexpected error, while checking db_new existed.\n");
        }
    }

    initialize_database(&new_db, new_db_path);

    /*
     * 3. Register user in new db and set NEW master password
     */

    new_user = user_init();
    if (strcmp(user->username, new_user.username) != 0) {
        strncpy(new_user.username, user->username,
                sizeof(new_user.username) - 1);
        new_user.username[sizeof(user->username) - 1] = '\0';
    }

    if (get_or_add_user(new_db, &new_user) != 0) {
        fprintf(stderr, "Unexpected error while executing get_or_add_user.\n");
        return;
    }

    /*
     * Ask NEW master pswd again, generate key, decipher old key
     */

    if (verify_master_pswd(new_user, &new_master_key) != 0) {
        fprintf(stderr, MSG_ERR_MASTER_PSWD);
        return;
    }

    if (decrypt_data(session_key.ptr, session_iv, master_key, &master_key)
        != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&new_master_key);
        binary_array_secure_free(&session_key);
        handle_errors(MSG_ERR_DECRYPT_DATA);
    }
    binary_array_secure_free(&session_key);

    /*
     * Decipher with old pswd, set relevant info for new DB, cipher with new and
     * write to new DB
     */

    for (int i = 0; i < result_count; i++) {
        /*
         * TODO Add check for empty pswd
         */
        if (decrypt_data(master_key.ptr, results[i].iv, results[i].pswd,
                         &results[i].pswd)
            != 0) {
            binary_array_secure_free(&master_key);
            binary_array_secure_free(&new_master_key);
            binary_array_secure_free(&results[i].pswd);
            fprintf(stderr,
                    "Failed to decrypt password for credential data with "
                    "ID: %d.\n",
                    results[i].id);
        }

        results[i].owner = new_user.id;

        if (generate_random_bytes(results[i].iv, IV_SIZE) != 0) {
            handle_errors("Failed to generate IV for password encryption.");
        }

        if (encrypt_data(new_master_key.ptr, results[i].iv, results[i].pswd,
                         &results[i].pswd)
            != 0) {
            binary_array_secure_free(&master_key);
            binary_array_secure_free(&new_master_key);
            binary_array_secure_free(&results[i].pswd);
            fprintf(stderr, MSG_ERR_ENCRYPT_DATA);
            return;
        }

        if (upsert_cred_data(new_db, &results[i]) == 0) {
            printf("Credential added successfully.\n");
        } else {
            fprintf(stderr, "Failed to upsert credential.\n");
        }

        binary_array_secure_free(&results[i].pswd);
    }

    binary_array_secure_free(&master_key);
    binary_array_secure_free(&new_master_key);

    sqlite3_close_v2(db);
    sqlite3_close_v2(new_db);

    strcat(old_db_path, cfg.db_path);
    strcat(old_db_path, ".old");

    if (rename(cfg.db_path, old_db_path) != 0) {
        fprintf(stderr, "rename('%s' -> '%s') failed: %s\n", cfg.db_path,
                old_db_path, strerror(errno));
    }

    if (rename(new_db_path, cfg.db_path) != 0) {
        fprintf(stderr, "rename('%s' -> '%s') failed: %s\n", new_db_path,
                cfg.db_path, strerror(errno));
    }

    printf("New password is set.\nDone.\n");
}
