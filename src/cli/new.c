/**
 * \file            cli/new.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface function handle_new declared in cli.h.
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

#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "db.h"
#include "encryption.h"
#include "mem.h"
#include "utils.h"

void handle_new(struct sqlite3* db, user_t* user) {
    cred_data_t credential_data =
                    {
                        .id     = -1,
                        .owner  = -1,
                        .source = "",
                        .login  = "",
                        .email  = "",
                        .iv     = "",
                        .pswd   = {0},
                    },
                *results      = NULL;
    binary_array_t master_key = {0}, session_key = {0}, secure_buffer = {0};
    unsigned char session_iv[IV_SIZE];
    int result_count = 0;

    // Add user if not already present
    if (get_or_add_user(db, user) != 0) {
        fprintf(stderr, "Unexpected error while executing get_or_add_user.\n");
        return;
    }

    /*
     * POPULATE credential_data SECTION
     */

    credential_data.owner = user->id;

    if (generate_random_bytes(credential_data.iv, IV_SIZE) != 0) {
        handle_errors("Failed to generate IV for password encryption.");
    }

    if (std_input("Source", "", credential_data.source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error at Source input.\n");
        return;
    }

    /*
     * In single-entry-per-source mode, we should update the existing entry.
     * In multiple-entry-per-source mode or if there are no entries for this
     * source, we add a new entry.
     *
     * Note that technically, we will update credential data if its ID > 0 and
     * corresponds to an existing entry. If the ID <= 0, we will create a new
     * entry. If the ID > 0 but there are no existing entries with this ID, it
     * will be added with the provided ID (which should be treated as an error
     * in our case).
     */

    if (cfg.multiple_accs_per_source == 0
        && get_cred_data_by_source(db, *user, credential_data.source, &results,
                                   &result_count)
               != 0) {
        fprintf(stderr,
                "Failed to check databse for entries with provided source.\n");
        return;

    } else if (result_count == 1) { // cfg.multiple_accs_per_source = 0 here
        printf(
            "Founded entry for this source. This row would be updated due to "
            "'one per source' mode is enabled.\n");
        credential_data = results[0];

    } else if (result_count > 1) { // cfg.multiple_accs_per_source = 0 here
        printf(
            "This source is in multiple account mode. New entry will be "
            "added.\n");
    }

    if (credential_data.id == -1
        && std_input("Login", OPTIONAL_PROMPT, credential_data.login,
                     INPUT_BUFF_SIZE)
               != 0) {
        fprintf(stderr, "Error at Login input.\n");
        return;
    }

    if (credential_data.id == -1
        && std_input("associated e-mail", OPTIONAL_PROMPT,
                     credential_data.email, sizeof(credential_data.email))
               != 0) {
        fprintf(stderr, "Error reading e-mail.\n");
        return;
    }

    /*
     * KEY OR PASSWORD DATA MUST BE CIPHERED WHILE NOT IN USE
     * INITIALIZING SESSION_KEY AND SESSION_IV FOR ENCRYPTION
     */

    session_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_random_bytes(session_key.ptr, session_key.size) != 0) {
        handle_errors("Failed to generate session encryption metadata.");
    }
    session_key.len = session_key.size;

    if (generate_random_bytes(session_iv, IV_SIZE) != 0) {
        binary_array_secure_free(&session_key);
        handle_errors("Failed to generate session encryption metadata.");
    }

    /* Prompt for password to store */
    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("password to store", "", (char*)secure_buffer.ptr,
                     secure_buffer.size)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Error reading password.\n");
        return;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    /*
     * We don't need entered password until encryption will start
     */

    if (encrypt_data(session_key.ptr, session_iv, secure_buffer,
                     &credential_data.pswd)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&secure_buffer);
        binary_array_secure_free(&credential_data.pswd);
        fprintf(stderr, "Failed to temporarily cipher important data.\n");
        return;
    }
    binary_array_secure_free(&secure_buffer);

    /* Prompt for encryption (master) password */
    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", "", (char*)secure_buffer.ptr,
                     secure_buffer.size)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&secure_buffer);
        binary_array_secure_free(&credential_data.pswd);
        handle_errors("Failed to read encryption password.");
        return;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    master_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_key_from_password(user->salt, (char*)secure_buffer.ptr,
                                   master_key.ptr)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&secure_buffer);
        binary_array_secure_free(&credential_data.pswd);
        binary_array_secure_free(&master_key);
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }
    binary_array_secure_free(&secure_buffer);
    master_key.len = KEY_SIZE;

    if (user_verify_master_key(*user, master_key.ptr) != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&credential_data.pswd);
        fprintf(stderr, "Invalid master password, repeat.\n");
        return;
    }

    /*
     * Decipher password to storee and cipher it with master key
     */

    if (decrypt_data(session_key.ptr, session_iv, credential_data.pswd,
                     &credential_data.pswd)
        != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&credential_data.pswd);
        handle_errors("Failed to decipher temporarily encrypted memory data.");
    }
    binary_array_secure_free(&session_key);

    if (encrypt_data(master_key.ptr, credential_data.iv, credential_data.pswd,
                     &credential_data.pswd)
        != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&credential_data.pswd);
        fprintf(stderr, "Failed to encrypt credential data.\n");
        return;
    }
    binary_array_secure_free(&master_key);

    if (upsert_cred_data(db, &credential_data) == 0) {
        printf("Credential added successfully.\n");
    } else {
        fprintf(stderr, "Failed to upsert credential.\n");
    }

    binary_array_secure_free(&credential_data.pswd);
}
