/**
 * \file            cli.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface functions declared in cli.h.
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

#include "cli.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db/creddata.h"
#include "db/users.h"
#include "encryption.h"
#include "memory.h"
#include "secure_memory.h"
#include "utils.h"

void handle_add_new_entry(struct sqlite3* db, user_t* user) {
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

    if (user_verify_master_pswd(*user, master_key.ptr) != 0) {
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

void handle_retrieve_creddata(struct sqlite3* db, user_t* user) {
    cred_data_t* results = NULL;

    binary_array_t secure_buffer = {0}, master_key = {0};
    char source[INPUT_BUFF_SIZE];
    int result_count = 0, status_code = 0;

    status_code = get_user(db, user);
    if (status_code == 1) {
        fprintf(stderr,
                "Current user NOT registered in database, there is NO stored "
                "passwords for %s.\n",
                user->username);
        return;
    } else if (status_code != 0) {
        fprintf(stderr, "Unexpected error while executing get_user.\n");
        return;
    }

    if (cfg.debug) {
        printf("DEBUG. user id is: %d\n", user->id);
    }

    // Prompt for source name
    if (std_input("source", "", source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error reading source.\n");
        return;
    }

    if (get_cred_data_by_source(db, *user, source, &results, &result_count)
        != 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    if (result_count == 0) {
        printf("No entries for provided source.\n");
        return;
    }

    /*
     * VERIFY MASTER PASSWORD, GENERATE MASTER KEY SECTION
     */

    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", "", (char*)secure_buffer.ptr,
                     INPUT_BUFF_SIZE)
        != 0) {
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Error reading decryption password.\n");
        return;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    if (secure_buffer.len < 1) {
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Entered password length less that minimum.\n");
        return;
    }

    master_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_key_from_password(user->salt, (char*)secure_buffer.ptr,
                                   master_key.ptr)
        != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }
    binary_array_secure_free(&secure_buffer);
    master_key.len = KEY_SIZE;

    if (user_verify_master_pswd(*user, master_key.ptr) != 0) {
        binary_array_secure_free(&master_key);
        fprintf(stderr, "Failed to verify master password.\n");
        return;
    }

    /*
     * DECIPHER AND DISPLAY RESULTS SECTION
     */

    for (int i = 0; i < result_count; i++) {
        if (decrypt_data(master_key.ptr, results[i].iv, results[i].pswd,
                         &results[i].pswd)
            != 0) {
            fprintf(stderr,
                    "Failed to decrypt password for credential data with "
                    "ID: %d.\n",
                    results[i].id);
        }
        printf("=========\n");
        printf("%s", cred_data_to_string(&results[i]));
    }

    binary_array_secure_free(&master_key);
}

void handle_update_creddata(struct sqlite3* db, user_t* user) {
    cred_data_t credential_data_to_update = {0};
    binary_array_t secure_buffer = {0}, master_key = {0}, session_key = {0};
    unsigned char session_iv[IV_SIZE];
    int status_code = 0;

    status_code = get_user(db, user);
    if (status_code == 1) {
        fprintf(stderr,
                "Current user NOT registered in database, there is NO stored "
                "passwords for %s.\n",
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
     * GET DATA TO EDIT
     */

    if (std_input("source", "", credential_data_to_update.source,
                  INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error reading source.\n");
        return;
    }

    if (std_input("login", "", credential_data_to_update.login, INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error reading login.\n");
        return;
    }

    if (std_input("e-mail", "", credential_data_to_update.email,
                  INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error reading e-mail.\n");
        return;
    }

    if (get_cred_data(db, *user, credential_data_to_update,
                      &credential_data_to_update)
        != 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    if (credential_data_to_update.id == 0) {
        printf("No data with provided source, login and email.\n");
        return;
    }

    /*
     * GET NEW VALUES
     */

    if (std_input("Source", "", credential_data_to_update.source,
                  INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error at Source input.\n");
        return;
    }

    if (std_input("Login", "", credential_data_to_update.login, INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error at Source input.\n");
        return;
    }

    if (std_input("E-mail", "", credential_data_to_update.email,
                  INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error at Source input.\n");
        return;
    }

    /*
     * CREDENTIAL SECTION
     * Generating session credentials to cipher data, that not currently in
     * usage. Erase all credential data after operations done
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
                     &credential_data_to_update.pswd)
        != 0) {
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&secure_buffer);
        binary_array_secure_free(&credential_data_to_update.pswd);
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
        binary_array_secure_free(&credential_data_to_update.pswd);
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
        binary_array_secure_free(&credential_data_to_update.pswd);
        binary_array_secure_free(&master_key);
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }
    binary_array_secure_free(&secure_buffer);
    master_key.len = KEY_SIZE;

    if (user_verify_master_pswd(*user, master_key.ptr) != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&credential_data_to_update.pswd);
        fprintf(stderr, "Invalid master password, repeat.\n");
        return;
    }

    /*
     * Decipher password to storee and cipher it with master key
     */

    if (decrypt_data(session_key.ptr, session_iv,
                     credential_data_to_update.pswd,
                     &credential_data_to_update.pswd)
        != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&session_key);
        binary_array_secure_free(&credential_data_to_update.pswd);
        handle_errors("Failed to decipher temporarily encrypted memory data.");
    }
    binary_array_secure_free(&session_key);

    if (encrypt_data(master_key.ptr, credential_data_to_update.iv,
                     credential_data_to_update.pswd,
                     &credential_data_to_update.pswd)
        != 0) {
        binary_array_secure_free(&master_key);
        binary_array_secure_free(&credential_data_to_update.pswd);
        fprintf(stderr, "Failed to encrypt credential data.\n");
        return;
    }
    binary_array_secure_free(&master_key);

    if (upsert_cred_data(db, &credential_data_to_update) == 0) {
        printf("Credential updated successfully.\n");
    } else {
        fprintf(stderr, "Failed to upsert credential.\n");
    }

    binary_array_secure_free(&credential_data_to_update.pswd);
    credential_data_to_update.pswd = binary_array_alloc(sizeof("*****"));
    memcpy(credential_data_to_update.pswd.ptr, "*****", sizeof("*****"));
    credential_data_to_update.pswd.len = sizeof("*****") - 1;

    printf("=========\n");
    printf("%s", cred_data_to_string(&credential_data_to_update));
}

void handle_update_master_pswd(struct sqlite3* db, user_t* user) {
    int status_code = 0;

    status_code = get_user(db, user);
    if (status_code != 0) {
        fprintf(stderr, "Failed to authenticate user.\n");
        return;
    }
}
