/**
 * \file            cli.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface functions declared in cli.h.
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

void handle_update(struct sqlite3* db, user_t* user) {
    cred_data_t search_by = {0}, credential_data_to_update = {0};
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

    if (std_input("source", "", search_by.source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error reading source.\n");
        return;
    }

    status_code = get_cred_data_for_update(db, *user, 0, search_by,
                                           &credential_data_to_update);

    if (status_code < 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    if (status_code == 1) {
        if (std_input("login", "", search_by.login, INPUT_BUFF_SIZE) != 0) {
            fprintf(stderr, "Error reading login.\n");
            return;
        }

        status_code = get_cred_data_for_update(db, *user, 1, search_by,
                                               &credential_data_to_update);

        if (status_code < 0) {
            fprintf(stderr, "Failed to retrieve credential data.\n");
            return;
        }
    }

    if (status_code == 1) {
        if (std_input("e-mail", "", search_by.email, INPUT_BUFF_SIZE) != 0) {
            fprintf(stderr, "Error reading e-mail.\n");
            return;
        }

        status_code = get_cred_data_for_update(db, *user, 2, search_by,
                                               &credential_data_to_update);
        if (status_code < 0) {
            fprintf(stderr, "Failed to retrieve credential data.\n");
            return;
        }
    }

    if (status_code == 1) {
        fprintf(stderr,
                "Critical database error. Multiple entries per owner, source, "
                "login and email.\n");
        return;
    }

    if (credential_data_to_update.id == 0) {
        printf("No data with provided source, login and email.\n");
        return;
    }

    /*
     * SHOW ACTUAL CREDENTIAL DATA ENTRY WE WILL UPDATE
     */

    binary_array_free(&credential_data_to_update.pswd);
    credential_data_to_update.pswd = string_to_binary_array("*****");
    printf("=========\n");
    printf("%s", cred_data_to_string(&credential_data_to_update));
    printf("=========\n");

    /*
     * GET NEW VALUES
     */

    if (std_input("new source", "", credential_data_to_update.source,
                  INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error at source input.\n");
        return;
    }

    if (std_input("new login", "", credential_data_to_update.login,
                  INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error at login input.\n");
        return;
    }

    if (std_input("new e-mail", "", credential_data_to_update.email,
                  INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error at e-mail input.\n");
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

    binary_array_free(&credential_data_to_update.pswd);
    credential_data_to_update.pswd = string_to_binary_array("*****");

    printf("=========\n");
    printf("%s", cred_data_to_string(&credential_data_to_update));
    printf("=========\n");
}
