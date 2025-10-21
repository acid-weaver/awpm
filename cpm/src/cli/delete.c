/**
 * \file            cli/delete.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface function handle_delete declared in
 * cli.h.
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

void handle_delete(struct sqlite3* db, user_t* user) {
    cred_data_t search_by = {0}, credential_data_to_delete = {0};
    binary_array_t secure_buffer = {0}, master_key = {0};
    char confirmation[INPUT_BUFF_SIZE];
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
     * Verify master password to ensure user have apopriate access rights
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

    if (user_verify_master_key(*user, master_key.ptr) != 0) {
        binary_array_secure_free(&master_key);
        fprintf(stderr, "Failed to verify master password.\n");
        return;
    }
    binary_array_secure_free(&master_key);

    /*
     * Get data to delete
     */

    if (std_input("source", "", search_by.source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error reading source.\n");
        return;
    }

    status_code = get_cred_data_by_step(db, *user, 0, search_by,
                                        &credential_data_to_delete);

    if (status_code < 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    if (status_code == 1) {
        if (std_input("login", "", search_by.login, INPUT_BUFF_SIZE) != 0) {
            fprintf(stderr, "Error reading login.\n");
            return;
        }

        status_code = get_cred_data_by_step(db, *user, 1, search_by,
                                            &credential_data_to_delete);

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

        status_code = get_cred_data_by_step(db, *user, 2, search_by,
                                            &credential_data_to_delete);
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

    if (credential_data_to_delete.id == 0) {
        printf("No data with provided source, login and email.\n");
        return;
    }

    /*
     * SHOW ACTUAL CREDENTIAL DATA ENTRY WE WILL DELETE
     */

    printf("THIS ENTRY WOULD BE DELETED:\n");
    binary_array_free(&credential_data_to_delete.pswd);
    credential_data_to_delete.pswd = string_to_binary_array("*****");
    printf("=========\n");
    printf("%s", cred_data_to_string(&credential_data_to_delete));
    printf("=========\n");

    printf("Are you sure?\n");
    if (std_input("y/N", "", confirmation, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error reading confirmation.\n");
        return;
    }

    if (strcmp(confirmation, "y") == 0 || strcmp(confirmation, "Y") == 0) {
        delete_cred_data(db, *user, credential_data_to_delete);
        printf("Credentials successfully deleted.\n");
    } else {
        printf("Credentials WON'T be deleted.\n");
    }
}
