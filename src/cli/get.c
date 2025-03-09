/**
 * \file            get.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface function handle_get declared in cli.h.
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

void handle_get(struct sqlite3* db, user_t* user) {
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
    printf("=========\n");

    binary_array_secure_free(&master_key);
}
