/**
 * \file            cli/get.c
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
#include "cli/cli_utils.h"
#include "db.h"
#include "mem.h"
#include "utils.h"

void handle_get(struct sqlite3* db, user_t* user) {
    cred_data_t* results = NULL;

    binary_array_t master_key = {0};
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

    if (strlen(source) > 0
        && get_cred_data_by_source(db, *user, source, &results, &result_count)
               != 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    if (strlen(source) == 0
        && get_all_cred_data(db, *user, &results, &result_count) != 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    if (result_count == 0 && strlen(source) != 0) {
        printf("No entries for provided source.\n");
        return;
    }

    /*
     * VERIFY MASTER PASSWORD, GENERATE MASTER KEY SECTION
     */

    if (verify_master_pswd(*user, &master_key) != 0) {
        binary_array_secure_free(&master_key);
        fprintf(stderr, "Master password was NOT verifyed. Exiting.");
        return;
    }

    /*
     * DECIPHER AND DISPLAY RESULTS SECTION
     */

    if (strlen(source) == 0) {
        binary_array_secure_free(&master_key);
        display_cred_data(results, result_count);
    } else {
        display_decrypted_cred_data(results, result_count, &master_key);
    }

    binary_array_secure_free(&master_key);
}
