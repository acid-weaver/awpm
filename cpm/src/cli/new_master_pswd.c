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

#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "cli/utils.h"
#include "db.h"
#include "encryption.h"
#include "mem.h"
#include "utils.h"

void handle_new_master_pswd(struct sqlite3* db, user_t* user) {
    /*
     *  1. Ask current master password, verify it
     *  2. Create new db
     *  3. Ask new master pswd, generate key, save it to new db
     *  4. Decipher entry from old db, ciqher it with new key and write to new db
     *  5. Backup old db, replace it with new db
     */

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
    int status_code = 0;

    /*
     *  Does this user in DB and have master password to change it
     */

    status_code = get_user(db, user);
    if (status_code == 1) {
        fprintf(stderr,
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
     * VERIFY MASTER PASSWORD, GENERATE MASTER KEY SECTION
     */

    if (verify_master_pswd(*user, &master_key) != 0) {
        binary_array_secure_free(&master_key);
        fprintf(stderr, "Master password was NOT verifyed. Exiting.\n");
        return;
    }
}
