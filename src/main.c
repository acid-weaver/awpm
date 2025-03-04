/**
 * \file            main.c
 * \brief           Main entry point for the application
 * \author          Your GitHub Name
 * \date            2024-12-21
 * \details
 * Initializes the application, parses command-line arguments, and invokes
 * the appropriate modules based on user input.
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

#include <openssl/crypto.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "cli/cli.h"
#include "db/database.h"
#include "db/users.h"
#include "utils.h"

struct config cfg = {
    .debug                    = 0,
    .multiple_accs_per_source = 0,
    .db_path                  = "/var/local/awpm/awpm.db",
};

int main(int argc, char* argv[]) {
    user_t user = {0};
    sqlite3* db = NULL;

    signal(SIGINT, handle_interrupt);  /* Handle Ctrl-C */
    signal(SIGTERM, handle_interrupt); /* Handle kill signals */
    disable_debugging(); /* To disable ability of reading memory with debug
                          * tools
                          */
    if (argc < 2) {
        fprintf(stderr, "Usage: pm %s | %s | %s | %s [%s]\n", CLI_NEW,
                CLI_FORCE_NEW, CLI_GET, CLI_SET_MASTER_PSWD, CLI_DEBUG_MODE);
        return 1;
    }

    user = user_init();
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], CLI_DEBUG_MODE) == 0) {
            cfg.debug = 1;
            printf("Debug mode enabled.\n");
        }

        if (strcmp(argv[i], CLI_USER) == 0) {
            if (i + 1 <= argc) {
                strncpy(user.username, argv[i + 1], sizeof(user.username) - 1);
                user.username[sizeof(user.username) - 1] = '\0';
                i++;
            } else {
                fprintf(stderr,
                        "Wrong %s parameter usage: it requires assign value!\n",
                        CLI_USER);
                return 1;
            }
        }
    }

    if (strlen(user.username) == 0) {
        handle_errors("Unauthorized access impossible.\n");
        return 1;
    }

    printf("Greetings, %s!\n", user.username);

    initialize_database(&db, cfg);

    if (strcmp(argv[1], CLI_NEW) == 0) {
        handle_add_new_entry(db, &user);
    } else if (strcmp(argv[1], CLI_FORCE_NEW) == 0) {
        cfg.multiple_accs_per_source = 1;
        handle_add_new_entry(db, &user);
    } else if (strcmp(argv[1], CLI_GET) == 0) {
        handle_retrieve_creddata(db, &user);
    } else if (strcmp(argv[1], CLI_UPDATE) == 0) {
        handle_update_creddata(db, &user);
    } else if (strcmp(argv[1], CLI_DELETE) == 0) {
        handle_delete_creddata(db, &user);
        /*
         *} else if (strcmp(argv[1], CLI_SET_MASTER_PSWD) == 0) {
         *  handle_set_master_pswd(db, &user);
         */
    } else {
        fprintf(stderr, "Unknown parameter: %s\n", argv[1]);
    }

    sqlite3_close(db);
    return 0;
}
