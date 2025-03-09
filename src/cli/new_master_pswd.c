/**
 * \file            new_master_pswd.c
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
#include "db.h"
#include "encryption.h"
#include "mem.h"
#include "utils.h"

void handle_new_master_pswd(struct sqlite3* db, user_t* user) {
    int status_code = 0;

    status_code = get_user(db, user);
    if (status_code != 0) {
        fprintf(stderr, "Failed to authenticate user.\n");
        return;
    }
}
