/**
 * \file            cli.h
 * \brief           Command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Declares functions for handling command-line interactions, including
 * parsing arguments and managing user input.
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

#ifndef CLI_H
#define CLI_H

// CLI parameters
#define CLI_NEW "-n"
#define CLI_FORCE_NEW "-nf"
#define CLI_GET "-g"
#define CLI_UPDATE "-u"
#define CLI_SET_MASTER_PSWD "-m"

#define CLI_USER "--user"
#define CLI_DEBUG_MODE "--debug"

#include "db/users.h"
struct sqlite3;

void handle_add_new_entry(struct sqlite3* db, user_t* user);
void handle_retrieve_creddata(struct sqlite3* db, user_t* user);
void handle_update_creddata(struct sqlite3* db, user_t* user);
void handle_delete_creddata(struct sqlite3* db, user_t* user);

void handle_update_master_pswd(struct sqlite3* db, user_t* user);

#endif // CLI_H
