/**
 * \file            database.c
 * \brief           Implementation of database initialization
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the database initialization functions declared in database.h.
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

#include "db/database.h"

#include <sqlite3.h>
#include <stdio.h>

int initialize_database(sqlite3 **db, struct config cfg) {
    const char *sql_create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "salt BLOB NOT NULL, "
        "master_iv BLOB NOT NULL, "
        "master_pswd BLOB NOT NULL"
        ");";

    const char *sql_create_creddata_table =
        "CREATE TABLE IF NOT EXISTS creddata ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "source TEXT NOT NULL, "
        "login TEXT NOT NULL, "
        "email TEXT, "
        "iv BLOB NOT NULL, "
        "pswd BLOB NOT NULL, "
        "owner INTEGER NOT NULL, "
        "FOREIGN KEY(owner) REFERENCES users(id), "
        "UNIQUE(source, login, email)"
        ");";

    int rc = sqlite3_open(cfg.db_path, db);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
        return rc;
    }

    char *err_msg = NULL;
    rc            = sqlite3_exec(*db, sql_create_users_table, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (users table): %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(*db);
        return rc;
    }

    rc = sqlite3_exec(*db, sql_create_creddata_table, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (creddata table): %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(*db);
        return rc;
    }

    return SQLITE_OK;
}

int user_exists(sqlite3 *db, const char *username) {
    const char *sql_query = "SELECT COUNT(*) FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;
    int rc, count = 0;

    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if(sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    return count;
}
