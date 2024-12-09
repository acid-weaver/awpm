#include "db/database.h"
#include <sqlite3.h>
#include <stdio.h>

int initialize_database(sqlite3 **db) {
    const char *sql_create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "salt BLOB NOT NULL);";

    const char *sql_create_creddata_table =
        "CREATE TABLE IF NOT EXISTS creddata ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "source TEXT NOT NULL, "
        "login TEXT NOT NULL, "
        "pswd BLOB NOT NULL, "
        "iv BLOB NOT NULL, "
        "mail TEXT, "
        "owner INTEGER NOT NULL, "
        "FOREIGN KEY(owner) REFERENCES users(id));";

    int rc = sqlite3_open("users.db", db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
        return rc;
    }

    char *err_msg = NULL;
    rc = sqlite3_exec(*db, sql_create_users_table, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error (users table): %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(*db);
        return rc;
    }

    rc = sqlite3_exec(*db, sql_create_creddata_table, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
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
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    return count > 0 ? 1 : 0;
}

