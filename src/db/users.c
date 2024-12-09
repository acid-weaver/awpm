#include "db/users.h"
#include "utils.h"
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <openssl/rand.h>

const char *get_current_username() {
    struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_name : NULL;
}

int populate_user_from_row(sqlite3_stmt *stmt, user_t *user) {
    if (!user) {
        return -1;
    }

    user->id = sqlite3_column_int(stmt, 0);
    strncpy(user->username, (const char *)sqlite3_column_text(stmt, 1), sizeof(user->username));
    memcpy(user->salt, sqlite3_column_blob(stmt, 2), 16);

    return 0;
}

int add_user(sqlite3 *db, const char *username) {
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Failed to generate salt.\n");
        return -1;
    }

    const char *sql_insert =
        "INSERT INTO users (username, salt) VALUES (?, ?);";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, salt, sizeof(salt), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert user: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int get_user_id_by_username(sqlite3 *db, const char *username, int *user_id) {
    const char *sql_query = "SELECT id FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;
    int rc;

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Bind the username parameter
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    // Execute the query and fetch the result
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *user_id = sqlite3_column_int(stmt, 0); // Retrieve owner_id
        sqlite3_finalize(stmt);
        return 0; // Success
    } else if (rc == SQLITE_DONE) {
        fprintf(stderr, "No user found with username: %s\n", username);
        sqlite3_finalize(stmt);
        return -1; // No user found
    } else {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1; // Query failed
    }
}

int get_salt_by_username(sqlite3 *db, const char *username, unsigned char *salt) {
    const char *sql_query = "SELECT salt FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;
    int rc;

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Bind the username parameter
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    // Execute the query and fetch the result
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Copy the salt into the provided buffer
        const unsigned char *retrieved_salt = (const unsigned char *)sqlite3_column_blob(stmt, 0);
        int salt_len = sqlite3_column_bytes(stmt, 0);

        if (salt_len != SALT_SIZE) {
            fprintf(stderr, "Unexpected salt size: %d\n", salt_len);
            sqlite3_finalize(stmt);
            return -1;
        }

        memcpy(salt, retrieved_salt, SALT_SIZE);
        sqlite3_finalize(stmt);
        return 0; // Success
    } else if (rc == SQLITE_DONE) {
        fprintf(stderr, "No user found with username: %s\n", username);
        sqlite3_finalize(stmt);
        return -1; // No user found
    } else {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1; // Query failed
    }
}

// Function to print users for debugging
void print_users(sqlite3 *db) {
    const char *sql_select = "SELECT username, hex(salt) FROM users;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare select statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    printf("Users in the database:\n");
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *username = (const char *)sqlite3_column_text(stmt, 0);
        const char *salt_hex = (const char *)sqlite3_column_text(stmt, 1);
        printf("Username: %s, Salt: %s\n", username, salt_hex);
    }
    sqlite3_finalize(stmt);
}
