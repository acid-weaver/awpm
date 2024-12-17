#include "db/users.h"
#include "memory.h"
#include "utils.h"
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <openssl/rand.h>

const char*
get_current_username() {
    struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_name : NULL;
}

int
populate_user_from_row(sqlite3_stmt* stmt, user_t* user) {
    const char* username = NULL;
    const void* buffer = NULL;
    int buffer_size = 0;

    if (user == NULL) {
        fprintf(stderr, "Invalid user_t pointer provided.\n");
        return -1;
    }

    // Reset the user struct
    memset(user, 0, sizeof(user_t));

    // Populate `id`
    user->id = sqlite3_column_int(stmt, 0);

    // Populate `username`
    username = (const char *)sqlite3_column_text(stmt, 1);
    if (username) {
        strncpy(user->username, username, sizeof(user->username) - 1);
    }

    // Populate `salt`
    buffer = sqlite3_column_blob(stmt, 2);
    buffer_size = sqlite3_column_bytes(stmt, 2);
    if (buffer != NULL && buffer_size == SALT_SIZE) {
        memcpy(user->salt, buffer, SALT_SIZE);
    } else {
        fprintf(stderr, "Invalid or missing salt for user: %s\n", user->username);
        return -1;
    }

    // Populate `master_iv`
    buffer = sqlite3_column_blob(stmt, 3);
    buffer_size = sqlite3_column_bytes(stmt, 3);
    if (buffer != NULL && buffer_size == IV_SIZE) {
        memcpy(user->master_iv, buffer, IV_SIZE);
    } else if (buffer == NULL) {
        // Allow `master_iv` to be NULL, indicating no master password set
        memset(user->master_iv, 0, IV_SIZE);
    } else {
        fprintf(stderr, "Invalid IV size for user: %s\n", user->username);
        return -1;
    }

    // Populate `master_pswd`
    buffer = sqlite3_column_blob(stmt, 4);
    buffer_size = sqlite3_column_bytes(stmt, 4);
    if (buffer != NULL && buffer_size > 0) {
        user->master_pswd = binary_array_alloc(buffer_size);
        memcpy(user->master_pswd.ptr, buffer, buffer_size);
        user->master_pswd.len = buffer_size;
    } else if (buffer == NULL) {
        // Allow `master_pswd` to be NULL, indicating no master password set
        user->master_pswd = binary_array_alloc(0);
    } else {
        fprintf(stderr, "Invalid master password size for user: %s\n", user->username);
        return -1;
    }

    return 0; // Success
}

int
add_user(sqlite3 *db, const char *username) {
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Failed to generate salt.\n");
        return -1;
    }

    const char *sql_insert =
        "INSERT INTO users (username, salt, master_iv, master_pswd) VALUES (?, ?, NULL, NULL);";
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

int
get_user(sqlite3* db, user_t* user) {
    sqlite3_stmt* stmt = NULL;
    const char* sql_query = "SELECT id, username, salt, master_iv, master_pswd FROM users WHERE username = ?;";
    int rc = 0;

    if (user == NULL || strlen(user->username) == 0) {
        fprintf(stderr, "Invalid user_t user provided to get_user: username must be provided.\n");
        return -1;
    }

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Bind the username parameter
    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // user exists, populate it
        if (populate_user_from_row(stmt, user) != 0) {
            fprintf(stderr, "Failed to populate user_t from row.\n");
            sqlite3_finalize(stmt);
            return -1;
        }

        sqlite3_finalize(stmt);
        return 0;

    } else if (rc == SQLITE_DONE) {
        // user does not exist
        fprintf(stderr, "No user found with username: %s.\n", user->username);
        sqlite3_finalize(stmt);
        return 1;

    } else {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1; // Query failed
    }
    return 0;
}

int
get_or_add_user(sqlite3* db, user_t* user) {
    sqlite3_stmt* stmt = NULL;
    const char* sql_query = "SELECT id, username, hex(salt), hex(master_iv), hex(master_pswd) FROM users WHERE username = ?;";
    int rc = 0;

    if (user == NULL || strlen(user->username) == 0) {
        fprintf(stderr, "Invalid user_t user provided to get_or_add_user: username must be provided.\n");
        return -1;
    }

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Bind the username parameter
    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);

    // Execute the query and fetch the result
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // user exists, populate it
        if (populate_user_from_row(stmt, user)) {
            fprintf(stderr, "Failed to populate user_t from row.\n");
            sqlite3_finalize(stmt);
            return -1;
        }

        sqlite3_finalize(stmt);
        return 0;

    } else if (rc == SQLITE_DONE) {
        // user does not exist, add
        fprintf(stderr, "No user found with username: %s. Adding to database.\n", user->username);
        sqlite3_finalize(stmt);

        if (add_user(db, user->username) != 0) {
            fprintf(stderr, "Failed to add new user with username: %s.\n", user->username);
            return -1;
        }

        return get_or_add_user(db, user);

    } else {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1; // Query failed
    }

    return 0;
}

int
get_user_id_by_username(sqlite3* db, const char* username, int* user_id) {
    sqlite3_stmt* stmt;
    const char* sql_query = "SELECT id FROM users WHERE username = ?;";
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

int
get_salt_by_user_id(sqlite3 *db, const int user_id, unsigned char *salt) {
    const char *sql_query = "SELECT salt FROM users WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc;

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Bind the username parameter
    sqlite3_bind_int(stmt, 1, user_id);


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
        fprintf(stderr, "No user found with user_id: %d\n", user_id);
        sqlite3_finalize(stmt);
        return -1; // No user found
    } else {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1; // Query failed
    }
}

int
write_master_pswd(sqlite3* db, const int user_id,
                  const binary_array_t master_pswd, const unsigned char* master_iv) {
    sqlite3_stmt* stmt;
    const char* sql_update = "UPDATE users SET master_iv = ?, master_pswd = ? WHERE id = ?;";

    int rc = sqlite3_prepare_v2(db, sql_update, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, master_iv, IV_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, master_pswd.ptr, master_pswd.len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update master_pswd: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int
get_master_password(sqlite3* db, const int user_id, binary_array_t* master_pswd) {
    sqlite3_stmt* stmt;
    const char* sql_query = "SELECT master_pswd FROM users WHERE id = ?;";
    int rc, status_code = 0;

    if (master_pswd == NULL) {
        fprintf(stderr, "Storage for master password is NOT provided.\n");
        return -1;
    }
    binary_array_free(master_pswd);

    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_int(stmt, 1, user_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const void* blob_data = sqlite3_column_blob(stmt, 0);
        int blob_size = sqlite3_column_bytes(stmt, 0);

        if (blob_data && blob_size > 0) {
            *master_pswd = binary_array_alloc(blob_size);
            memcpy(master_pswd->ptr, blob_data, blob_size);
            master_pswd->len = blob_size;
        } else {
            // Handle case where `master_pswd` is NULL
            fprintf(stderr, "Master password is not set for user_id: %d\n", user_id);
            status_code = 1; // Indicate `master_pswd` is NULL
        }
    } else if (rc == SQLITE_DONE) {
        fprintf(stderr, "No user found with user_id: %d\n", user_id);
        status_code = -1; // No user found
    } else {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        status_code = -1; // Query failed
    }

    sqlite3_finalize(stmt);
    return status_code;
}

// Function to print all users for debugging
void
print_users(sqlite3 *db) {
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

