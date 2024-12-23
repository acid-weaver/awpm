/**
 * \file            creddata.c
 * \brief           Implementation of credential management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the credential management functions declared in creddata.h.
 */

/* Copyright (C) 2024  Acid Weaver acid.weaver@gmail.com
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

#include "db/creddata.h"
#include "db/users.h"
#include "utils.h"
#include "memory.h"
#include "encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int
populate_cred_data_from_row(sqlite3_stmt* stmt, cred_data_t* credential_data) {
    const void* buffer;
    int buffer_len;

    if (stmt == NULL || credential_data == NULL) {
        fprintf(stderr, "Invalid arguments to populate_cred_data_from_row.\n");
        return -1;
    }

    credential_data->id = sqlite3_column_int(stmt, 0);
    credential_data->owner = sqlite3_column_int(stmt, 1);

    buffer = sqlite3_column_text(stmt, 2);
    strncpy(credential_data->source, (const char*)buffer, sizeof(credential_data->source) - 1);
    credential_data->source[sizeof(credential_data->source) - 1] = '\0';

    buffer = sqlite3_column_text(stmt, 3);
    strncpy(credential_data->login, buffer ? (const char *)buffer : "", sizeof(credential_data->login) - 1);
    credential_data->login[sizeof(credential_data->login) - 1] = '\0';

    buffer = sqlite3_column_text(stmt, 4);
    strncpy(credential_data->email, buffer ? (const char *)buffer : "", sizeof(credential_data->email) - 1);
    credential_data->email[sizeof(credential_data->email) - 1] = '\0';

    buffer = sqlite3_column_blob(stmt, 5);
    buffer_len = sqlite3_column_bytes(stmt, 5);
    if (buffer == NULL || buffer_len != IV_SIZE) {
        fprintf(stderr, "Invalid IV for credential data with ID: %d and Source: %s\n", credential_data->id, credential_data->source);
        return -1;
    }
    memcpy(credential_data->iv, buffer, IV_SIZE);

    buffer = sqlite3_column_blob(stmt, 6);
    buffer_len = sqlite3_column_bytes(stmt, 6);

    if (buffer == NULL || buffer_len < 1) {
        fprintf(stderr, "Invalid pswd for credential with ID: %d and Source: %s\n", credential_data->id, credential_data->source);
        return -1;
    }

    credential_data->pswd = binary_array_alloc(buffer_len);
    memcpy(credential_data->pswd.ptr, buffer, buffer_len);
    credential_data->pswd.len = buffer_len;

    return 0;
}

char*
cred_data_to_string(const cred_data_t* cred_data) {
    static const char empty_string[] = ""; // Reusable empty string
    char* result = NULL;
    size_t result_size = 0;

    if (cred_data == NULL) {
        fprintf(stderr, "Invalid input to cred_data_to_string.\n");
        return (char*)empty_string;
    }

    result_size = snprintf(NULL, 0, "ID: %d\nSource: %s\nLogin: %s\nEmail: %s\nPassword: %s\n",
                           cred_data->id, cred_data->source, cred_data->login,
                           cred_data->email, binary_array_to_string(&cred_data->pswd))
                  + 1;
    result = malloc(result_size);

    if (result == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return (char *)empty_string;
    }

    snprintf(result, result_size, "ID: %d\nSource: %s\nLogin: %s\nEmail: %s\nPassword: %s\n",
             cred_data->id, cred_data->source, cred_data->login, cred_data->email,
             binary_array_to_string(&cred_data->pswd));

    return result;
}

int
upsert_cred_data(sqlite3* db, const cred_data_t* credential_data) {
    const char *sql_upsert =
        "INSERT INTO creddata (id, source, login, email, iv, pswd, owner) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "source = excluded.source, "
        "login = excluded.login, "
        "email = excluded.email, "
        "iv = excluded.iv, "
        "pswd = excluded.pswd, "
        "owner = excluded.owner;";
    sqlite3_stmt *stmt;
    int rc = 0;

    if (db == NULL || credential_data == NULL || credential_data->owner < 1) {
        fprintf(stderr, "Invalid data provided to upsert_cred_data function.\n");
        return -1;
    }

    rc = sqlite3_prepare_v2(db, sql_upsert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    sqlite3_bind_int(stmt, 1, credential_data->id); // Can be 0 or a valid id
    sqlite3_bind_text(stmt, 2, credential_data->source, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, credential_data->login, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, credential_data->email, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, credential_data->iv, IV_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, credential_data->pswd.ptr,
                      credential_data->pswd.len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, credential_data->owner);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert credential: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int
get_credentials_by_source(sqlite3* db, const user_t user, const char* source,
                          cred_data_t** results, int* result_count) {
    cred_data_t* temp_results = NULL;
    sqlite3_stmt* stmt;
    const char* sql_query = "SELECT id, owner, source, login, email, iv, pswd FROM creddata WHERE source = ? AND owner = ?;";
    int rc, temp_count = 0;

    if (db == NULL || user.id < 1 || source == NULL || result_count == NULL) {
        fprintf(stderr, "Invalid input into get_credentials_by_source function.\n");
        return -1;
    }

    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, source, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, user.id);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cred_data_t current_row_result = {0};

        if (populate_cred_data_from_row(stmt, &current_row_result) != 0) {
            fprintf(stderr, "Failed to parse data from DB into cred_data_t object.\n");
            return -1;
        }

        // Add the result to the list
        temp_results = realloc(temp_results, (temp_count + 1) * sizeof(cred_data_t));
        if (temp_results == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            free(temp_results);
            sqlite3_finalize(stmt);
            return -1;
        }

        temp_results[temp_count] = current_row_result;
        temp_count++;
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);

    // Return results
    *results = temp_results;
    *result_count = temp_count;
    return 0;
}

int
retrieve_and_decipher_by_source(sqlite3* db, const char* source,
                                const unsigned char* key, char*** results,
                                int* result_count) {
    const char* sql_query = "SELECT source, login, pswd, iv, email FROM creddata WHERE source = ?;";
    sqlite3_stmt* stmt;
    int rc;

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Bind the source parameter
    sqlite3_bind_text(stmt, 1, source, -1, SQLITE_STATIC);

    // Temporary storage for results
    char **temp_results = NULL;
    int temp_count = 0;

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        binary_array_t decrypted_pswd = {
            .size = 0,
            .len  = 0,
            .ptr  = NULL,
        };
        const char *source = (const char *)sqlite3_column_text(stmt, 0);
        const char *login = (const char *)sqlite3_column_text(stmt, 1);
        const binary_array_t encrypted_pswd = {
            .size = sqlite3_column_bytes(stmt, 2),
            .len  = sqlite3_column_bytes(stmt, 2),
            .ptr  = (unsigned char*)sqlite3_column_blob(stmt, 2),
        };
        const unsigned char *iv = sqlite3_column_blob(stmt, 3);
        int iv_len = sqlite3_column_bytes(stmt, 3);
        const char *mail = (const char *)sqlite3_column_text(stmt, 4);

        // Check that IV size is correct
        if (iv_len != IV_SIZE) {
            fprintf(stderr, "Invalid IV size: %d\n", iv_len);
            continue; // Skip invalid entries
        }

        // Decrypt the password
        if (decrypt_string(key, iv, encrypted_pswd, &decrypted_pswd) != 0) {
            fprintf(stderr, "Failed to decrypt password for login: %s\n", login);
            continue; // Skip this entry
        }

        // Combine all data into a single formatted string
        size_t result_len = strlen(source) + strlen(login) + strlen(mail) +
                            (decrypted_pswd.len * 2) + 50;
        char *result_string = malloc(result_len);
        if (result_string == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            binary_array_free(&decrypted_pswd);
            continue; // Skip this entry
        }

        snprintf(result_string, result_len, "Source: %s, Login: %s, Password: %s, Email: %s",
                 source, login, binary_array_to_string(&decrypted_pswd), mail);

        // Add the result to the list
        temp_results = realloc(temp_results, (temp_count + 1) * sizeof(char *));
        if (!temp_results) {
            fprintf(stderr, "Memory allocation failed.\n");
            free(result_string);
            binary_array_free(&decrypted_pswd);
            continue; // Skip this entry
        }

        temp_results[temp_count] = result_string;
        temp_count++;

        // Clean up decrypted password
        binary_array_free(&decrypted_pswd);
    }

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);

    // Return results
    *results = temp_results;
    *result_count = temp_count;
    return 0; // Success
}

