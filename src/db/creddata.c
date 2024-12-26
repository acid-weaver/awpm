/**
 * \file            creddata.c
 * \brief           Implementation of credential management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the credential management functions declared in creddata.h.
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

#include "db/creddata.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db/users.h"
#include "encryption.h"
#include "memory.h"
#include "utils.h"

int cred_data_populate(sqlite3_stmt* stmt, cred_data_t* credential_data) {
    const void* buffer;
    int buffer_len;

    if(stmt == NULL || credential_data == NULL) {
        fprintf(stderr, "Invalid arguments to populate_cred_data_from_row.\n");
        return -1;
    }

    credential_data->id    = sqlite3_column_int(stmt, 0);
    credential_data->owner = sqlite3_column_int(stmt, 1);

    buffer = sqlite3_column_text(stmt, 2);
    strncpy(credential_data->source, (const char*)buffer,
            sizeof(credential_data->source) - 1);
    credential_data->source[sizeof(credential_data->source) - 1] = '\0';

    buffer = sqlite3_column_text(stmt, 3);
    strncpy(credential_data->login, buffer ? (const char*)buffer : "",
            sizeof(credential_data->login) - 1);
    credential_data->login[sizeof(credential_data->login) - 1] = '\0';

    buffer = sqlite3_column_text(stmt, 4);
    strncpy(credential_data->email, buffer ? (const char*)buffer : "",
            sizeof(credential_data->email) - 1);
    credential_data->email[sizeof(credential_data->email) - 1] = '\0';

    buffer     = sqlite3_column_blob(stmt, 5);
    buffer_len = sqlite3_column_bytes(stmt, 5);
    if(buffer == NULL || buffer_len != IV_SIZE) {
        fprintf(stderr,
                "Invalid IV for credential data with ID: %d and Source: %s\n",
                credential_data->id, credential_data->source);
        return -1;
    }
    memcpy(credential_data->iv, buffer, IV_SIZE);

    buffer     = sqlite3_column_blob(stmt, 6);
    buffer_len = sqlite3_column_bytes(stmt, 6);

    if(buffer == NULL || buffer_len < 1) {
        fprintf(stderr,
                "Invalid pswd for credential with ID: %d and Source: %s\n",
                credential_data->id, credential_data->source);
        return -1;
    }

    credential_data->pswd = binary_array_alloc(buffer_len);
    memcpy(credential_data->pswd.ptr, buffer, buffer_len);
    credential_data->pswd.len = buffer_len;

    return 0;
}

char* cred_data_to_string(const cred_data_t* cred_data) {
    static const char empty_string[] = "";  // Reusable empty string
    char* result                     = NULL;
    size_t result_size               = 0;

    if(cred_data == NULL) {
        fprintf(stderr, "Invalid input to cred_data_to_string.\n");
        return (char*)empty_string;
    }

    result_size =
        snprintf(NULL, 0,
                 "ID: %d\nSource: %s\nLogin: %s\nEmail: %s\nPassword: %s\n",
                 cred_data->id, cred_data->source, cred_data->login,
                 cred_data->email, binary_array_to_string(&cred_data->pswd))
        + 1;
    result = malloc(result_size);

    if(result == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return (char*)empty_string;
    }

    snprintf(result, result_size,
             "ID: %d\nSource: %s\nLogin: %s\nEmail: %s\nPassword: %s\n",
             cred_data->id, cred_data->source, cred_data->login,
             cred_data->email, binary_array_to_string(&cred_data->pswd));

    return result;
}

int cred_data_upsert(sqlite3* db, const cred_data_t* credential_data) {
    const char* sql_upsert =
        "INSERT INTO creddata (id, source, login, email, iv, pswd, owner) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "source = excluded.source, "
        "login = excluded.login, "
        "email = excluded.email, "
        "iv = excluded.iv, "
        "pswd = excluded.pswd, "
        "owner = excluded.owner;";
    sqlite3_stmt* stmt;
    int rc = 0;

    if(db == NULL || credential_data == NULL || credential_data->owner < 1) {
        fprintf(stderr,
                "Invalid data provided to upsert_cred_data function.\n");
        return -1;
    }

    rc = sqlite3_prepare_v2(db, sql_upsert, -1, &stmt, NULL);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare insert statement: %s\n",
                sqlite3_errmsg(db));
        return rc;
    }

    if(credential_data->id > 0) {
        sqlite3_bind_int(stmt, 1, credential_data->id);  // Valid ID
    } else {
        sqlite3_bind_null(stmt, 1);  // Use NULL for auto-generated ID
    }

    sqlite3_bind_text(stmt, 2, credential_data->source, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, credential_data->login, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, credential_data->email, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, credential_data->iv, IV_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, credential_data->pswd.ptr,
                      credential_data->pswd.len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, credential_data->owner);

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE) {
        if(rc == SQLITE_CONSTRAINT) {
            fprintf(stderr,
                    "Duplicate credential: This combination of source, login, "
                    "and email already exists.\n");
        } else {
            fprintf(stderr, "Failed to insert credential: %s\n",
                    sqlite3_errmsg(db));
        }
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int cred_data_get_by_source(sqlite3* db, const user_t user, const char* source,
                            cred_data_t** results, int* result_count) {
    cred_data_t* temp_results = NULL;
    sqlite3_stmt* stmt;
    const char* sql_query =
        "SELECT id, owner, source, login, email, iv, pswd FROM creddata WHERE "
        "source = ? AND owner = ?;";
    int rc, temp_count = 0;

    if(db == NULL || user.id < 1 || source == NULL || result_count == NULL) {
        fprintf(stderr,
                "Invalid input into get_credentials_by_source function.\n");
        return -1;
    }

    rc = sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, source, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, user.id);

    while((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cred_data_t current_row_result = {0};

        if(cred_data_populate(stmt, &current_row_result) != 0) {
            fprintf(stderr,
                    "Failed to parse data from DB into cred_data_t object.\n");
            return -1;
        }

        // Add the result to the list
        temp_results =
            realloc(temp_results, (temp_count + 1) * sizeof(cred_data_t));
        if(temp_results == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            free(temp_results);
            sqlite3_finalize(stmt);
            return -1;
        }

        temp_results[temp_count] = current_row_result;
        temp_count++;
    }

    if(rc != SQLITE_DONE) {
        fprintf(stderr, "Error executing query: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);

    // Return results
    *results      = temp_results;
    *result_count = temp_count;
    return 0;
}
