#include "utils.h"
#include "memory.h"
#include "db/creddata.h"
#include "encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void
print_credential_data(cred_data_t *credential_data) {
    if (!credential_data) {
        fprintf(stderr, "Invalid cred_data_t provided.\n");
        return;
    }

    printf("Credential Data:\n");
    printf("  Source: %s\n", credential_data->source);
    printf("  Login: %s\n", credential_data->login);
    printf("  Email: %s\n", credential_data->email);
    printf("  Owner ID: %d\n", credential_data->owner);

    printf("  IV: ");
    for (size_t i = 0; i < IV_SIZE; i++) {
        printf("%02x", (unsigned char)credential_data->iv[i]);
    }
    printf("\n");

    printf("  Encrypted Password:\n");
    binary_array_print(&credential_data->pswd);
}

int add_credential(sqlite3 *db, cred_data_t credential_data, const unsigned char *key) {
    binary_array_t ciphertext = {
        .size = 0,
        .len  = 0,
        .ptr  = NULL,
    };

    if (encrypt_string(key, credential_data.iv, credential_data.pswd,
                       &ciphertext) != 0) {
        fprintf(stderr, "Failed to encrypt password.\n");
        return -1;
    }

    if (DEBUG) {
        binary_array_t decrypted_data = {
            .size = 0,
            .len  = 0,
            .ptr  = NULL,
        };

        if (decrypt_string(key, credential_data.iv, ciphertext, &decrypted_data) != 0) {
            fprintf(stderr, "Debug decyphrating failed!\n");
            return -1;
        }
        printf("DEBUG. Decrypted after encryption data:\n");
        binary_array_print(&decrypted_data);
    }

    const char *sql_insert =
        "INSERT INTO creddata (source, login, pswd, iv, mail, owner) VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    sqlite3_bind_text(stmt, 1, credential_data.source, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, credential_data.login, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, ciphertext.ptr,
                      ciphertext.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, credential_data.iv, IV_SIZE, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, credential_data.email, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, credential_data.owner);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert credential: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int retrieve_and_decipher_by_source(sqlite3 *db, const char *source, const unsigned char *key, char ***results, int *result_count) {
    const char *sql_query = "SELECT source, login, pswd, iv, mail FROM creddata WHERE source = ?;";
    sqlite3_stmt *stmt;
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

