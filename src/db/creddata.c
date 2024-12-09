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
    dynamic_string_print(&credential_data->pswd);
}

int add_credential(sqlite3 *db, cred_data_t credential_data, const unsigned char *key) {
    unsigned char *ciphertext     = NULL;
    size_t         ciphertext_len = 0;

    if (encrypt_password(key, credential_data.pswd, credential_data.iv, &ciphertext, &ciphertext_len) != 0) {
        fprintf(stderr, "Failed to encrypt password.\n");
        return -1;
    }

    if (DEBUG) {
        char *decrypted_data = NULL;

        if (decrypt_password(key, ciphertext, ciphertext_len,
                             credential_data.iv, &decrypted_data) != 0) {
            fprintf(stderr, "Debug decyphrating failed!\n");
            return -1;
        }
        printf("DEBUG. Decrypted after encryption data: %s\n", decrypted_data);
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
    sqlite3_bind_blob(stmt, 3, ciphertext,
                      ciphertext_len, SQLITE_STATIC);
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
        const char *source = (const char *)sqlite3_column_text(stmt, 0);
        const char *login = (const char *)sqlite3_column_text(stmt, 1);
        const unsigned char *encrypted_pswd = sqlite3_column_blob(stmt, 2);
        int encrypted_len = sqlite3_column_bytes(stmt, 2);
        const unsigned char *iv = sqlite3_column_blob(stmt, 3);
        int iv_len = sqlite3_column_bytes(stmt, 3);
        const char *mail = (const char *)sqlite3_column_text(stmt, 4);

        // Check that IV size is correct
        if (iv_len != IV_SIZE) {
            fprintf(stderr, "Invalid IV size: %d\n", iv_len);
            continue; // Skip invalid entries
        }

        // Decrypt the password
        char *decrypted_password = NULL;
        if (decrypt_password(key, encrypted_pswd, encrypted_len, iv, &decrypted_password) != 0) {
            fprintf(stderr, "Failed to decrypt password for login: %s\n", login);
            continue; // Skip this entry
        }

        // Combine all data into a single formatted string
        size_t result_len = strlen(source) + strlen(login) + strlen(mail) + strlen(decrypted_password) + 50;
        char *result_string = malloc(result_len);
        if (!result_string) {
            fprintf(stderr, "Memory allocation failed.\n");
            free(decrypted_password);
            continue; // Skip this entry
        }

        snprintf(result_string, result_len, "Source: %s, Login: %s, Password: %s, Email: %s",
                 source, login, decrypted_password, mail);

        // Add the result to the list
        temp_results = realloc(temp_results, (temp_count + 1) * sizeof(char *));
        if (!temp_results) {
            fprintf(stderr, "Memory allocation failed.\n");
            free(result_string);
            free(decrypted_password);
            continue; // Skip this entry
        }

        temp_results[temp_count] = result_string;
        temp_count++;

        // Clean up decrypted password
        free(decrypted_password);
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

