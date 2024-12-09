#include "cli.h"
// #include "memory.h"
#include "memory.h"
#include "utils.h"
#include "db/database.h"
#include "db/users.h"
#include "db/creddata.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>


void handle_add_new_entry(struct sqlite3 *db, const char *username) {
    cred_data_t credential_data = {
        .id = -1,
        .owner = -1,
        .source = "",
        .login = "",
        .email = "",
        .iv = "",
        .pswd = {
            .ptr  = NULL,
            .size = 0,
        },
    };
    unsigned char salt[SALT_SIZE], key[KEY_SIZE];
    char encrypt_password[INPUT_BUFF_SIZE];

    // Add user if not already present
    if (!user_exists(db, username)) {
        printf("User '%s' not found. Adding to database...\n", username);
        if (add_user(db, username) != SQLITE_OK) {
            fprintf(stderr, "Failed to add user '%s'.\n", username);
            return;
        }
        printf("User '%s' added successfully.\n", username);
    }

    if (get_user_id_by_username(db, username, &credential_data.owner) != 0) {
        fprintf(stderr, "Failed to retrieve owner ID for username: %s\n", username);
        return;
    }

    if (std_input("Source", "", credential_data.source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error at Source input.\n");
        return;
    }

    if (std_input("Login", OPTIONAL_PROMPT, credential_data.login, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error at Login input.\n");
        return;
    }

    // Prompt for password
    credential_data.pswd = dynamic_string_alloc(INPUT_BUFF_SIZE);
    if (secure_input("password to store", "", credential_data.pswd.ptr,
                     credential_data.pswd.size) != 0) {
        fprintf(stderr, "Error reading password.\n");
        return;
    }
    credential_data.pswd.len = strlen(credential_data.pswd.ptr);
    printf("DEBUG. Entered: %s.\n", credential_data.pswd.ptr);

    // Prompt for optional mail
    if (std_input("associated e-mail", "", credential_data.email,
                  sizeof(credential_data.email)) != 0) {
        fprintf(stderr, "Error reading e-mail.\n");
    }

    // Prompt for encryption password
    if (secure_input("encryption password", "", encrypt_password,
                     sizeof(encrypt_password)) != 0) {
        return;
    }

    // Derive key using PBKDF2
    if (get_salt_by_username(db, username, salt) != 0) {
        fprintf(stderr, "Failed to retrieve salt for user: %s\n", username);
        return;
    }


    if (!PKCS5_PBKDF2_HMAC(encrypt_password, strlen(encrypt_password), salt, SALT_SIZE, ITERATIONS, EVP_sha256(), KEY_SIZE, key)) {
        fprintf(stderr, "Failed to derive encryption key.\n");
        return;
    }

    // Add credential
    if (add_credential(db, credential_data, key) == 0) {
        printf("Credential added successfully.\n");
    } else {
        fprintf(stderr, "Failed to add credential.\n");
    }
}


void handle_retrieve_creddata(struct sqlite3 *db, const char *username) {
    char *source = NULL;
    char decrypt_password[INPUT_BUFF_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    char **results = NULL;
    int result_count = 0;

    // Prompt for source name
    printf("Enter source name to filter (optional, press Enter to skip): ");
    char source_buffer[INPUT_BUFF_SIZE];
    if (fgets(source_buffer, INPUT_BUFF_SIZE, stdin) == NULL) {
        fprintf(stderr, "Error reading source.\n");
        return;
    }
    source_buffer[strcspn(source_buffer, "\n")] = '\0'; // Remove newline
    source = strlen(source_buffer) > 0 ? strdup(source_buffer) : NULL;

    // Prompt for decryption password
    if (secure_input("decryption password", OPTIONAL_PROMPT, decrypt_password,
                     INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error reading decryption password.\n");
        return;
    }
    printf("DEBUG. Entered: %s\n", decrypt_password);

    // Retrieve user's salt if a decryption password is provided
    if (strlen(decrypt_password) > 0) {
        if (get_salt_by_username(db, username, salt) != 0) {
            fprintf(stderr, "Failed to retrieve salt for user: %s\n", username);
            free(source);
            return;
        }
        if (!PKCS5_PBKDF2_HMAC(decrypt_password, strlen(decrypt_password), salt, SALT_SIZE, ITERATIONS, EVP_sha256(), KEY_SIZE, key)) {
            fprintf(stderr, "Failed to derive decryption key.\n");
            free(source);
            return;
        }
    }

    // Retrieve and display data
    if (retrieve_and_decipher_by_source(db, source, key, &results, &result_count) == 0) {
        printf("Retrieved %d entries:\n", result_count);
        for (int i = 0; i < result_count; i++) {
            printf("%s\n", results[i]);
            free(results[i]); // Free each result string
        }
        free(results); // Free the results array
    } else {
        fprintf(stderr, "Failed to retrieve data.\n");
    }

    // Clean up
    free(source);
}

