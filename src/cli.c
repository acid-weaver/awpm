#include "cli.h"
#include "memory.h"
#include "utils.h"
#include "encryption.h"
#include "db/users.h"
#include "db/creddata.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>


void
handle_add_new_entry(struct sqlite3* db, user_t* user) {
    cred_data_t credential_data = {
        .id = -1,
        .owner = -1,
        .source = "",
        .login = "",
        .email = "",
        .iv = "",
        .pswd = {
            .size = 0,
            .len  = 0,
            .ptr  = NULL,
        },
    };
    unsigned char key[KEY_SIZE];
    char encrypt_password[INPUT_BUFF_SIZE];

    // Add user if not already present
    if (get_or_add_user(db, user) != 0) {
        fprintf(stderr, "Unexpected error while executing get_or_add_user.\n");
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
    credential_data.pswd = binary_array_alloc(INPUT_BUFF_SIZE);
    if (secure_input("password to store", "", (char *)credential_data.pswd.ptr,
                     credential_data.pswd.size) != 0) {
        fprintf(stderr, "Error reading password.\n");
        return;
    }
    credential_data.pswd.len = strlen((char *)credential_data.pswd.ptr);

    if (DEBUG) {
        printf("DEBUG. You entered: %s\n", (char *)credential_data.pswd.ptr);
    }

    // Prompt for optional mail
    if (std_input("associated e-mail", OPTIONAL_PROMPT, credential_data.email,
                  sizeof(credential_data.email)) != 0) {
        fprintf(stderr, "Error reading e-mail.\n");
    }

    // Prompt for encryption password
    if (secure_input("encryption password", "", encrypt_password,
                     sizeof(encrypt_password)) != 0) {
        handle_errors("Failed to read encryption password.");
        return;
    }

    if (generate_key_from_password(user->salt, encrypt_password, key) != 0) {
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }

    // Add credential
    if (add_credential(db, credential_data, key) == 0) {
        printf("Credential added successfully.\n");
    } else {
        fprintf(stderr, "Failed to add credential.\n");
    }
}


void
handle_retrieve_creddata(struct sqlite3* db, user_t* user) {
    char *source = NULL;
    char decrypt_password[INPUT_BUFF_SIZE], source_buffer[INPUT_BUFF_SIZE];
    unsigned char key[KEY_SIZE];
    char **results = NULL;
    int result_count = 0, status_code = 0;

    status_code = get_user(db, user);
    if (status_code == 1) {
        fprintf(stderr, "Current user NOT registered in database, there is NO stored passwords for %s.\n", user->username);
        return;
    } else if (status_code != 0) {
        fprintf(stderr, "Unexpected error while executing get_user.\n");
        return;
    }

    // Prompt for source name
    printf("Enter source name to filter (optional, press Enter to skip): ");
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

    // Retrieve user's salt if a decryption password is provided
    if (strlen(decrypt_password) > 0) {
        if (generate_key_from_password(user->salt, decrypt_password, key) != 0) {
            fprintf(stderr, "Failed to generate key from password.\n");
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

void
handle_set_master_pswd(struct sqlite3* db, user_t* user) {
    int status_code = 0;

    status_code = get_user(db, user);
    if (status_code != 0) {
        fprintf(stderr, "Failed to authenticate user.\n");
        return;
    }

    if (user_set_master_pswd(user) != 0) {
        fprintf(stderr, "Failed to prepare new master password. Try again.\n");
        return;
    }

    if (write_master_pswd(db, user->id, user->master_pswd, user->master_iv) != 0) {
        fprintf(stderr, "Failed to write ciphrated master password to database.\n");
        return;
    }
}

