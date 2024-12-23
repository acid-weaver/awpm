/**
 * \file            cli.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface functions declared in cli.h.
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
handle_add_new_entry(struct sqlite3* db, struct config cfg, user_t* user) {
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
    }, *results = NULL;
    unsigned char key[KEY_SIZE];
    char encrypt_password[INPUT_BUFF_SIZE];
    int result_count = 0, update = 0;

    // Add user if not already present
    if (get_or_add_user(db, user) != 0) {
        fprintf(stderr, "Unexpected error while executing get_or_add_user.\n");
        return;
    }
    credential_data.owner = user->id;

    if (std_input("Source", "", credential_data.source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error at Source input.\n");
        return;
    }

    if (cfg.multiple_accs_per_source == 0 && get_credentials_by_source(db, *user,
        credential_data.source, &results, &result_count) != 0) {
        fprintf(stderr, "Failed to check databse for entries with provided source.\n");
        return;

    } else if (result_count == 1) {
        printf("Founded entry for this source. This row would be updated due to 'one per source' mode is enabled.\n");
        credential_data = results[0];
        update = 1;

    } else if (result_count > 1){
        printf("This source is in multiple account mode. New entry will be added.\n");
    }

    if (update == 0 && std_input("Login", OPTIONAL_PROMPT, credential_data.login, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error at Login input.\n");
        return;
    }

    if (update == 0 && std_input("associated e-mail", OPTIONAL_PROMPT, credential_data.email,
                  sizeof(credential_data.email)) != 0) {
        fprintf(stderr, "Error reading e-mail.\n");
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

    // Prompt for encryption password
    if (secure_input("master password", "", encrypt_password,
                     sizeof(encrypt_password)) != 0) {
        handle_errors("Failed to read encryption password.");
        return;
    }

    if (generate_key_from_password(user->salt, encrypt_password, key) != 0) {
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }

    if (user_verify_master_pswd(*user, key) != 0) {
        fprintf(stderr, "Invalid master password, repeat.\n");
        return;
    }

    if (encrypt_string(key, credential_data.iv, credential_data.pswd,
                       &credential_data.pswd) != 0) {
        fprintf(stderr, "Failed to encrypt credential data.\n");
        return;
    }

    // Add credential
    if (upsert_cred_data(db, &credential_data) == 0) {
        printf("Credential added successfully.\n");
    } else {
        fprintf(stderr, "Failed to upsert credential.\n");
    }
}


void
handle_retrieve_creddata(struct sqlite3* db, struct config cfg, user_t* user) {
    cred_data_t* results = NULL;
    char source[INPUT_BUFF_SIZE], master_password[INPUT_BUFF_SIZE];
    unsigned char key[KEY_SIZE];
    int result_count = 0, status_code = 0;

    status_code = get_user(db, user);
    if (status_code == 1) {
        fprintf(stderr, "Current user NOT registered in database, there is NO stored passwords for %s.\n", user->username);
        return;
    } else if (status_code != 0) {
        fprintf(stderr, "Unexpected error while executing get_user.\n");
        return;
    }

    if (cfg.debug) {
        printf("DEBUG. user id is: %d\n", user->id);
    }

    // Prompt for source name
    if (std_input("source", "", source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error reading source.\n");
        return;
    }

    // Prompt for decryption password
    if (secure_input("master password", "", master_password,
                     INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error reading decryption password.\n");
        return;
    }

    if (strlen(master_password) < 1) {
        fprintf(stderr, "Entered password length less that minimum.\n");
        return;
    }

    if (generate_key_from_password(user->salt, master_password, key) != 0) {
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }

    if (user_verify_master_pswd(*user, key) != 0) {
        fprintf(stderr, "Failed to verify master password.\n");
        return;
    }

    if (get_credentials_by_source(db, *user, source, &results, &result_count) != 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    if (result_count == 0) {
        printf("No results found.\n");

    } else if (result_count == 1) {
        // Only one account per source!
        printf("Credential found.\n");
        if (decrypt_string(key, results[0].iv, results[0].pswd, &results[0].pswd) != 0) {
            fprintf(stderr, "Failed to decrypt password.\n");
        }
        printf("%s", cred_data_to_string(&results[0]));

    } else if (cfg.multiple_accs_per_source == 0) { // result_count > 1 here
        printf("Multiple credentials for this source in 'one per source' mode.\n");
        printf("Change config and run program again or choose credential to delete.\n");

    } else if (cfg.multiple_accs_per_source > 0) {  // result_count > 1 here
        // Handle multiple accounts
        printf("Multiple accounts in multiple mode.\n");
    }

    // char** results_str;
    // Retrieve and display data
    // if (retrieve_and_decipher_by_source(db, source, key, &results_str, &result_count) == 0) {
    //     printf("Retrieved %d entries:\n", result_count);
    //     for (int i = 0; i < result_count; i++) {
    //         printf("%s\n", results_str[i]);
    //         free(results_str[i]); // Free each result string
    //     }
    //     free(results_str); // Free the results array
    // } else {
    //     fprintf(stderr, "Failed to retrieve data.\n");
    // }
}

void
handle_set_master_pswd(struct sqlite3* db, struct config cfg, user_t* user) {
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

