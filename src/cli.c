/**
 * \file            cli.c
 * \brief           Implementation of command-line interface utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the command-line interface functions declared in cli.h.
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

#include "cli.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db/creddata.h"
#include "db/users.h"
#include "encryption.h"
#include "memory.h"
#include "secure_memory.h"
#include "utils.h"

void handle_add_new_entry(struct sqlite3* db, const struct config cfg,
                          user_t* user) {
    cred_data_t credential_data =
                    {
                        .id     = -1,
                        .owner  = -1,
                        .source = "",
                        .login  = "",
                        .email  = "",
                        .iv     = "",
                        .pswd =
                            {
                                .size = 0,
                                .len  = 0,
                                .ptr  = NULL,
                            },
                    },
                *results = NULL;
    binary_array_t master_key =
                       {
                           .size = 0,
                           .len  = 0,
                           .ptr  = NULL,
                       },
                   session_key =
                       {
                           .size = 0,
                           .len  = 0,
                           .ptr  = NULL,
                       },
                   secure_buffer = {
                       .size = 0,
                       .len  = 0,
                       .ptr  = NULL,
                   };
    unsigned char session_iv[IV_SIZE];
    int result_count = 0;

    // Add user if not already present
    if (get_or_add_user(db, user) != 0) {
        fprintf(stderr, "Unexpected error while executing get_or_add_user.\n");
        return;
    }

    /*
     * POPULATE credential_data SECTION
     */

    credential_data.owner = user->id;

    if (std_input("Source", "", credential_data.source, INPUT_BUFF_SIZE) != 0) {
        fprintf(stderr, "Error at Source input.\n");
        return;
    }

    /*
     * IF ONE PER SOURCE MODE - WE SHOULD UPDATE EXISTING ENTRY. IN MULTIPLE PER
     * SOURCE MODE OR IF THERE IS NO ENTRIES FOR THIS SOURCE - WE ADD NEW ENTRY.
     * PAY ATTENSION, THAT TECHNICALLY WE WILL UPDATE CREDENTIAL DATA IF ITS ID
     * > 0 AND CORRESPONDS TO EXISTING ENTRY. IF ID <= 0 - WE WILL CREATE NEW
     * ENTRY. IF ID > 0 BUT THERE IS NO EXISTING ENTRIES WITH THIS ID - IT WOULD
     * BE ADDED WITH PROVIDED ID (SHOULD BE AN ERROR IN OUR CASE).
     */

    if (cfg.multiple_accs_per_source == 0
        && cred_data_get_by_source(db, *user, credential_data.source, &results,
                                   &result_count)
               != 0) {
        fprintf(stderr,
                "Failed to check databse for entries with provided source.\n");
        return;

    } else if (result_count == 1) { // cfg.multiple_accs_per_source = 0 here
        printf(
            "Founded entry for this source. This row would be updated due to "
            "'one per source' mode is enabled.\n");
        credential_data = results[0];

    } else if (result_count > 1) { // cfg.multiple_accs_per_source = 0 here
        printf(
            "This source is in multiple account mode. New entry will be "
            "added.\n");
    }

    if (credential_data.id == -1
        && std_input("Login", OPTIONAL_PROMPT, credential_data.login,
                     INPUT_BUFF_SIZE)
               != 0) {
        fprintf(stderr, "Error at Login input.\n");
        return;
    }

    if (credential_data.id == -1
        && std_input("associated e-mail", OPTIONAL_PROMPT,
                     credential_data.email, sizeof(credential_data.email))
               != 0) {
        fprintf(stderr, "Error reading e-mail.\n");
        return;
    }

    /*
     * KEY OR PASSWORD DATA MUST BE CIPHERED WHILE NOT IN USE
     * INITIALIZING SESSION_KEY AND SESSION_IV FOR ENCRYPTION
     */

    session_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_random_bytes(session_key.ptr, session_key.size) != 0) {
        handle_errors("Failed to generate session encryption metadata.");
    }
    session_key.len = session_key.size;

    if (generate_random_bytes(session_iv, IV_SIZE) != 0) {
        handle_errors("Failed to generate session encryption metadata.");
    }

    /* Prompt for password to store */
    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("password to store", "", (char*)secure_buffer.ptr,
                     secure_buffer.size)
        != 0) {
        fprintf(stderr, "Error reading password.\n");
        return;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    /*
     * We don't need entered password until encryption will start
     */

    if (encrypt_data(session_key.ptr, session_iv, secure_buffer,
                     &credential_data.pswd)
        != 0) {
        fprintf(stderr, "Failed to temporarily cipher important data.\n");
        return;
    }
    binary_array_secure_free(&secure_buffer);

    /* Prompt for encryption (master) password */
    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", "", (char*)secure_buffer.ptr,
                     secure_buffer.size)
        != 0) {
        handle_errors("Failed to read encryption password.");
        return;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    master_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_key_from_password(user->salt, (char*)secure_buffer.ptr,
                                   master_key.ptr)
        != 0) {
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }
    binary_array_secure_free(&secure_buffer);
    master_key.len = KEY_SIZE;

    if (user_verify_master_pswd(*user, master_key.ptr) != 0) {
        fprintf(stderr, "Invalid master password, repeat.\n");
        return;
    }

    if (generate_random_bytes(credential_data.iv, IV_SIZE) != 0) {
        handle_errors("Failed to generate IV for password encryption.");
    }

    /*
     * DECIPHER PASSWORD FOR STORING TO CIPHER IT WITH MASTER KEY
     */

    if (decrypt_data(session_key.ptr, session_iv, credential_data.pswd,
                     &credential_data.pswd)
        != 0) {
        handle_errors("Failed to decipher temporarily encrypted memory data.");
    }

    if (encrypt_data(master_key.ptr, credential_data.iv, credential_data.pswd,
                     &credential_data.pswd)
        != 0) {
        fprintf(stderr, "Failed to encrypt credential data.\n");
        return;
    }
    binary_array_secure_free(&master_key);

    if (cred_data_upsert(db, &credential_data) == 0) {
        printf("Credential added successfully.\n");
    } else {
        fprintf(stderr, "Failed to upsert credential.\n");
    }

    binary_array_secure_free(&credential_data.pswd);
}

void handle_retrieve_creddata(struct sqlite3* db, const struct config cfg,
                              user_t* user) {
    cred_data_t* results = NULL;

    binary_array_t secure_buffer =
                       {
                           .size = 0,
                           .len  = 0,
                           .ptr  = NULL,
                       },
                   master_key = {
                       .size = 0,
                       .len  = 0,
                       .ptr  = NULL,
                   };
    char source[INPUT_BUFF_SIZE];
    int result_count = 0, status_code = 0;

    status_code = get_user(db, user);
    if (status_code == 1) {
        fprintf(stderr,
                "Current user NOT registered in database, there is NO stored "
                "passwords for %s.\n",
                user->username);
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

    if (cred_data_get_by_source(db, *user, source, &results, &result_count)
        != 0) {
        fprintf(stderr, "Failed to retrieve credential data.\n");
        return;
    }

    /*
     * VERIFY MASTER PASSWORD, GENERATE MASTER KEY SECTION
     */

    master_key    = binary_array_secure_alloc(KEY_SIZE);
    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", "", (char*)secure_buffer.ptr,
                     INPUT_BUFF_SIZE)
        != 0) {
        fprintf(stderr, "Error reading decryption password.\n");
        return;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    if (secure_buffer.len < 1) {
        fprintf(stderr, "Entered password length less that minimum.\n");
        return;
    }

    if (generate_key_from_password(user->salt, (char*)secure_buffer.ptr,
                                   master_key.ptr)
        != 0) {
        fprintf(stderr, "Failed to generate key from password.\n");
        return;
    }
    binary_array_secure_free(&secure_buffer);
    master_key.len = KEY_SIZE;

    if (user_verify_master_pswd(*user, master_key.ptr) != 0) {
        fprintf(stderr, "Failed to verify master password.\n");
        binary_array_secure_free(&master_key);
        return;
    }

    /*
     * DECIPHER AND DISPLAY RESULTS SECTION
     */

    if (result_count == 0) {
        printf("No results found.\n");
        binary_array_secure_free(&master_key);
        return;

    } else if (result_count == 1) {
        // Only one account per source!
        printf("Credential found.\n");
        if (decrypt_data(master_key.ptr, results[0].iv, results[0].pswd,
                         &results[0].pswd)
            != 0) {
            fprintf(stderr, "Failed to decrypt password.\n");
        }
        printf("%s", cred_data_to_string(&results[0]));

    } else { // result_count > 1 here
        printf("Current source have multiple accounts.\n");

        for (int i = 0; i < result_count; i++) {
            if (decrypt_data(master_key.ptr, results[i].iv, results[i].pswd,
                             &results[i].pswd)
                != 0) {
                fprintf(stderr,
                        "Failed to decrypt password for credential data with "
                        "ID: %d.\n",
                        results[i].id);
            }
            printf("%s", cred_data_to_string(&results[i]));
            printf("=========\n");
        }
    }

    binary_array_secure_free(&master_key);
}

void handle_set_master_pswd(struct sqlite3* db, const struct config cfg,
                            user_t* user) {
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

    if (write_master_pswd(db, user->id, user->master_pswd, user->master_iv)
        != 0) {
        fprintf(stderr,
                "Failed to write ciphrated master password to database.\n");
        return;
    }
}
