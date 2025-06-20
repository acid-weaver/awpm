/**
 * \file            cli/cli_utils.c
 * \brief           Implementation of utilities for command line interface
 * implementation
 * \author          Acid Weaver
 * \date            2025-04-27
 * \details
 * Implements utilities (in most functions to achieve DRY) for command line
 * interface implementation functions from cli.h.
 */

/* Copyright (C) 2024-2025  Acid Weaver <acid.weaver@gmail.com>
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

#include "cli/utils.h"

#include <stdio.h>
#include <string.h>

#include "db.h"
#include "encryption.h"
#include "mem.h"
#include "utils.h"

int verify_master_pswd(user_t user, binary_array_t* master_key) {
    binary_array_t secure_buffer = {0};

    secure_buffer = binary_array_secure_alloc(INPUT_BUFF_SIZE);
    if (secure_input("master password", "", (char*)secure_buffer.ptr,
                     INPUT_BUFF_SIZE)
        != 0) {
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Error reading decryption password.\n");
        return -1;
    }
    secure_buffer.len = strlen((char*)secure_buffer.ptr);

    if (secure_buffer.len < 1) {
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Entered password length less that minimum.\n");
        return 1; /* This is the same as wrong password */
    }

    *master_key = binary_array_secure_alloc(KEY_SIZE);
    if (generate_key_from_password(user.salt, (char*)secure_buffer.ptr,
                                   master_key->ptr)
        != 0) {
        binary_array_secure_free(master_key);
        binary_array_secure_free(&secure_buffer);
        fprintf(stderr, "Failed to generate key from password.\n");
        return -1;
    }
    binary_array_secure_free(&secure_buffer);
    master_key->len = KEY_SIZE;

    if (user_verify_master_key(user, master_key->ptr) != 0) {
        binary_array_secure_free(master_key);
        fprintf(stderr, "Failed to verify master password.\n");
        return 1;
    }

    printf("Master password succesfully verified!\n");
    return 0;
}

void display_decrypted_cred_data(cred_data_t* results, int result_count,
                                 binary_array_t* master_key) {
    for (int i = 0; i < result_count; i++) {
        if (decrypt_data(master_key->ptr, results[i].iv, results[i].pswd,
                         &results[i].pswd)
            != 0) {
            fprintf(stderr,
                    "Failed to decrypt password for credential data with "
                    "ID: %d.\n",
                    results[i].id);
        }
        printf("=========\n");
        printf("%s", cred_data_to_string(&results[i]));
    }
    printf("=========\n");
}

void display_cred_data(cred_data_t* results, int result_count) {
    for (int i = 0; i < result_count; i++) {
        binary_array_free(&results[i].pswd);
        results[i].pswd = string_to_binary_array("***");
        printf("=========\n");
        printf("%s", cred_data_to_string(&results[i]));
    }
    printf("=========\n");
}
