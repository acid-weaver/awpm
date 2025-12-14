/**
 * \file            config.h
 * \brief           App configuration
 * \author          Acid Weaver
 * \date            2025-06-20
 * \details
 * This file provides constants and app configuration related structs,
 * functions, etc.
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

#ifndef CONFIG_H
#define CONFIG_H

// Input constants
#define INPUT_BUFF_SIZE 256

// OpenSSL encryption constants
#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16
#define ITERATIONS 10000

#define HASH_SIZE 64
#define HASH_ALG EVP_sha3_512()

// Config related
#ifndef CONFIG_PATH
#define CONFIG_PATH "~/.config/awpm/awpm.ini"
#endif

struct config {
    int debug;                        // 0 (off) or 1 (on)
    int multiple_accs_per_source;     // 0 (off) or 1 (on)
    char cli_output[INPUT_BUFF_SIZE]; /* "full_clipboard" / "pswd_clipboard" /
                                         "login_pswd_clipboard" /
                                         "email_pswd_clipboard" / "display" /
                                         "pswd_clipboard_display" */
    char db_path[INPUT_BUFF_SIZE * 2];
};

extern struct config cfg;

int config_load(const char* path);

#endif // CONFIG_H
