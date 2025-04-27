/**
 * \file            cli/cli_utils.h
 * \brief           Command-line interface utilities
 * \author          Acid Weaver
 * \date            2025-04-27
 * \details
 * Declares functions for implementation CLI.
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

#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include "db.h"

int verify_master_pswd(user_t user, binary_array_t* master_key);

void display_decrypted_cred_data(cred_data_t* results, int result_count,
                                 binary_array_t* master_key);
void display_cred_data(cred_data_t* results, int result_count);

#endif // CLI_UTILS_H
