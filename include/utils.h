/**
 * \file            utils.h
 * \brief           Common utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * This file provides utilities for various needs, that could be used across
 * whole project.
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

#ifndef UTILS_H
#define UTILS_H

#define OPTIONAL_PROMPT "(optional, hit Enter to skip)"
#define PSWD_CONFIRMATION "(confirm previously entered value)"

// Error messages
#define ERR_USER_NOT_FOUND "User not found."
#define ERR_DECRYPTION_FAILED "Decryption failed."

// Utils function part
#include <stdlib.h>

void handle_errors(const char* msg);
void handle_interrupt(int sig);
void disable_debugging();
int std_input(const char* input_name, const char* description, char* result,
              size_t result_size);
int secure_input(const char* input_name, const char* description, char* result,
                 size_t result_size);

#endif // UTILS_H
