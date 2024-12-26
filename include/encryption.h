/**
 * \file            encryption.h
 * \brief           Encryption utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * This file declares encryption and decryption functions used for securing
 * sensitive data such as passwords and master keys.
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

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "memory.h"

int generate_random_bytes(unsigned char* ptr, size_t size);
int generate_hash(const char* input, binary_array_t* output);
int generate_key_from_password(const unsigned char* salt, const char* password,
                               unsigned char* key);
int encrypt_data(const unsigned char* key, const unsigned char* iv,
                 const binary_array_t plaintext, binary_array_t* ciphertext);
int decrypt_data(const unsigned char* key, const unsigned char* iv,
                 const binary_array_t ciphertext, binary_array_t* plaintext);

#endif // ENCRYPTION_H
