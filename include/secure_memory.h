/**
 * \file            secure_memory.h
 * \brief           Memory management utilities for secure dynamic allocations
 * \author          Acid Weaver
 * \date            2024-12-26
 * \details
 * This file provides utility functions for secure dynamic memory allocation,
 * including secure_malloc, secure_free, and tracking of allocated memory
 * blocks.
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

#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h> // For size_t

#include "memory.h"

/* General memory managment helpers */
void* secure_malloc(size_t size);
void secure_free(void* ptr, size_t size);

/* Dynamic string related */
dynamic_string_t dynamic_string_secure_alloc(size_t size);
void dynamic_string_secure_free(dynamic_string_t* dyn_str);

/* Binary array related */
binary_array_t binary_array_secure_alloc(size_t size);
void binary_array_secure_free(binary_array_t* bin_arr);

#endif // SECURE_MEMORY_H
