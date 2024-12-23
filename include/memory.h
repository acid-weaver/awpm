/**
 * \file            memory.h
 * \brief           Memory management utilities for dynamic allocations
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * This file provides utility functions for dynamic memory allocation, including
 * safe_malloc, safe_free, and tracking of allocated memory blocks.
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

#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>                 // For size_t

typedef struct {
    size_t          size;           // Size of allocated memory
    char*           ptr;            // Pointer to the allocated memory
} dynamic_string_t;

typedef struct {
    size_t          size;           // Size of allocated memory
    size_t          len;            // Length of content
    unsigned char*  ptr;            // Pointer to content
} binary_array_t;


void*               safe_malloc(size_t size);
void                safe_free(void* ptr, size_t size);
size_t              get_dynamically_allocated();

dynamic_string_t    dynamic_string_alloc(size_t size);
void                dynamic_string_free(dynamic_string_t* dyn_str);
int                 dynamic_string_copy(dynamic_string_t* dst, dynamic_string_t* src);
void                dynamic_string_print(const dynamic_string_t* dyn_str);

binary_array_t      binary_array_alloc(size_t size);
void                binary_array_free(binary_array_t* bin_arr);
int                 binary_array_copy(binary_array_t* dst, binary_array_t* src);
char*               binary_array_to_string(const binary_array_t* bin_arr);
void                binary_array_print(const binary_array_t* bin_arr);

#endif                      // MEMORY_H

