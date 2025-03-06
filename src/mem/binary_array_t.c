/**
 * \file            binary_array_t.c
 * \brief           Implementation of memory management utilities
 * \author          Acid Weaver
 * \date            2024-12-26
 * \details
 * Implements memory management functions related to binary_array_t and declared
 * in mem.h.
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "mem.h"

/*
 * DYNAMIC STRING FUNCTIONS
 */

binary_array_t binary_array_alloc(size_t size) {
    binary_array_t bin_arr = {.size = 0, .len = 0, .ptr = NULL};

    bin_arr.ptr  = safe_malloc(size);
    bin_arr.size = size;
    return bin_arr;
}

void binary_array_free(binary_array_t *bin_arr) {
    if (bin_arr != NULL) { // ptr not NULL check in safe_free
        safe_free(bin_arr->ptr);
        bin_arr->ptr  = NULL;
        bin_arr->size = 0;
        bin_arr->len  = 0;
    }
}

binary_array_t binary_array_secure_alloc(size_t size) {
    binary_array_t sec_bin_arr = {
        .size = 0,
        .len  = 0,
        .ptr  = NULL,
    };

    sec_bin_arr.ptr  = secure_malloc(size);
    sec_bin_arr.size = size;
    return sec_bin_arr;
}

void binary_array_secure_free(binary_array_t *sec_bin_arr) {
    if (sec_bin_arr != NULL) {
        secure_free(sec_bin_arr->ptr, sec_bin_arr->size);
        sec_bin_arr->ptr  = NULL;
        sec_bin_arr->size = 0;
        sec_bin_arr->len  = 0;
    }
}

int binary_array_copy(binary_array_t *dst, binary_array_t *src) {
    if (src == NULL || src->ptr == NULL || src->size == 0) {
        fprintf(stderr, "Invalid source dynamic_string_t.\n");
        return -1;
    }

    binary_array_free(dst);
    *dst = binary_array_alloc(src->size);

    memcpy(dst->ptr, src->ptr, src->size);
    dst->size = src->size;
    dst->len  = src->len;

    return 0;
}

binary_array_t string_to_binary_array(const char *string) {
    binary_array_t result = {0};

    result = binary_array_alloc(sizeof(string));
    memcpy(result.ptr, string, result.size);
    result.len = strlen(string);

    return result;
}

char *binary_array_to_string(const binary_array_t *bin_arr) {
    static const char empty_string[] = ""; // Reusable empty string
    char *hex_string                 = NULL;
    size_t hex_len                   = 0;
    int is_printable                 = 1;

    // Validate input
    if (bin_arr == NULL || bin_arr->ptr == NULL || bin_arr->len == 0) {
        fprintf(stderr, "Empty or NO binary_array_t provided.\n");
        return (char *)empty_string;
    }

    // Check if the content is printable (assumes it's a null-terminated string)
    for (size_t i = 0; i < bin_arr->len; i++) {
        if (isprint(bin_arr->ptr[i]) == 0) {
            is_printable = 0;
            break;
        }
    }

    if (is_printable) {
        // Return the original string if it's fully printable
        return (char *)bin_arr->ptr;
    }

    // Otherwise, convert to hexadecimal representation
    hex_len    = bin_arr->len * 2 + 1; // 2 chars per byte + null terminator
    hex_string = malloc(hex_len);
    if (hex_string == NULL) {
        fprintf(stderr, "Memory allocation failed for hex string.\n");
        return (char *)empty_string;
    }

    for (size_t i = 0; i < bin_arr->len; i++) {
        snprintf(&hex_string[i * 2], 3, "%02x", bin_arr->ptr[i]);
    }

    return hex_string;
}
