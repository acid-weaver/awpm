/**
 * \file            dynamic_string.c
 * \brief           Implementation of memory management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the memory management functions related to dynamic_string_t
 * and declared in mem.h.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "mem.h"

dynamic_string_t dynamic_string_alloc(size_t size) {
    dynamic_string_t dyn_str = {.size = 0, .ptr = NULL};

    dyn_str.ptr  = safe_malloc(size);
    dyn_str.size = size;
    return dyn_str;
}

void dynamic_string_free(dynamic_string_t *dyn_str) {
    if (dyn_str != NULL) { // ptr not NULL check in safe_free
        safe_free(dyn_str->ptr);
        dyn_str->ptr  = NULL;
        dyn_str->size = 0;
    }
}

dynamic_string_t dynamic_string_secure_alloc(size_t size) {
    dynamic_string_t sec_dyn_str = {
        .size = 0,
        .ptr  = NULL,
    };

    sec_dyn_str.ptr  = secure_malloc(size);
    sec_dyn_str.size = size;
    return sec_dyn_str;
}

void dynamic_string_secure_free(dynamic_string_t *sec_dyn_str) {
    if (sec_dyn_str != NULL) {
        secure_free(sec_dyn_str->ptr, sec_dyn_str->size);
        sec_dyn_str->ptr  = NULL;
        sec_dyn_str->size = 0;
    }
}

int dynamic_string_copy(dynamic_string_t *dst, dynamic_string_t *src) {
    if (src == NULL || src->ptr == NULL || src->size == 0) {
        fprintf(stderr, "Invalid source dynamic_string_t.\n");
        return -1;
    }

    dynamic_string_free(dst);
    *dst = dynamic_string_alloc(src->size);

    memcpy(dst->ptr, src->ptr, src->size);
    dst->size = src->size;

    return 0;
}

binary_array_t dynamic_string_to_binary_array(dynamic_string_t *dyn_str) {
    binary_array_t bin_arr = {
        .size = 0,
        .len  = 0,
        .ptr  = NULL,
    };

    bin_arr = binary_array_alloc(dyn_str->size);
    memcpy(bin_arr.ptr, dyn_str->ptr, dyn_str->size);
    bin_arr.size = dyn_str->size;
    bin_arr.len  = strlen(dyn_str->ptr);
    return bin_arr;
}
