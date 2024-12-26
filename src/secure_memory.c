/**
 * \file            secure_memory.c
 * \brief           Implementation of secure memory management utilities
 * \author          Acid Weaver
 * \date            2024-12-26
 * \details
 * Implements the secure memory management functions declared in
 * secure_memory.h.
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

#include "secure_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "memory.h"

/*
 * GENERAL MEMORY MANAGMENT
 */

static size_t securely_allocated = 0;

void* secure_malloc(size_t size) {
    void* ptr = safe_malloc(size);

    if(mlock(ptr, size) != 0) {
        perror("mlock failed");
        safe_free(ptr, size);
        exit(EXIT_FAILURE);
    }

    securely_allocated += size;
    return ptr;
}

void secure_free(void* ptr, size_t size) {
    if(ptr != NULL) {
        explicit_bzero(ptr, size);
        munlock(ptr, size);
        securely_allocated -= size;
        safe_free(ptr, size);
    }
}

size_t get_securely_allocated() {
    return securely_allocated;
}

/*
 * DYNAMIC STRING FUNCTIONS
 */

dynamic_string_t dynamic_string_secure_alloc(size_t size) {
    dynamic_string_t sec_dyn_str = {
        .size = 0,
        .ptr  = NULL,
    };

    sec_dyn_str.ptr  = secure_malloc(size);
    sec_dyn_str.size = size;
    return sec_dyn_str;
}

void dynamic_string_secure_free(dynamic_string_t* sec_dyn_str) {
    if(sec_dyn_str != NULL) {
        secure_free(sec_dyn_str->ptr, sec_dyn_str->size);
        sec_dyn_str->ptr  = NULL;
        sec_dyn_str->size = 0;
    }
}

/*
 * BINARY ARRAY FUNCTIONS
 */

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

void binary_array_secure_free(binary_array_t* sec_bin_arr) {
    if(sec_bin_arr != NULL) {
        secure_free(sec_bin_arr->ptr, sec_bin_arr->size);
        sec_bin_arr->ptr  = NULL;
        sec_bin_arr->size = 0;
        sec_bin_arr->len  = 0;
    }
}
