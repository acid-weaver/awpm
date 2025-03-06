/**
 * \file            managment.c
 * \brief           Implementation of memory management utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements the general memory management functions declared in mem.h.
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

void *safe_malloc(size_t size) {
    void *ptr = malloc(size);

    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed for %zu bytes.\n", size);
        exit(EXIT_FAILURE);
    }

    return ptr;
}

void safe_free(void *ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}

/*
 * Secure variants
 */

void *secure_malloc(size_t size) {
    void *ptr = safe_malloc(size);

    if (mlock(ptr, size) != 0) {
        perror("mlock failed");
        safe_free(ptr);
        exit(EXIT_FAILURE);
    }

    return ptr;
}

void secure_free(void *ptr, size_t size) {
    if (ptr != NULL) {
        explicit_bzero(ptr, size);
        munlock(ptr, size);
        safe_free(ptr);
    }
}
