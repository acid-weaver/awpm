#include "memory.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static size_t dynamically_allocated = 0;

void*
safe_malloc(size_t size) {
    dynamically_allocated += size;
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed for %zu bytes.\n", size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void
safe_free(void *ptr, size_t size) {
    if (ptr) {
        dynamically_allocated -= size;
        free(ptr);
    }
}

size_t
get_dynamically_allocated() {
    return dynamically_allocated;
}

dynamic_string_t
dynamic_string_alloc(size_t size) {
    dynamic_string_t dyn_str = {
        .size = 0,
        .ptr  = NULL};

    dyn_str.ptr = safe_malloc(size);
    dyn_str.size = size;
    return dyn_str;
}

void
dynamic_string_free(dynamic_string_t *dyn_str) {
    if (dyn_str) {    // For ptr NULL check in safe_free
        safe_free(dyn_str->ptr, dyn_str->size);
        dyn_str->ptr  = NULL;
        dyn_str->size = 0;
    }
}

int
dynamic_string_copy(dynamic_string_t *src, dynamic_string_t *cpy) {
    if (src == NULL || src->ptr == NULL || src->size == 0) {
        fprintf(stderr, "Invalid source dynamic_string_t.\n");
        return -1;
    }

    dynamic_string_free(cpy);
    *cpy = dynamic_string_alloc(src->size);

    memcpy(cpy->ptr, src->ptr, src->size);
    cpy->size = src->size;

    return 0;
}

void
dynamic_string_print(const dynamic_string_t *dyn_str) {
    if (!dyn_str || !dyn_str->ptr) {
        fprintf(stderr, "Invalid dynamic_string_t provided.\n");
        return;
    }

    printf("Dynamic String:\n");
    printf("  Allocated Size: %zu bytes\n", dyn_str->size);
    printf("  Content Length: %zu bytes\n", strlen(dyn_str->ptr));

    // Check if the string is printable
    int is_printable = 1;
    for (size_t i = 0; i < strlen(dyn_str->ptr); i++) {
        if (!isprint((unsigned char)dyn_str->ptr[i])) {
            is_printable = 0;
            break;
        }
    }

    if (is_printable) {
        printf("  Contents (String): %.*s\n", (int)strlen(dyn_str->ptr), dyn_str->ptr);
    } else {
        printf("  Contents (Hex): ");
        for (size_t i = 0; i < strlen(dyn_str->ptr); i++) {
            printf("%02x", (unsigned char)dyn_str->ptr[i]);
        }
        printf("\n");
    }
}

