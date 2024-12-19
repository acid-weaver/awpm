#include "memory.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static size_t dynamically_allocated = 0;

void*
safe_malloc(size_t size) {
    void *ptr = malloc(size);

    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed for %zu bytes.\n", size);
        exit(EXIT_FAILURE);
    }

    dynamically_allocated += size;
    return ptr;
}

void
safe_free(void *ptr, size_t size) {
    if (ptr != NULL) {
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
    if (dyn_str != NULL) {    // ptr not NULL check in safe_free
        safe_free(dyn_str->ptr, dyn_str->size);
        dyn_str->ptr  = NULL;
        dyn_str->size = 0;
    }
}

int
dynamic_string_copy(dynamic_string_t* dst, dynamic_string_t *src) {
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

binary_array_t
binary_array_alloc(size_t size) {
    binary_array_t bin_arr = {
        .size = 0,
        .len  = 0,
        .ptr  = NULL
    };

    bin_arr.ptr = safe_malloc(size);
    bin_arr.size = size;
    return bin_arr;
}

void
binary_array_free(binary_array_t* bin_arr) {
    if (bin_arr != NULL) {    // ptr not NULL check in safe_free
        safe_free(bin_arr->ptr, bin_arr->size);
        bin_arr->ptr  = NULL;
        bin_arr->size = 0;
        bin_arr->len  = 0;
    }
}

int
binary_array_copy(binary_array_t* dst, binary_array_t *src) {
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

char*
binary_array_to_string(const binary_array_t *bin_arr) {
    static const char empty_string[] = ""; // Reusable empty string
    char* hex_string = NULL;
    size_t hex_len = 0;
    int is_printable = 1;

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
    hex_len = bin_arr->len * 2 + 1; // 2 chars per byte + null terminator
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

void
binary_array_print(const binary_array_t *bin_arr) {
    if (bin_arr == NULL || bin_arr->ptr == NULL) {
        fprintf(stderr, "No binary array provided for printing.\n");
        return;
    }

    printf("Binary data (array):\n");
    printf("  Allocated Size: %zu bytes\n", bin_arr->size);
    printf("  Content Length: %zu bytes\n", bin_arr->len);

    // Check if the string is printable
    int is_printable = 1;
    for (size_t i = 0; i < bin_arr->len; i++) {
        if (isprint(bin_arr->ptr[i]) == 0) {
            is_printable = 0;
            break;
        }
    }

    if (is_printable) {
        printf("  Contents (String): %.*s\n", (int)bin_arr->len, bin_arr->ptr);
    } else {
        printf("  Contents (Hex): ");
        for (size_t i = 0; i < bin_arr->len; i++) {
            printf("%02x", bin_arr->ptr[i]);
        }
        printf("\n");
    }
}

