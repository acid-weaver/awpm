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

