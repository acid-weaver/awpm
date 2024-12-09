#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h> // For size_t

typedef struct {
    size_t size;	// Size of allocated memory
    size_t len;         // Actual length of content
    char  *ptr;         // Pointer to the allocated memory
} dynamic_string_t;

void			*safe_malloc(size_t size);
void			safe_free(void *ptr, size_t size);
size_t			get_dynamically_allocated();

dynamic_string_t	dynamic_string_alloc(size_t size);
void			dynamic_string_clear(dynamic_string_t *dyn_str);
int			dynamic_string_copy(dynamic_string_t *src, dynamic_string_t *cpy);
void			dynamic_string_print(const dynamic_string_t *dyn_str);

#endif // MEMORY_H

