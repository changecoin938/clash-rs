#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * # Safety
 * This function is unsafe because it dereferences raw pointers.
 */
void clash_start(uint32_t id, const char *config, const char *cwd, int multithread);

int clash_shutdown(uint32_t id);

/**
 * # Safety
 * This function is unsafe because it dereferences raw pointers.
 */
void clash_free_string(char *s);
