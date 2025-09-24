#ifndef PRINT_SPEED_H
#define PRINT_SPEED_H

#include <stddef.h>
#include <stdint.h>

void print_results(const char *s, uint64_t *t, size_t tlen);
void print_results_hash(const char *s, uint64_t *t_out, uint64_t *t_in, size_t t_in_len);


#endif
