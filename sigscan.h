#ifndef SIGSCAN_H
#define SIGSCAN_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

/* external scanning */
uintptr_t *sigscan_scan_ext(ssize_t *num_matches, 
		size_t max_matches, const char *sig, int pid);

/* internal scanning */
uintptr_t *sigscan_scan_int(ssize_t *num_matches, 
		size_t max_matches, const char *sig);

#endif
