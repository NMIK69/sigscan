# sigscan
This is a library made in ```C``` for scanning memory signatures both internally
and externally (```Linux``` only).  It was mostly developed to suit my own use
cases. For that reason it requirers the signatures to be in a specific format.

## Signature Format
- Format 1 (example): ```03 e8 ?? ?? ?? ?? 49 89 c4 48 85```
- Format 2 (example): ```03 e8 ? ? ? ? 49 89 c4 48 85```

Every byte is sperated by a white space without a preceding ```0x```. The symbols
```?``` and ```??``` are wildcards for a single byte.

## Features
- Internal scanning (target is the same process).
- External scanning (target is a different process).

## Limitations
- External scanning requires superuser privileges.

## Dependencies
- None.

# Usage

The library provides two functions for scanning:

```c
/* external scanning */
uintptr_t *sigscan_scan_ext(ssize_t *num_matches, 
		size_t max_matches, const char *sig, int pid);

/* internal scanning */
uintptr_t *sigscan_scan_int(ssize_t *num_matches, 
		size_t max_matches, const char *sig);

```

Both functions scan all readable and executable memory regions of the process
for the specified signature ```sig```. The functions continue scanning until
either the specified maximum number of matches ```max_matches``` is reached or
all memory regions have been scanned. The number of found matches is stored in
```*num_matches```. On success, these functions return a list of addresses
where the signature matches. On failure, they return ```NULL```, and
```*num_matches``` is set to -1.

When scanning externally (using ```sigscan_scan_ext```), you have to put in an
additional ```pid``` parameter, which is the PID of the target process.

## Example Usage

```c
static const char example_func_sig[] = 
	"f3 0f 1e fa 41 56 41 55 41 54 55 48 89 fd 53 e8 ?? ?? ?? ?? 48 "
	"ba ab aa aa aa aa aa aa aa 49 89 c6 48 f7 e2 48 d1 ea 48 8d 7a "
	"03 e8 ?? ?? ?? ?? 49 89 c4 48 85 c0 0f 84 9b 00 00 00 49 83 c6 "
	"01 4c 89 f7 e8 ?? ?? ?? ?? 49 89 c5 48 85 c0 0f 84 b3 00 00 00";

int main(void)
{
	ssize_t num_matches = 0;
	size_t max_matches = 5;
	uintptr_t *matches = sigscan_scan_int(
					&num_matches, 
					max_matches, 
					example_func_sig);

	if (num_matches == -1) {
		printf("[!] Failed to scan for signatures\n");
		return 0;
	}

	printf("[*] Found %zd matches\n", num_matches);
	for (ssize_t i = 0; i < num_matches; i++) {
		printf("[*] Match %zd at address: 0x%lx\n", i + 1, matches[i]);
	}

	free(matches);

	return 0;
}
```
