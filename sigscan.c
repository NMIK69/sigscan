#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "sigscan.h"

#define ARR_SIZE(arr) (sizeof(arr) / sizeof(*arr))


struct map_entry
{
	uintptr_t start;
	uintptr_t end;

	int r, w, x;

	int is_searchable;
};

struct sig_byte
{
	uint8_t is_wildcard;
	uint8_t byte;
};

static ssize_t get_nbytes(const char *sig);
static struct sig_byte *sig_to_bytes(const char *sig, size_t nbytes);

static int attatch(int pid);
static int detatch(int pid);

static int setup_proc_files(int pid);
static int get_map_entry(struct map_entry *out, const char *fname);

static ssize_t read_mem_ext(int pid, long start, long end, 
				uint8_t **data, size_t *len);

static long find_sig(const uint8_t *data, 
		size_t data_size, const struct sig_byte *sig, 
		size_t sig_len);


static char pmem_file[PATH_MAX];
static char pmap_file[PATH_MAX];


uintptr_t *sigscan_scan_int(ssize_t *num_matches, 
	size_t max_matches, const char *sig)
{
	int pid = getpid();

	if(setup_proc_files(pid) != 0)
		return NULL;

	uint8_t *mem_ptr = NULL;
	struct map_entry me = {0};

	uintptr_t *matches = malloc(sizeof(*matches) * max_matches);
	if(matches == NULL)
		return NULL;
	

	size_t nbytes = get_nbytes(sig);
	struct sig_byte *sig_bytes = sig_to_bytes(sig, nbytes);
	if(sig_bytes == NULL) {
		free(matches);
		return NULL;
	}

	int ret = get_map_entry(&me, pmap_file);
	size_t i = 0;
	while(ret == 0) {
	
		if(me.is_searchable == 1 && me.r == 1 && me.w == 0 && me.x == 1) {

			mem_ptr = (uint8_t *)me.start;
			assert(me.end >= me.start);
			size_t mem_size = me.end - me.start;

			long off = find_sig(mem_ptr, mem_size, sig_bytes, nbytes);

			while(off > 0 && i < max_matches) {
				matches[i++] = off + me.start;
				off = find_sig(NULL, mem_size, sig_bytes, nbytes);
			}
		}

		ret = get_map_entry(&me, NULL);
	}

	if(ret == -1)
		goto err_out;

	free(sig_bytes);

	(*num_matches) = i;
	return matches;

err_out:
	(*num_matches) = -1;
	free(sig_bytes);
	free(matches);
	return NULL;
}



uintptr_t *sigscan_scan_ext(ssize_t *num_matches, 
	size_t max_matches, const char *sig, int pid)
{
	if(setup_proc_files(pid) != 0)
		return NULL;

	uint8_t *mem_buf = NULL;
	size_t mem_buf_size = 0;
	struct map_entry me = {0};

	uintptr_t *matches = malloc(sizeof(*matches) * max_matches);
	if(matches == NULL)
		return NULL;
	

	size_t nbytes = get_nbytes(sig);
	struct sig_byte *sig_bytes = sig_to_bytes(sig, nbytes);
	if(sig_bytes == NULL) {
		free(matches);
		return NULL;
	}

	int ret = get_map_entry(&me, pmap_file);
	size_t i = 0;
	while(ret == 0) {
	
		if(me.is_searchable == 1 && me.r == 1 && me.w == 0 && me.x == 1) {

			ssize_t br = read_mem_ext(pid, me.start, me.end,
						&mem_buf, &mem_buf_size);

			if(br == -1)
				goto err_out;

			long off = find_sig(mem_buf, br, sig_bytes, nbytes);

			while(off > 0 && i < max_matches) {
				matches[i++] = off + me.start;
				off = find_sig(NULL, br, sig_bytes, nbytes);
			}
		}

		ret = get_map_entry(&me, NULL);
	}

	if(ret == -1)
		goto err_out;

	free(mem_buf);
	free(sig_bytes);

	(*num_matches) = i;
	return matches;

err_out:

	(*num_matches) = -1;
	free(mem_buf);
	free(sig_bytes);
	free(matches);
	return NULL;
}


/* assumes that the entire signature is in a single memory section. */
static long find_sig(const uint8_t *data, 
		size_t data_size, const struct sig_byte *sig, 
		size_t sig_len)

{
	static const uint8_t *buf = NULL;
	static size_t buf_size = 0;
	static size_t i = 0;

	if(data != NULL) {
		buf = data;
		buf_size = data_size;
		i = 0;
	}

	if(buf == NULL)
		return -1;
	
	size_t j = 0;
	while(i < buf_size) {
		if(j == sig_len) {
			assert(i >= j);
			return i - j;
		}
		
		if(sig[j].is_wildcard == 1 || sig[j].byte == buf[i])
			j += 1;
		else 
			j = 0;

		i += 1;
	}

	if(j == sig_len) {
		assert(i >= j);
		return i - j;
	}

	buf = NULL;
	buf_size = 0;
	i = 0;

	return -1;
}


static ssize_t read_mem_ext(int pid, long start, long end, uint8_t **data, size_t *len)
{

	if(attatch(pid) != 0)
		return -1;


	FILE *f = fopen(pmem_file, "r");
	if(f == NULL)
		return -1;

	
	if(fseek(f, start, SEEK_SET) != 0)
		return -1;

	if(*len == 0) 
		*data = NULL;
	
	if(*data == NULL)
		*len = 0;

	long nbytes = end - start;	
	if((long)*len < nbytes) {
		*data = realloc(*data, nbytes);
		if(*data == NULL) {
			*len = 0;
			return -1;
		}
		*len = nbytes;
	}

	size_t br = fread(*data, sizeof(**data), nbytes, f);		
	if(br == 0 || br != (size_t)nbytes)
		return -1;

	if(detatch(pid) != 0)
		return -1;

	if(fclose(f) != 0)
		return -1;
	
	return nbytes;
}


static ssize_t get_nbytes(const char *sig)
{
	size_t num_ws = 0;
	for(size_t i = 0; i < strlen(sig); i++) {
		if(sig[i] == ' ')
			num_ws += 1;
	}

	return num_ws + 1;
}

static struct sig_byte *sig_to_bytes(const char *sig, size_t nbytes)
{
	size_t sig_len = strlen(sig);
	struct sig_byte *bytes = malloc(sizeof(*bytes) * nbytes); 
	if(bytes == NULL)
		return NULL;
	
	/* so i can use strtok without destroying the original sig */
	char *sig_cpy = malloc(sizeof(*sig_cpy) * (sig_len + 1));
	if(sig_cpy == NULL) {
		free(bytes);
		return NULL;
	}
	memcpy(sig_cpy, sig, sig_len + 1);

	char *tok = strtok(sig_cpy, " ");
	size_t i = 0;
	while(tok != NULL) {

		if(tok[0] == '?') {
			bytes[i].is_wildcard = 1;
		}
		else {
			bytes[i].is_wildcard = 0;
			bytes[i].byte = strtol(tok, NULL, 16); 
		}
		
		tok = strtok(NULL, " ");
		i += 1;
	}

	free(sig_cpy);

	return bytes;
}

static int setup_proc_files(int pid)
{
	int ret = snprintf(pmem_file, ARR_SIZE(pmem_file), "/proc/%d/mem", pid);
	if(ret <= 0 || (size_t)ret >= ARR_SIZE(pmem_file))
		return -1;

	ret = snprintf(pmap_file, ARR_SIZE(pmap_file), "/proc/%d/maps", pid);
	if(ret <= 0 || (size_t)ret >= ARR_SIZE(pmem_file))
		return -1;

	return 0;
}


static int attatch(int pid)
{
	long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if(ret == -1)
		return -1;

	int status;	
	if(waitpid(pid, &status, 0) == -1)
		return -1;

	if(WIFSTOPPED(status) == 0)
		return -1;

	return 0;	
}


static int detatch(int pid)
{
	long ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if(ret == -1)
		return -1;

	return 0;
}


static int get_map_entry(struct map_entry *out, const char *fname)
{
	char entry[1024];
	char perms[5];
	static FILE *f = NULL;

	if(fname != NULL) {
		if(f != NULL)
			fclose(f);

		f = fopen(pmap_file, "r");
		if(f == NULL)
			goto err_out;
	}
	
	/* end of file reached */
	if(feof(f) != 0 || fgets(entry, ARR_SIZE(entry), f) == NULL) {
		clearerr(f);
		fclose(f);
		return 1;
	}

	if(ferror(f) != 0) {
		clearerr(f);
		goto err_out;
	}

	int ret = sscanf(entry, "%lx-%lx %s", &out->start, &out->end, perms);
	if(ret != 3)
		goto err_out;
	
	out->r = perms[0] == 'r' ? 1 : 0;
	out->w = perms[1] == 'w' ? 1 : 0;
	out->x = perms[2] == 'x' ? 1 : 0;
	out->is_searchable = 1;
	if(strstr(entry, "[") != NULL)
		out->is_searchable = 0;


	/* still more in file */
	return 0;

err_out:
	/* error */
	fclose(f);
	return -1;
}
