
#include "nolibc.h"

// // Use these to test the real libc.
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/mman.h>

static void test_mmap(void)
{
	const size_t len = 1024;
	void *p;

	p = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
		 -1, 0);
	if (!p) {
		puts("mmap() error");
		return;
	}

	munmap(p, len);
}

static void test_malloc(void)
{
	void *ptr, *tmp;
	const size_t len1 = 4096;
	const size_t len2 = 8192;

	ptr = malloc(len1);
	if (!ptr) {
		puts("malloc() error");
		return;
	}
	memset(ptr, 'a', len1);

	tmp = realloc(ptr, len2);
	if (!tmp) {
		free(ptr);
		puts("realloc() error");
		return;
	}
	ptr = tmp;
	memset(ptr, 'b', len2);
	free(ptr);
}

static void test_calloc(void)
{
	void *ptr, *tmp;
	const size_t len1 = 4096;
	const size_t len2 = 8192;

	ptr = calloc(sizeof(char), len1);
	if (!ptr) {
		puts("malloc() error");
		return;
	}
	memset(ptr, 'a', len1);

	tmp = realloc(ptr, len2);
	if (!tmp) {
		free(ptr);
		puts("realloc() error");
		return;
	}
	ptr = tmp;
	memset(ptr, 'b', len2);
	free(ptr);
}

static void test_realloc(void)
{
	char *ptr;
	struct nolibc_heap *heap;
	size_t user_p_len;
	int i;

	const size_t len1 = 4096;
	const size_t len2 = 8192;

	/* imitate malloc to add out-of-bounds padding */
	heap = mmap(NULL, len2, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
		 -1, 0);
	if (!heap) {
		puts("mmap() error");
		return;
	}

	memset(heap, 'b', len2);

	heap->len = len1;
	user_p_len = heap->len - sizeof(*heap);
	ptr = heap->user_p;

	memset(ptr, 'a', user_p_len);

	/* this should only copy 'a' values */
	ptr = realloc(ptr, len2);
	if (!ptr) {
		munmap(heap, len2);
		puts("realloc() error");
		return;
	}

	/* unmap the memory realloc didn't */
	munmap(heap + len1, len1);

	/* if we copied any 'b' values, we went too far */
	user_p_len = len2 - sizeof(*heap);
	for (i = 0; i < user_p_len; i++) {
		if (ptr[i] == 'b') {
			free(ptr);
			puts("realloc() error");
			return;
		}
	}
	free(ptr);
}
static void test_string_heap(void)
{
	static const char str[] = "Hello World!";
	char *x;

	x = strdup(str);
	if (memcmp(x, str, sizeof(str))) {
		printf("Wrong strdup()!\n");
		return;
	}
	free(x);

	x = strndup(str, 5);
	if (memcmp(x, str, 4) || x[5] != '\0') {
		printf("Wrong strndup()!\n");
		return;
	}
	free(x);
}

int main(void)
{
	test_mmap();
	test_malloc();
	test_calloc();
	test_string_heap();
	test_realloc();
}
