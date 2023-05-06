/*
 * Minimal libc prototypes and definitions
 *
 * This file is placed in the public domain or licensed under the CC0 if
 * that's not possible.
 */
#ifndef minilibc_h
#define minilibc_h
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

typedef ptrdiff_t ssize_t;

/* stdio.h */
typedef void FILE;
FILE *fopen(const char*, const char*);
int fprintf(FILE*, const char*, ...);
char* fgets(char*, int, FILE*);
void fclose(FILE*);
int puts(const char*);
void perror(const char*);

/* stdlib.h */
void* malloc(size_t);
void* aligned_alloc(size_t, size_t);
void* realloc(void*, size_t);
void free(void*);
void aligned_free(void*);
_Noreturn void abort();

/* string.h */
void* memcpy(void*, const void*, size_t);
void* memmove(void*, const void*, size_t);
void* memset(void*, int, size_t);
int memcmp(const void*, const void*, size_t);
void* memchr(const void*, int, size_t);
char* strchr(const char*, int);
int strcmp(const char*, const char*);
int strncmp(const char*, const char*, size_t);
size_t strlen(const char*);

/* assert.h */
#define assert(cond) \
    if (!(cond)) { \
        puts("assertion failed: " #cond " in " __FILE__); \
        abort(); \
    }

/* sys/random.h */
ssize_t getrandom(void*, size_t, unsigned int);

/* time.h */
int64_t mtime(int64_t*);
#endif
