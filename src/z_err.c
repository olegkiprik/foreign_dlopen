#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <unistd.h>

#define z_errno (*z_perrno())

void z_exit(int status);
int z_open(const char *pathname, int flags);
int z_close(int fd);
int z_lseek(int fd, off_t offset, int whence);
ssize_t z_read(int fd, void *buf, size_t count);
ssize_t z_write(int fd, const void *buf, size_t count);
void *z_mmap(void *addr, size_t length, int prot,
			 int flags, int fd, off_t offset);
int z_munmap(void *addr, size_t length);
int z_mprotect(void *addr, size_t length, int prot);
int *z_perrno(void);
#include <stdlib.h>
#include <stdarg.h>
#include <alloca.h>
#include <string.h>

#define z_alloca __builtin_alloca

void *z_memset(void *s, int c, size_t n);
void *z_memcpy(void *dest, const void *src, size_t n);
int z_strcmp(const char *a, const char *b);
char *z_strstr(const char *haystack, const char *needle);

void z_sprintn(char *buf, unsigned long ul, int base);

void z_vprintf(const char *fmt, va_list ap);
void z_vfdprintf(int fd, const char *fmt, va_list ap);
void z_printf(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void z_fdprintf(int fd, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void z_errx(int eval, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#ifdef Z_SMALL
#define z_errx(eval, fmt, ...) z_exit(eval)
#define z_printf(fmt, ...) \
	do                     \
	{                      \
	} while (0)
#define z_fdprintf(fd, fmt, ...) \
	do                           \
	{                            \
	} while (0)
#endif

void z_errx(int eval, const char *fmt, ...)
{
	va_list ap;
	z_fdprintf(2, "error: ");
	va_start(ap, fmt);
	z_vfdprintf(2, fmt, ap);
	va_end(ap);
	z_fdprintf(2, "\n");
	z_exit(eval);
}

