
#include <stdarg.h>

void z_exit(int status);
void z_vfdprintf(int fd, const char *fmt, va_list ap);
void z_fdprintf(int fd, const char *fmt, ...)
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

