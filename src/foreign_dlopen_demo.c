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
void init_exec_elf(char *argv[]);
void exec_elf(const char *file, int argc, char *argv[]);

#define DL_APP_DEFAULT "/bin/sleep"

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	const char *app;
	if (argc > 1 && argv[1] && argv[1][0]) {
		app = argv[1];
	} else {
		app = DL_APP_DEFAULT;
	}

	char *targv[] = { (char *)app, (char *)"x" };
	exec_elf(app, 2, targv);

	z_exit(0);
}
