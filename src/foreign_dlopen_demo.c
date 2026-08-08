#define EI_NIDENT (16)

#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long

#define SYS_EXIT 0x3c
#define SYS_READ 0x00
#define SYS_OPENAT 0x101
#define SYS_LSEEK 0x08
#define SYS_MPROTECT 0xa
#define SYS_MUNMAP 0x0b
#define SYS_MMAP 0x09

#define LOAD_ERR ((unsigned long)-1)
#define z_alloca __builtin_alloca
#define Z_PROG 0
#define PRIVATE __attribute__((visibility("hidden")))
#define Z_INTERP 1

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_NONE 0x0
#define PROT_EXEC 0x4

#define PAGE_SIZE 4096
#define ALIGN (PAGE_SIZE - 1)
#define ROUND_PG(x) (((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x) ((x) & ~(ALIGN))
#define PFLAGS(x)                                                                                              \
	((((x) & PF_R) ? PROT_READ : 0) | (((x) & PF_W) ? PROT_WRITE : 0) | (((x) & PF_X) ? PROT_EXEC : 0))

#define ELFCLASS ELFCLASS64
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_auxv_t Elf64_auxv_t

#define AT_NULL 0    /* End of vector */
#define ET_DYN 3     /* Shared object file */
#define PT_INTERP 3  /* Program interpreter */
#define AT_PHDR 3    /* Program headers for program */
#define AT_PHNUM 5   /* Number of program headers */
#define AT_PHENT 4   /* Size of program header entry */
#define AT_ENTRY 9   /* Entry point of program */
#define AT_EXECFN 31 /* Filename of executable.  */
#define AT_BASE 7    /* Base address of interpreter */

#define EI_MAG0 0    /* File identification byte 0 index */
#define ELFMAG0 0x7f /* Magic number byte 0 */

#define EI_MAG1 1   /* File identification byte 1 index */
#define ELFMAG1 'E' /* Magic number byte 1 */

#define EI_MAG2 2   /* File identification byte 2 index */
#define ELFMAG2 'L' /* Magic number byte 2 */

#define EI_MAG3 3   /* File identification byte 3 index */
#define ELFMAG3 'F' /* Magic number byte 3 */

#define EI_VERSION 6 /* File version byte index */
		     /* Value must be EV_CURRENT */

#define EI_CLASS 4   /* File class byte index */
#define EV_CURRENT 1 /* Current version */

#define ELFCLASS64 2 /* 64-bit objects */
#define PT_LOAD 1    /* Loadable program segment */

#define ET_EXEC 2     /* Executable file */
#define PF_X (1 << 0) /* Segment is executable */
#define PF_W (1 << 1) /* Segment is writable */
#define PF_R (1 << 2) /* Segment is readable */

#define size_t unsigned long
#define ssize_t long
#define NULL ((void *)0)

#define LONG_MAX 0x7fffFFFFffffFFFF
#define ULONG_MAX 0xffffFFFFffffFFFFu
#define INT_MAX 0x7fffFFFF

#define MAP_FIXED 0x10
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

#define AT_FDCWD (-100)
#define SEEK_SET 0x0
#define O_RDONLY 0x0

#define ASSERT(x)                                                                                              \
	do {                                                                                                   \
		if (!(x)) {                                                                                    \
			__builtin_unreachable();                                                               \
		}                                                                                              \
	} while (0)

#define OFTEN(x) (__builtin_expect_with_probability((x), 1, 0.9))
#define RARELY(x) (__builtin_expect_with_probability((x), 0, 0.9))

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint64_t Elf64_Xword;

typedef struct {
	unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
	Elf64_Half e_type;		  /* Object file type */
	Elf64_Half e_machine;		  /* Architecture */
	Elf64_Word e_version;		  /* Object file version */
	Elf64_Addr e_entry;		  /* Entry point virtual address */
	Elf64_Off e_phoff;		  /* Program header table file offset */
	Elf64_Off e_shoff;		  /* Section header table file offset */
	Elf64_Word e_flags;		  /* Processor-specific flags */
	Elf64_Half e_ehsize;		  /* ELF header size in bytes */
	Elf64_Half e_phentsize;		  /* Program header table entry size */
	Elf64_Half e_phnum;		  /* Program header table entry count */
	Elf64_Half e_shentsize;		  /* Section header table entry size */
	Elf64_Half e_shnum;		  /* Section header table entry count */
	Elf64_Half e_shstrndx;		  /* Section header string table index */
} Elf64_Ehdr;

typedef struct {
	Elf64_Word p_type;    /* Segment type */
	Elf64_Word p_flags;   /* Segment flags */
	Elf64_Off p_offset;   /* Segment file offset */
	Elf64_Addr p_vaddr;   /* Segment virtual address */
	Elf64_Addr p_paddr;   /* Segment physical address */
	Elf64_Xword p_filesz; /* Segment size in file */
	Elf64_Xword p_memsz;  /* Segment size in memory */
	Elf64_Xword p_align;  /* Segment alignment */
} Elf64_Phdr;

typedef struct {
	uint64_t a_type; /* Entry type */
	union {
		uint64_t a_val; /* Integer value */
				/* We use to have pointer elements added here.  We cannot do that,
				   though, since it does not work when using 32-bit definitions
				   on 64-bit platforms and vice versa.  */
	} a_un;
} Elf64_auxv_t;

unsigned long g_interp_base = 0;

static unsigned long *entry_sp =
    NULL;		     /* Original sp (i.e. pointer to executable params) passed to entry, if any. */
static void (*x_fini)(void); /* External fini function that the caller can provide us. */

static void sys_exit(int status);
static long sys_openat(long dirfd, const void *restrict pathname, long flags, int *restrict result);
static long sys_read(long fd, void *restrict buf, unsigned long nbytes, long *restrict result);
static long sys_lseek(long fd, long offset, long whence, long *result);
static long sys_mmap(void *restrict addr, unsigned long length, long prot, long flags, long fd, long offset,
		     void **restrict result);
static long sys_munmap(void *addr, unsigned long length);
static long sys_mprotect(void *addr, size_t len, int prot);

static void *z_memcpy(void *dest, const void *src, size_t n);

__attribute__((always_inline)) static void exec_elf(const char *file, int argc, char **argv);

int main(int argc, char **argv)
{
	char *targv[2];
	char *app;

	if (argc > 1 && argv[1] != NULL && argv[1][0] != '\0') {
		app = argv[1];
	} else {
		app = "/bin/sleep";
	}

	targv[0] = app;
	targv[1] = "x";

	exec_elf(app, sizeof targv / sizeof *targv, targv);
	sys_exit(0);
}

static int check_ehdr(Elf_Ehdr *ehdr);
static unsigned long loadelf_anon(int fd, Elf_Ehdr *restrict ehdr, Elf_Phdr *restrict phdr);
static void z_fini(void);

PRIVATE void z_fdl_entry(void);
PRIVATE void z_trampo(void (*entry)(void), unsigned long *sp, void (*fini)(void));

typedef union unn_syscall_result_ {
	long l;
	unsigned long ul;
	void *p;
} unn_syscall_result;

__attribute__((always_inline)) static void exec_elf(const char *file, int argc, char **argv)
{
	Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
	Elf_Phdr *phdr, *iter;
	Elf_auxv_t *av;
	char **env, **p, *elf_interp = NULL;
	unsigned long *sp = entry_sp;
	unsigned long base[2], entry[2];
	ssize_t sz;
	int fd, i;
	long tmpres;

	{
		unsigned long *p = sp;
		/* argc */
		p++;
		/* argv */
		while (*p++ != 0)
			;

		unsigned long *from = p;
		/* env */
		while (*p++ != 0)
			;
		/* aux vector */
		while (*p++ != 0) {
			p++;
		}
		p++;

		unsigned long argv_sz = argc * sizeof(*p);
		unsigned sz = (char *)p - (char *)from;
		p = __builtin_alloca(sizeof(*p) + argv_sz + sz); /* alloca */
		*p = argc;
		z_memcpy(p + 1, argv, argv_sz);
		z_memcpy((char *)(p + 1) + argv_sz, from, sz);
		sp = p;
		argv = (char **)sp + 1;
	}

	env = p = (char **)&argv[argc + 1];
	while (*p++ != NULL)
		;
	av = (void *)p;

	(void)env;

	for (i = 0;; i++, ehdr++) {
		/* Open file, read and than check ELF header.*/
		if (RARELY(0 > sys_openat(AT_FDCWD, file, O_RDONLY, &fd))) {
			goto l_exit_failure;
		}

		if (RARELY(0 > sys_read(fd, ehdr, sizeof *ehdr, &tmpres) || tmpres != sizeof *ehdr)) {
			goto l_exit_failure;
		}

		if (RARELY(!check_ehdr(ehdr)))
			goto l_exit_failure;

		/* Read the program header. */
		sz = ehdr->e_phnum * sizeof(Elf_Phdr);
		phdr = z_alloca(sz);

		if (RARELY(0 > sys_lseek(fd, ehdr->e_phoff, SEEK_SET, NULL))) {
			goto l_exit_failure;
		}

		if (RARELY(0 > sys_read(fd, phdr, sz, &tmpres) || tmpres != sz)) {
			goto l_exit_failure;
		}

		/* Time to load ELF. */
		if (RARELY((base[i] = loadelf_anon(fd, ehdr, phdr)) == LOAD_ERR))
			goto l_exit_failure;

		/* Set the entry point, if the file is dynamic than add bias. */
		entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
		/* The second round, we've loaded ELF interp. */
		if (file == elf_interp)
			break;
		for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
			if (iter->p_type != PT_INTERP)
				continue;
			elf_interp = z_alloca(iter->p_filesz);

			if (RARELY(0 > sys_lseek(fd, iter->p_offset, SEEK_SET, NULL))) {
				goto l_exit_failure;
			}

			if (RARELY(0 > sys_read(fd, elf_interp, iter->p_filesz, &tmpres) ||
				   tmpres != (ssize_t)iter->p_filesz)) {
				goto l_exit_failure;
			}

			if (RARELY(elf_interp[iter->p_filesz - 1] != '\0'))
				goto l_exit_failure;
			// z_printf("elf_interp: %s\n", elf_interp);
			file = elf_interp;
		}
		/* Looks like the ELF is static -- leave the loop. */
		if (elf_interp == NULL)
			break;
	}

	/* Reassign some vectors that are important for
	 * the dynamic linker and for lib C. */
	while (av->a_type != AT_NULL) {
		switch (av->a_type) {
		case AT_PHDR:
			av->a_un.a_val = base[Z_PROG] + ehdrs[Z_PROG].e_phoff;
			break;
		case AT_PHNUM:
			av->a_un.a_val = ehdrs[Z_PROG].e_phnum;
			break;
		case AT_PHENT:
			av->a_un.a_val = ehdrs[Z_PROG].e_phentsize;
			break;
		case AT_ENTRY:
			av->a_un.a_val = (unsigned long)z_fdl_entry;
			break;
		case AT_EXECFN:
			av->a_un.a_val = (unsigned long)argv[1];
			break;
		case AT_BASE:
			av->a_un.a_val = elf_interp ? base[Z_INTERP] : av->a_un.a_val;
			break;
		}
		++av;
	}

	++av;

	if (elf_interp) {
		g_interp_base = base[Z_INTERP];
	}

	unn_syscall_result vp;
	vp.ul = elf_interp ? entry[Z_INTERP] : entry[Z_PROG];

	z_trampo(vp.p, sp, z_fini);

	__builtin_unreachable();

l_exit_failure:
	sys_exit(1);
}

static void z_fini(void)
{
	if (x_fini != NULL)
		(*x_fini)();
}

static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 || e_ident[EI_MAG2] != ELFMAG2 ||
		e_ident[EI_MAG3] != ELFMAG3 || e_ident[EI_CLASS] != ELFCLASS ||
		e_ident[EI_VERSION] != EV_CURRENT || (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
		   ? 0
		   : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr *restrict ehdr, Elf_Phdr *restrict phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;
	void *tmp;
	long tmpres;

	minva = (unsigned long)-1;
	maxva = 0;

	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	/* Check that we can hold the whole image. */
	if (RARELY(0 > sys_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0, &tmp))) {
		return -1;
	}
	base = tmp;
	(void)sys_munmap(base, maxva - minva);

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		if (RARELY(0 > sys_mmap((void *)start, sz, PROT_READ | PROT_WRITE, flags, -1, 0, &tmp))) {
			goto err;
		}
		p = tmp;

		if (RARELY(0 > sys_lseek(fd, iter->p_offset, SEEK_SET, NULL))) {
			goto err;
		}

		if (RARELY(0 > sys_read(fd, p + off, iter->p_filesz, &tmpres) ||
			   (unsigned long)tmpres != iter->p_filesz)) {
			goto err;
		}

		(void)sys_mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	(void)sys_munmap(base, maxva - minva);
	return LOAD_ERR;
}

void z_entry(unsigned long *restrict sp, void (*fini)(void))
{
	int argc;
	char **argv;

	entry_sp = sp;
	x_fini = fini;
	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	main(argc, argv);
}

static void syscall1(unsigned long a1, unsigned long n, unn_syscall_result *res)
{
	asm volatile("syscall" : "=a"(*res) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
}

static void syscall2(unsigned long a1, unsigned long a2, unsigned long n, unn_syscall_result *res)
{
	asm volatile("syscall" : "=a"(*res) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
}

static void syscall3(unsigned long a1, unsigned long a2, unsigned long a3, unsigned long n,
		     unn_syscall_result *res)
{
	asm volatile("syscall" : "=a"(*res) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
}

static void syscall6(unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5,
		     unsigned long a6, unsigned long n, unn_syscall_result *res)
{
	register unsigned long r10 asm("r10") = a4;
	register unsigned long r8 asm("r8") = a5;
	register unsigned long r9 asm("r9") = a6;
	asm volatile("syscall"
		     : "=a"(*res)
		     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
		     : "rcx", "r11", "memory");
}

static void sys_exit(int status)
{
	/* too long assembly because of 'int' */
	unn_syscall_result rax;
	syscall1((long)status, SYS_EXIT, &rax);
	(void)rax;
}

static long sys_mprotect(void *addr, size_t len, int prot)
{
	unn_syscall_result rax;

	syscall3((unsigned long)addr, len, (unsigned long)prot, SYS_MPROTECT, &rax);
	if (RARELY(rax.l < 0 && rax.l > -0x1000)) {
		return rax.l;
	}

#if defined(KERNEL_MITIGATION_ERRNO)
	if (RARELY(rax != 0)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#endif

	ASSERT(rax.l == 0);
	return rax.l;
}

static long sys_mmap(void *restrict addr, unsigned long length, long prot, long flags, long fd, long offset,
		     void **restrict result)
{
	unn_syscall_result rax;
	unsigned long offset_ul;
	unsigned long fd_ul;

	ASSERT(prot >= 0);
	ASSERT(flags >= 0);
	ASSERT(fd >= 0 || fd == -1);
	ASSERT(prot <= INT_MAX);
	ASSERT(flags <= INT_MAX);
	ASSERT(fd <= INT_MAX);

	if (offset < 0) {
		offset -= -LONG_MAX - 1;
		offset_ul = (unsigned long)offset;
		offset_ul -= -LONG_MAX - 1;
	} else {
		offset_ul = (unsigned long)offset;
	}

	if (fd == -1) {
		fd_ul = ULONG_MAX;
	} else {
		fd_ul = (unsigned long)fd;
	}

	/* 'offset' is changed */

	syscall6((unsigned long)addr, length, (unsigned long)(long)prot, (unsigned long)(long)flags, fd_ul,
		 offset_ul, SYS_MMAP, &rax);
	if (RARELY(rax.l < 0 && rax.l > -0x1000)) {
		return rax.l;
	}

#if defined(KERNEL_MITIGATION_ERRNO)
	if (RARELY(rax.l < 0)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#endif

	ASSERT(rax.l >= 0);

	if (OFTEN(result != NULL)) {
		*result = rax.p;
	}

	return rax.l;
}

static long sys_munmap(void *addr, unsigned long length)
{
	unn_syscall_result rax;

	syscall2((unsigned long)addr, length, SYS_MUNMAP, &rax);
	if (RARELY(rax.l < 0 && rax.l > -0x1000)) {
		return rax.l;
	}

#if defined(KERNEL_MITIGATION_ERRNO)
	if (RARELY(rax != 0)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#endif

	ASSERT(rax.l == 0);
	return rax.l;
}

static long sys_lseek(long fd, long offset, long whence, long *result)
{
	unn_syscall_result rax;

	ASSERT(fd >= 0);
	ASSERT(whence >= 0);
	ASSERT(fd <= INT_MAX);
	ASSERT(whence <= INT_MAX);

	syscall3((unsigned long)fd, (unsigned long)offset, (unsigned long)whence, SYS_LSEEK, &rax);
	if (RARELY(rax.l < 0 && rax.l > -0x1000)) {
		return rax.l;
	}

#if defined(KERNEL_MITIGATION_ERRNO)
	if (RARELY(rax <= -0x1000)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#endif

	ASSERT(rax.l >= 0);
	if (OFTEN(result != NULL)) {
		*result = rax.l;
	}
	return rax.l;
}

static long sys_read(long fd, void *restrict buf, unsigned long nbytes, long *restrict result)
{
	unn_syscall_result rax;

	ASSERT(buf != NULL);
	ASSERT(fd >= 0);
	ASSERT(fd <= INT_MAX);

#if defined(STDIO_DESCRIPTOR_NO_HACKING)
	ASSERT(fd != STDOUT_FILENO);
	ASSERT(fd != STDERR_FILENO);
#endif

	syscall3((unsigned long)(long)fd, (unsigned long)buf, nbytes, SYS_READ, &rax);
	if (RARELY(rax.l < 0 && rax.l > -0x1000)) {
		return rax.l;
	}

#if defined(KERNEL_MITIGATION_ERRNO)
	if (RARELY(rax < 0 || (unsigned long)rax > nbytes)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#endif

	ASSERT(rax.l >= 0);
	ASSERT((unsigned long)rax.l <= nbytes);

	if (OFTEN(result != NULL)) {
		*result = rax.l;
	}
	return rax.l;
}

static long sys_openat(long dirfd, const void *restrict pathname, long flags, int *restrict result)
{
	unn_syscall_result rax;
	unsigned long dirfd_ul;

	ASSERT(result != NULL);
	ASSERT(flags >= 0);
	ASSERT(dirfd == AT_FDCWD || dirfd >= 0);
	ASSERT(AT_FDCWD >= -LONG_MAX);
	ASSERT(AT_FDCWD < 0);
	ASSERT(dirfd <= INT_MAX);
	ASSERT(flags <= INT_MAX);

	if (dirfd == AT_FDCWD) {
		dirfd_ul = ULONG_MAX - (-AT_FDCWD) + 1;
	} else {
		dirfd_ul = (unsigned long)dirfd;
	}

	syscall3(dirfd_ul, (unsigned long)pathname, (unsigned long)(long)flags, SYS_OPENAT, &rax);
	if (RARELY(rax.l < 0 && rax.l > -0x1000)) {
		return rax.l;
	}

#if defined(KERNEL_MITIGATION_ERRNO)
	if (RARELY(rax > INT_MAX || rax <= -0x1000)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#if defined(STDIO_DESCRIPTOR_NO_HACKING)
	if (LESS_LIKELY(rax == STDOUT_FILENO || rax == STDERR_FILENO || rax == STDIN_FILENO)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#endif
#endif /* KERNEL_MITIGATION_ERRNO */

	ASSERT(rax.l <= INT_MAX);
	ASSERT(rax.l > -0x1000);
#if defined(STDIO_DESCRIPTOR_NO_HACKING)
	ASSERT(rax.l != STDOUT_FILENO);
	ASSERT(rax.l != STDERR_FILENO);
	ASSERT(rax.l != STDIN_FILENO);
#endif

	if (OFTEN(result != NULL)) {
		*result = (int)rax.l;
	}
	return rax.l;
}

static void *z_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *p = src, *e = p + n;
	while (p < e)
		*d++ = *p++;
	return dest;
}
