
#define RARELY(x) (__builtin_expect_with_probability((x), 0, 0.9))

#define ASSERT(x)                                                                                              \
	do {                                                                                                   \
		if (!(x)) {                                                                                    \
			__builtin_unreachable();                                                               \
		}                                                                                              \
	} while (0)

#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long
#define int64_t long

#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define Elf_auxv_t Elf64_auxv_t

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;

#define EI_NIDENT (16)

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
	Elf64_Sxword d_tag; /* Dynamic entry type */
	union {
		Elf64_Xword d_val; /* Integer value */
		Elf64_Addr d_ptr;  /* Address value */
	} d_un;
} Elf64_Dyn;

typedef uint16_t Elf64_Section;

typedef struct {
	Elf64_Word st_name;	/* Symbol name (string tbl index) */
	unsigned char st_info;	/* Symbol type and binding */
	unsigned char st_other; /* Symbol visibility */
	Elf64_Section st_shndx; /* Section index */
	Elf64_Addr st_value;	/* Symbol value */
	Elf64_Xword st_size;	/* Symbol size */
} Elf64_Sym;

/* In-memory ELF helpers */
typedef struct {
	Elf_Ehdr *eh;
	Elf_Phdr *ph;
	Elf_Dyn *dyn;
	unsigned long base;
	unsigned long nbucket, nchain;
	uint32_t *buckets, *chains;
	uint32_t *gnu_buckets;
	uint32_t *gnu_chain;
	uint32_t gnu_maskwords;
	uint32_t gnu_shift2;
	unsigned long *gnu_bloom;
	uint32_t gnu_nbucket;
	uint32_t gnu_symoffset;
	Elf_Sym *dynsym;
	const char *dynstr;
	uint16_t *versym;
} mod_t;

static long find_libc_base(void);
static int mod_init(mod_t *m, unsigned long base);

typedef union unn_syscall_result_ {
	long l;
	unsigned long ul;
	void *p;
} unn_syscall_result;

#define NULL ((void *)0)

#define INT_MAX 0x7fffFFFF
#define SYS_READ 0x00

static void syscall3(unsigned long a1, unsigned long a2, unsigned long a3, unsigned long n,
		     unn_syscall_result *res)
{
	asm volatile("syscall" : "=a"(*res) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
}

#define OFTEN(x) (__builtin_expect_with_probability((x), 1, 0.9))

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

/* Minimal readers */
static int read_all(int fd, char *buf, int sz)
{
	int off;
	int n;
	long tmpres;

	off = 0;
	while (1) {
		if (off >= sz) {
			break;
		}

		if (0 > sys_read(fd, buf + off, sz - off, &tmpres)) {
			break;
		}

		if (tmpres <= 0) {
			break;
		}

		n = tmpres;
		off += n;
	}

	return off;
}

static int gl_cached = 0;
static unsigned long text_base = 0;
static const char *gl_cached_name = NULL;
static unsigned long gl_cached_base = 0;
static const char *soname = NULL;

#define LONG_MAX 0x7fffFFFFffffFFFF
#define ULONG_MAX 0xffffFFFFffffFFFFu
#define AT_FDCWD (-100)
#define SYS_OPENAT 0x101

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

static void syscall1(unsigned long a1, unsigned long n, unn_syscall_result *res)
{
	asm volatile("syscall" : "=a"(*res) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
}

#define SYS_CLOSE 0x03

static long sys_close(long fd)
{
	unn_syscall_result rax;

	ASSERT(fd >= 0);
	ASSERT(fd <= INT_MAX);
#if defined(STDIO_DESCRIPTOR_NO_HACKING)
	ASSERT(fd != STDIN_FILENO);
	ASSERT(fd != STDOUT_FILENO);
	ASSERT(fd != STDERR_FILENO);
#endif

	syscall1((unsigned long)(long)fd, SYS_CLOSE, &rax);
	if (RARELY(rax.l < 0 && rax.l > -0x1000)) {
		return rax.l;
	}

#if defined(KERNEL_MITIGATION_ERRNO)
	if (RARELY(rax.l != 0)) {
		return -KERNEL_MITIGATION_ERRNO;
	}
#endif

	ASSERT(rax.l == 0);
	return rax.l;
}

#define MAPS_PATH "/proc/self/maps"
#define O_RDONLY 0x0

static char *z_strstr(const char *h, const char *n)
{
	if (!*n)
		return (char *)h;
	for (; *h; h++) {
		const char *p = h, *q = n;
		while (*p && *q && *p == *q) {
			p++;
			q++;
		}
		if (!*q)
			return (char *)h;
	}
	return NULL;
}

/* parse one /proc/self/maps line; returns 0 on success */
static int parse_maps_line(const char *line, unsigned long *start, char *perms_out, unsigned long *offset,
			   const char **path_out)
{
	const char *p;
	unsigned long v;
	int i;

	p = line;
	v = 0;

	/* start */
	v = 0;
	for (; *p >= '0' && *p <= '9' || *p >= 'a' && *p <= 'f' || *p >= 'A' && *p <= 'F'; p++)
		v = v << 4 | (unsigned long)(*p <= '9' ? *p - '0' : *p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A');
	if (RARELY(*p != '-'))
		return -1;
	*start = v;
	p++;

	/* end (skip) */
	for (; *p >= '0' && *p <= '9' || *p >= 'a' && *p <= 'f' || *p >= 'A' && *p <= 'F'; p++)
		;
	while (*p == ' ')
		p++;

	/* perms (4 chars) */
	for (i = 0; i < 4; i++) {
		if (RARELY(!p[i]))
			return -1;
		perms_out[i] = p[i];
	}
	perms_out[4] = 0;
	p += 4;
	while (*p == ' ')
		p++;

	/* offset */
	v = 0;
	for (; *p >= '0' && *p <= '9' || *p >= 'a' && *p <= 'f' || *p >= 'A' && *p <= 'F'; p++)
		v = v << 4 | (unsigned long)(*p <= '9' ? *p - '0' : *p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A');
	*offset = v;

	/* skip dev */
	while (*p && *p != ' ')
		p++;
	while (*p == ' ')
		p++;
	/* skip inode */
	while (*p && *p != ' ')
		p++;
	while (*p == ' ')
		p++;

	/* path (may be empty) */
	*path_out = *p != '\0' ? p : NULL;
	return 0;
}

/* Parse /proc/self/maps to find libc mapping with offset 0 */
static long find_libc_base(void)
{
	long res;

	if (gl_cached) {
		text_base = gl_cached_base;
		soname = gl_cached_name;
		return 0;
	}

	int fd;
	if (0 > (res = sys_openat(AT_FDCWD, MAPS_PATH, O_RDONLY, &fd))) {
		return res;
	}

	char buf[65536];
	int n = read_all(fd, buf, sizeof(buf) - 1);
	(void)sys_close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	char *p = buf;
	while (*p) {
		char *line = p;
		while (*p && *p != '\n')
			p++;
		char save = *p;
		*p = 0;

		unsigned long start = 0, off = 0;
		char perms[5];
		const char *path = NULL;
		if (z_strstr(line, "libc")) {
			if (parse_maps_line(line, &start, perms, &off, &path) == 0 && path && off == 0) {
				text_base = start;
				soname = path;
				gl_cached = 1;
				gl_cached_base = text_base;
				gl_cached_name = soname;
				*p = save;
				return 0;
			}
		}

		*p = save;
		if (*p)
			p++;
	}
	return -1;
}

/* helper: turn a DT_* pointer/offset into an absolute VA */
static void *dyn_ptr(unsigned long base, unsigned long lo, unsigned long hi, unsigned long p)
{
	unn_syscall_result vp;

	vp.ul = p;
	/* if it's not already inside this module's mapped range, treat as offset */
	if (vp.ul < lo || vp.ul >= hi)
		vp.ul += base;
	return vp.p;
}

#define PT_LOAD 1 /* Loadable program segment */
#define DT_NULL 0	       /* Marks end of dynamic section */
#define PT_DYNAMIC 2	       /* Dynamic linking information */
#define DT_STRTAB 5	       /* Address of string table */
#define DT_SYMTAB 6	       /* Address of symbol table */
#define DT_HASH 4	       /* Address of symbol hash table */
#define DT_GNU_HASH 0x6ffffef5 /* GNU-style hash table.  */

/* The versioning entry types.  The next are defined as part of the
   GNU extension.  */
#define DT_VERSYM 0x6ffffff0

static int mod_init(mod_t *m, unsigned long base)
{
	m->base = base;
	m->eh = (Elf_Ehdr *)base;
	if (RARELY(m->eh->e_ident[0] != 0x7f || m->eh->e_ident[1] != 'E' || m->eh->e_ident[2] != 'L' ||
		   m->eh->e_ident[3] != 'F'))
		return -1;

	m->ph = (Elf_Phdr *)(base + m->eh->e_phoff);

	unsigned long lo = ~0UL, hi = 0;
	for (int i = 0; i < m->eh->e_phnum; i++) {
		Elf_Phdr *ph = &m->ph[i];
		if (ph->p_type == PT_LOAD) {
			unsigned long seg_lo = base + ph->p_vaddr;
			unsigned long seg_hi = seg_lo + ph->p_memsz;
			if (seg_lo < lo)
				lo = seg_lo;
			if (seg_hi > hi)
				hi = seg_hi;
		}
	}

	m->dyn = NULL;
	for (int i = 0; i < m->eh->e_phnum; i++) {
		if (m->ph[i].p_type == PT_DYNAMIC) {
			unsigned long dyn_addr = base + m->ph[i].p_vaddr;
			if (dyn_addr < lo || dyn_addr + sizeof(Elf_Dyn) > hi) {
				return -1;
			}
			m->dyn = (Elf_Dyn *)dyn_addr;
			break;
		}
	}
	if (RARELY(!m->dyn)) {
		return -1;
	}

	for (Elf_Dyn *d = m->dyn; d->d_tag != DT_NULL; d++) {
		switch (d->d_tag) {
		case DT_STRTAB:
			m->dynstr = (const char *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
			break;
		case DT_SYMTAB:
			m->dynsym = (Elf_Sym *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
			break;
		case DT_HASH: {
			uint32_t *h = (uint32_t *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
			m->nbucket = h[0];
			m->nchain = h[1];
			m->buckets = h + 2;
			m->chains = h + 2 + m->nbucket;
			break;
		}
		case DT_GNU_HASH: {
			uint32_t *gh = (uint32_t *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
			m->gnu_nbucket = gh[0];
			m->gnu_symoffset = gh[1];
			m->gnu_maskwords = gh[2];
			m->gnu_shift2 = gh[3];
			m->gnu_bloom = (unsigned long *)(gh + 4);
			m->gnu_buckets = (uint32_t *)(m->gnu_bloom + m->gnu_maskwords);
			m->gnu_chain = (uint32_t *)(m->gnu_buckets + m->gnu_nbucket);
			break;
		}
		case DT_VERSYM:
			m->versym = (uint16_t *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
			break;
		default:
			break;
		}
	}

	return m->dynsym && m->dynstr ? 0 : -1;
}

#define size_t unsigned long

static void *z_memset(void *s, int c, size_t n)
{
	unsigned char *p = s, *e = p + n;
	while (p < e)
		*p++ = c;
	return s;
}

static uint32_t gnu_hash_str(const char *s)
{
	uint32_t h = 5381;
	for (unsigned char c; (c = *s++) != 0;)
		h = (h * 33) + c;
	return h;
}

static uint32_t u32_mod(uint32_t a, uint32_t m)
{
	if (m == 0) {
		return 0;
	}
	return a % m;
}

static int z_strcmp(const char *a, const char *b)
{
	while (*a && (*a == *b)) {
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}

/* GNU hash lookup */
static Elf_Sym *lookup_gnu(mod_t *restrict m, const char *restrict name)
{
	if (!m->gnu_buckets)
		return NULL;
	uint32_t h = gnu_hash_str(name);
	size_t bloom_idx = (h / (sizeof(unsigned long) * 8)) & (m->gnu_maskwords - 1);
	unsigned long bitmask = (1UL << (h % (sizeof(unsigned long) * 8))) |
				(1UL << ((h >> m->gnu_shift2) % (sizeof(unsigned long) * 8)));
	if ((m->gnu_bloom[bloom_idx] & bitmask) != bitmask)
		return NULL;

	uint32_t idx = m->gnu_buckets[u32_mod(h, m->gnu_nbucket)];
	if (!idx)
		return NULL;
	for (;;) {
		uint32_t hv = m->gnu_chain[idx - m->gnu_symoffset];
		if ((hv | 1U) == (h | 1U)) {
			Elf_Sym *sym = &m->dynsym[idx];
			if (sym->st_name && !z_strcmp(m->dynstr + sym->st_name, name))
				return sym;
		}
		if (hv & 1U)
			break;
		idx++;
	}
	return NULL;
}

static uint32_t sysv_hash(const char *s)
{
	uint32_t h;
	uint32_t g;

	h = 0;
	while (*s) {
		h = (h << 4) + (unsigned char)*s++;
		g = h & 0xF0000000U;
		if (g)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

/* SysV hash lookup */
static Elf_Sym *lookup_sysv(mod_t *restrict m, const char *restrict name)
{
	if (!m->buckets)
		return NULL;
	uint32_t h = sysv_hash(name);
	for (uint32_t i = m->buckets[u32_mod(h, m->nbucket)]; i != 0; i = m->chains[i]) {
		Elf_Sym *sym = &m->dynsym[i];
		if (sym->st_name && !z_strcmp(m->dynstr + sym->st_name, name))
			return sym;
	}
	return NULL;
}

#define ELF_ST_TYPE(i) ((i) & 0xF)
#define STT_FUNC 2 /* Symbol is a code object */
#define STT_GNU_IFUNC 10 /* Symbol is indirect code object */
#define RTLD_NOW 0x0002
#define SYS_EXIT 0x3c

static void *resolve_sym(mod_t *restrict m, const char *restrict name)
{
	Elf_Sym *s = NULL;

	if (!s) {
		s = lookup_gnu(m, name);
	}
	if (!s) {
		s = lookup_sysv(m, name);
	}
	if (RARELY(!s)) {
		return NULL;
	}
	if (RARELY(ELF_ST_TYPE(s->st_info) != STT_FUNC && ELF_ST_TYPE(s->st_info) != STT_GNU_IFUNC)) {
		return NULL;
	}
	return (void *)(m->base + s->st_value);
}

static void sys_exit(int status)
{
	unn_syscall_result rax;
	syscall1((long)status, SYS_EXIT, &rax);
	(void)rax;
}

double (*my_fabs)(double) = NULL;
double (*my_fmod)(double) = NULL;
double (*my_exp)(double) = NULL;
double (*my_log)(double) = NULL;
double (*my_log10)(double) = NULL;
double (*my_pow)(double, double) = NULL;
double (*my_sqrt)(double) = NULL;
double (*my_sin)(double) = NULL;
double (*my_cos)(double) = NULL;
double (*my_tan)(double) = NULL;
double (*my_asin)(double) = NULL;
double (*my_acos)(double) = NULL;
double (*my_atan)(double) = NULL;
double (*my_atan2)(double, double) = NULL;
double (*my_sinh)(double) = NULL;
double (*my_cosh)(double) = NULL;
double (*my_tanh)(double) = NULL;
double (*my_ceil)(double) = NULL;
double (*my_floor)(double) = NULL;
double (*my_frexp)(double) = NULL;
double (*my_ldexp)(double) = NULL;
double (*my_modf)(double) = NULL;

void *my_pthread_atfork = NULL;
void *my_pthread_attr_init = NULL;
void *my_pthread_attr_destroy = NULL;
void *my_pthread_cancel = NULL;
void *my_pthread_cleanup_push = NULL;
void *my_pthread_cleanup_pop = NULL;
void *my_pthread_cond_init = NULL;
void *my_pthread_cond_signal = NULL;
void *my_pthread_cond_broadcast = NULL;
void *my_pthread_cond_wait = NULL;
void *my_pthread_cond_timedwait = NULL;
void *my_pthread_cond_destroy = NULL;
void *my_pthread_create = NULL;
void *my_pthread_detach = NULL;
void *my_pthread_equal = NULL;
void *my_pthread_exit = NULL;
void *my_pthread_key_create = NULL;
void *my_pthread_key_delete = NULL;
void *my_pthread_setspecific = NULL;
void *my_pthread_getspecific = NULL;
void *my_pthread_kill = NULL;
void *my_pthread_mutex_lock = NULL;
void *my_pthread_mutex_unlock = NULL;
void *my_pthread_mutex_trylock = NULL;
void *my_pthread_mutex_init = NULL;
void *my_pthread_mutex_destroy = NULL;
void *my_pthread_mutexattr_destroy = NULL;
void *my_pthread_mutexattr_init = NULL;
void *my_pthread_join = NULL;

void *(*my_dlopen)(const char *, int) = NULL;
void *(*my_dlsym)(void *restrict, const char *restrict) = NULL;
int (*my_dlclose)(void *) = NULL;

extern unsigned long g_interp_base;

#include "my_dlfcn.h"

/* example */

struct worker_str {
	void *printff;
	void *sleepf;
};

static void *worker(void *foo)
{
	struct worker_str *ffd;
	ffd = foo;

	(*(int (*)(const char *, ...))ffd->printff)("One\n");
	(*(int (*)(unsigned int))ffd->sleepf)(1000000);
	(*(int (*)(const char *, ...))ffd->printff)("Two\n");
	(*(int (*)(unsigned int))ffd->sleepf)(1000000);
	(*(int (*)(const char *, ...))ffd->printff)("Three\n");

	return NULL;
}

/* MUST ensure that stack is 16 byte aligned for calls to external functions */
/* especially ones with variadic arguments. We do this via the z_fdlentry.S wrapper */
extern void fdl_entry_impl(void)
{
	void *c;
	void *m;
	void *p;

	void *tmp_dlopen;
	void *tmp_dlsym;
	void *tmp_dlclose;

	int (*my_printf)(const char *restrict, ...);
	float (*my_sinf)(float);
	void *sleepf;
	void *pth_create;
	void *pth_join;

	unsigned long tid1;
	unsigned long tid2;
	struct worker_str ws1;
	struct worker_str ws2;
	void *dummy;
	int exit_status;

	mod_t M;

	exit_status = 0;

	if (0 > find_libc_base()) {
		if (g_interp_base != 0) {
			text_base = g_interp_base;
		} else {
			goto l_exit_failure;
		}
	}

	z_memset(&M, 0, sizeof M);
	if (RARELY(mod_init(&M, text_base) < 0))
		goto l_exit_failure;

	/* glibc: prefer __libc_dlopen_mode; fallback to dlopen/dlsym */

	tmp_dlopen = resolve_sym(&M, "__libc_dlopen_mode");
	if (!tmp_dlopen) {
		tmp_dlopen = resolve_sym(&M, "dlopen");
	}

	tmp_dlsym = resolve_sym(&M, "dlsym");
	tmp_dlclose = resolve_sym(&M, "dlclose");

	if (!tmp_dlopen || !tmp_dlsym || !tmp_dlclose) {
		goto l_exit_failure;
	}

	my_dlopen = tmp_dlopen;
	my_dlsym = tmp_dlsym;
	my_dlclose = tmp_dlclose;

	/* my_dlfcn.h */

	c = dlopen(NULL, RTLD_NOW);
	my_printf = dlsym(c, "printf");

	m = dlopen("libm.so.6", RTLD_NOW);
	if (RARELY(m == NULL)) {
		goto l_exit_failure;
	}

	my_sinf = dlsym(m, "sinf");
	if (RARELY(my_sinf == NULL)) {
		goto l_exit_failure;
	}

	if (RARELY(my_printf == NULL)) {
		goto l_exit_failure;
	}

	(*my_printf)("sine of 3.14/3 is %f\n", (*my_sinf)(3.14 / 3));

	p = dlopen("libpthread.so.0", RTLD_NOW);
	if (p == NULL) {
		goto l_exit_failure;
	}

	sleepf = dlsym(c, "usleep");
	if (sleepf == NULL) {
		goto l_exit_failure;
	}

	pth_create = dlsym(p, "pthread_create");
	if (!pth_create) {
		goto l_exit_failure;
	}

	pth_join = dlsym(p, "pthread_join");
	if (!pth_join) {
		goto l_exit_failure;
	}

	ws1.printff = ws2.printff = my_printf;
	ws1.sleepf = ws2.sleepf = sleepf;

	if (0 != (*(int (*)(unsigned long *, const void *, void *(*)(void *), void *))pth_create)(
		     &tid1, NULL, worker, &ws1)) {
		goto l_exit_failure;
	}

	if (0 != (*(int (*)(unsigned long *, const void *, void *(*)(void *), void *))pth_create)(
		     &tid2, NULL, worker, &ws2)) {
		goto l_exit_failure;
	}

	if (0 != (*(int (*)(unsigned long, void **))pth_join)(tid1, &dummy)) {
		goto l_exit_failure;
	}

	if (0 != (*(int (*)(unsigned long, void **))pth_join)(tid2, &dummy)) {
		goto l_exit_failure;
	}

	(void)dlclose(p);
	(void)dlclose(m);
	(void)dlclose(c);

l_exit:
	sys_exit(exit_status);

l_exit_failure:
	exit_status = 1;
	goto l_exit;
}

