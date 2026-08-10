
#define FOREIGN_DLOPEN_STATIC
#include "my_dlfcn.h"
#include "my_math.h"
#include "my_pthread.h"
#undef MY_VISIBILITY

/* put single-header libraries here, without standard library #include */

/* custom macros */
#define asm __asm__
#define RARELY(x) (__builtin_expect_with_probability((x), 0, 0.9))
#define OFTEN(x) (__builtin_expect_with_probability((x), 1, 0.9))
#define ASSERT(x)                                                                                              \
	do {                                                                                                   \
		if (!(x)) {                                                                                    \
			__builtin_unreachable();                                                               \
		}                                                                                              \
	} while (0)

#if !defined(NULL)
#define NULL ((void *)0)
#endif

#if !defined(INT_MAX)
#define INT_MAX 0x7fffFFFF
#endif

#if !defined(RTLD_NOW)
#define RTLD_NOW 0x0002
#endif

#if !defined(O_RDONLY)
#define O_RDONLY 0x0
#endif

#if !defined(LONG_MAX)
#define LONG_MAX 0x7fffFFFFffffFFFF
#endif

#if !defined(ULONG_MAX)
#define ULONG_MAX 0xffffFFFFffffFFFFu
#endif

#if !defined(AT_FDCWD)
#define AT_FDCWD (-100)
#endif

typedef struct {
	unsigned char e_ident[16];  /* Magic number and other info */
	unsigned short e_type;	    /* Object file type */
	unsigned short e_machine;   /* Architecture */
	unsigned int e_version;	    /* Object file version */
	unsigned long e_entry;	    /* Entry point virtual address */
	unsigned long e_phoff;	    /* Program header table file offset */
	unsigned long e_shoff;	    /* Section header table file offset */
	unsigned int e_flags;	    /* Processor-specific flags */
	unsigned short e_ehsize;    /* ELF header size in bytes */
	unsigned short e_phentsize; /* Program header table entry size */
	unsigned short e_phnum;	    /* Program header table entry count */
	unsigned short e_shentsize; /* Section header table entry size */
	unsigned short e_shnum;	    /* Section header table entry count */
	unsigned short e_shstrndx;  /* Section header string table index */
} Elf64_Ehdr;

typedef struct {
	unsigned int p_type;	/* Segment type */
	unsigned int p_flags;	/* Segment flags */
	unsigned long p_offset; /* Segment file offset */
	unsigned long p_vaddr;	/* Segment virtual address */
	unsigned long p_paddr;	/* Segment physical address */
	unsigned long p_filesz; /* Segment size in file */
	unsigned long p_memsz;	/* Segment size in memory */
	unsigned long p_align;	/* Segment alignment */
} Elf64_Phdr;

typedef struct {
	long d_tag;		 /* Dynamic entry type */
	unsigned long d_ptr_val; /* Address or integer value */
} Elf64_Dyn;

typedef struct {
	unsigned int st_name;	 /* Symbol name (string tbl index) */
	unsigned char st_info;	 /* Symbol type and binding */
	unsigned char st_other;	 /* Symbol visibility */
	unsigned short st_shndx; /* Section index */
	unsigned long st_value;	 /* Symbol value */
	unsigned long st_size;	 /* Symbol size */
} Elf64_Sym;

/* In-memory ELF helpers */
typedef struct {
	Elf64_Ehdr *eh;
	Elf64_Phdr *ph;
	Elf64_Dyn *dyn;
	unsigned long base;
	unsigned long nbucket;
	unsigned long nchain;
	unsigned int *buckets;
	unsigned int *chains;
	unsigned int *gnu_buckets;
	unsigned int *gnu_chain;
	unsigned int gnu_maskwords;
	unsigned int gnu_shift2;
	unsigned int *gnu_bloom; /* unsigned long, but effective type is unsigned int */
	unsigned int gnu_nbucket;
	unsigned int gnu_symoffset;
	Elf64_Sym *dynsym;
	const char *dynstr;
	void *versym; /* unsigned short */
} mod_t;

typedef union unn_syscall_result_ {
	long l;
	unsigned long ul;
	void *p;
} unn_syscall_result;

static void syscall1(unsigned long a1, unsigned long n, unn_syscall_result *res)
{
	asm volatile("syscall" : "=a"(*res) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
}

static void syscall3(unsigned long a1, unsigned long a2, unsigned long a3, unsigned long n,
		     unn_syscall_result *res)
{
	asm volatile("syscall" : "=a"(*res) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
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

	syscall3((unsigned long)(long)fd, (unsigned long)buf, nbytes, 0x00, &rax);
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

	/* TODO: AArch64 */
	syscall3(dirfd_ul, (unsigned long)pathname, (unsigned long)(long)flags, 0x101, &rax);
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

	syscall1((unsigned long)(long)fd, 0x03, &rax);
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

static void sys_exit(int status)
{
	unn_syscall_result rax;
	syscall1((long)status, 0x3c, &rax);
	(void)rax;
}

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

		if (0 > sys_read(fd, buf + off, sz - off, &tmpres) || tmpres <= 0) {
			break;
		}

		n = tmpres;
		off += n;
	}

	return off;
}

static const char *z_strstr(const char *h, const char *n)
{
	const char *p;
	const char *q;

	if (*n == '\0') {
		return h;
	}
	for (; *h != '\0'; ++h) {
		p = h;
		q = n;
		while ((unsigned int)(*p != '\0') & (unsigned int)(*q != '\0') & (unsigned int)(*p == *q)) {
			++p;
			++q;
		}
		if (*q == '\0') {
			return h;
		}
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
	while ((unsigned int)(*p >= '0') & (unsigned int)(*p <= '9') |
	       (unsigned int)(*p >= 'a') & (unsigned int)(*p <= 'f') |
	       (unsigned int)(*p >= 'A') & (unsigned int)(*p <= 'F')) {
		v = v << 4 | (unsigned long)(*p <= '9' ? *p - '0' : *p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A');
		++p;
	}
	if (*p != '-') {
		return -1;
	}
	*start = v;
	++p;

	/* end (skip) */
	while ((unsigned int)(*p >= '0') & (unsigned int)(*p <= '9') |
	       (unsigned int)(*p >= 'a') & (unsigned int)(*p <= 'f') |
	       (unsigned int)(*p >= 'A') & (unsigned int)(*p <= 'F')) {
		++p;
	}
	while (*p == ' ') {
		++p;
	}

	/* perms (4 chars) */
	for (i = 0; i < 4; ++i) {
		if (p[i] == '\0') {
			return -1;
		}
		perms_out[i] = p[i];
	}

	perms_out[4] = 0;
	p += 4;
	while (*p == ' ') {
		++p;
	}

	/* offset */
	v = 0;
	while ((unsigned int)(*p >= '0') & (unsigned int)(*p <= '9') |
	       (unsigned int)(*p >= 'a') & (unsigned int)(*p <= 'f') |
	       (unsigned int)(*p >= 'A') & (unsigned int)(*p <= 'F')) {
		v = v << 4 | (unsigned long)(*p <= '9' ? *p - '0' : *p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A');
		++p;
	}
	*offset = v;

	/* skip dev */
	while ((unsigned int)(*p != '\0') & (unsigned int)(*p != ' ')) {
		++p;
	}
	while (*p == ' ') {
		++p;
	}

	/* skip inode */
	while ((unsigned int)(*p != '\0') & (unsigned int)(*p != ' ')) {
		++p;
	}
	while (*p == ' ') {
		++p;
	}

	/* path (may be empty) */
	*path_out = *p != '\0' ? p : NULL;
	return 0;
}

/* Parse /proc/self/maps to find libc mapping with offset 0 */
static long find_libc_base(int *restrict cached, void **restrict text_base, const char **restrict cached_name,
			   void **restrict cached_base, const char **restrict soname)
{
	long res;
	int fd;
	char buf[65536];
	int n;
	char *p;
	char *line;
	char save;
	unsigned long start;
	unsigned long off;
	char perms[5];
	const char *path;
	unn_syscall_result vp;

	if (*cached) {
		*text_base = *cached_base;
		*soname = *cached_name;
		return 0;
	}

	if (0 > (res = sys_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, &fd))) {
		return res;
	}

	n = read_all(fd, buf, sizeof buf - 1);
	(void)sys_close(fd);

	if (n <= 0) {
		return -1;
	}

	buf[n] = 0;
	p = buf;

	while (*p != '\0') {
		line = p;
		while ((unsigned int)(*p != '\0') & (unsigned int)(*p != '\n')) {
			++p;
		}
		save = *p;
		*p = 0;

		start = 0;
		off = 0;
		path = NULL;
		if (NULL != z_strstr(line, "libc")) {
			if (0 == parse_maps_line(line, &start, perms, &off, &path) &&
			    ((unsigned int)(path != NULL) & (unsigned int)(off == 0))) {
				vp.ul = start;
				*text_base = vp.p;
				*soname = path;
				*cached = 1;
				*cached_base = *text_base;
				*cached_name = *soname;
				*p = save;
				return 0;
			}
		}

		*p = save;
		if (*p != '\0') {
			++p;
		}
	}
	return -1;
}

/* helper: turn a DT_* pointer/offset into an absolute VA */
static void *dyn_ptr(void *base, unsigned long lo, unsigned long hi, unsigned long p)
{
	unn_syscall_result vp;

	vp.ul = p;
	/* if it's not already inside this module's mapped range, treat as offset */
	if ((unsigned int)(vp.ul < lo) | (unsigned int)(vp.ul >= hi)) {
		vp.ul += (unsigned long)base;
	}
	return vp.p;
}

#if defined(DT_STRTAB) || defined(DT_SYMTAB) || defined(DT_HASH) || defined(DT_GNU_HASH) || defined(DT_VERSYM)
#error "!"
#endif

#define DT_STRTAB 5	       /* Address of string table */
#define DT_SYMTAB 6	       /* Address of symbol table */
#define DT_HASH 4	       /* Address of symbol hash table */
#define DT_GNU_HASH 0x6ffffef5 /* GNU-style hash table.  */
#define DT_VERSYM                                                                                              \
	0x6ffffff0 /* The versioning entry types.  The next are defined as part of the GNU extension.  */

static int mod_init(mod_t *restrict m, void *restrict base)
{
	const unsigned long dt_NULL = 0;    /* Marks end of dynamic section */
	const unsigned long pt_LOAD = 1;    /* Loadable program segment */
	const unsigned long pt_DYNAMIC = 2; /* Dynamic linking information */
	unsigned int *h;
	unsigned int *gh;
	unsigned long lo;
	unsigned long hi;
	unsigned long seg_lo;
	unsigned long seg_hi;
	void *dyn_addr;
	int i;

	m->base = (unsigned long)base;
	m->eh = (Elf64_Ehdr *)base;
	if (RARELY((unsigned int)(m->eh->e_ident[0] != 0x7f) | (unsigned int)(m->eh->e_ident[1] != 'E') |
		   (unsigned int)(m->eh->e_ident[2] != 'L') | (unsigned int)(m->eh->e_ident[3] != 'F'))) {
		return -1;
	}

	m->ph = (Elf64_Phdr *)((char *)base + m->eh->e_phoff);

	lo = ~0UL;
	hi = 0;
	for (i = 0; i < m->eh->e_phnum; ++i) {
		Elf64_Phdr *ph = &m->ph[i];
		if (ph->p_type == pt_LOAD) {
			seg_lo = (unsigned long)base + ph->p_vaddr;
			seg_hi = (unsigned long)seg_lo + ph->p_memsz;
			if (seg_lo < lo) {
				lo = seg_lo;
			}
			if (seg_hi > hi) {
				hi = seg_hi;
			}
		}
	}

	m->dyn = NULL;
	for (i = 0; i < m->eh->e_phnum; ++i) {
		if (m->ph[i].p_type == pt_DYNAMIC) {
			dyn_addr = (char *)base + m->ph[i].p_vaddr;
			if ((unsigned int)((unsigned long)dyn_addr < lo) |
			    (unsigned int)((unsigned long)dyn_addr + sizeof(Elf64_Dyn) > hi)) {
				return -1;
			}
			m->dyn = (Elf64_Dyn *)dyn_addr;
			break;
		}
	}
	if (RARELY(!m->dyn)) {
		return -1;
	}

	for (Elf64_Dyn *d = m->dyn; d->d_tag != dt_NULL; ++d) {
		switch (d->d_tag) {
		case DT_STRTAB:
			m->dynstr = (const char *)dyn_ptr(base, lo, hi, d->d_ptr_val);
			break;
		case DT_SYMTAB:
			m->dynsym = (Elf64_Sym *)dyn_ptr(base, lo, hi, d->d_ptr_val);
			break;
		case DT_HASH:
			h = (unsigned int *)dyn_ptr(base, lo, hi, d->d_ptr_val);
			m->nbucket = h[0];
			m->nchain = h[1];
			m->buckets = h + 2;
			m->chains = h + 2 + m->nbucket;
			break;
		case DT_GNU_HASH:
			gh = (unsigned int *)dyn_ptr(base, lo, hi, d->d_ptr_val);
			m->gnu_nbucket = gh[0];
			m->gnu_symoffset = gh[1];
			m->gnu_maskwords = gh[2];
			m->gnu_shift2 = gh[3];
			m->gnu_bloom = gh + 4;
			m->gnu_buckets = m->gnu_bloom + 2ull * m->gnu_maskwords;
			m->gnu_chain = m->gnu_buckets + m->gnu_nbucket;
			break;
		case DT_VERSYM:
			m->versym = dyn_ptr(base, lo, hi, d->d_ptr_val);
			break;
		default:
			break;
		}
	}

	return (unsigned long)(m->dynsym) & (unsigned long)(m->dynstr) ? 0 : -1;
}

#undef DT_STRTAB
#undef DT_SYMTAB
#undef DT_HASH
#undef DT_GNU_HASH
#undef DT_VERSYM

static void *z_memset(void *s, int c, unsigned long n)
{
	unsigned char *p = s, *e = p + n;
	while (p < e) {
		*p = c;
		++p;
	}
	return s;
}

static unsigned int gnu_hash_str(const char *s)
{
	unsigned int h;
	unsigned char c;

	h = 5381;

	while (1 == 1) {
		c = *s;
		++s;
		if (c == 0) {
			break;
		}
		h = (h * 33) + c;
	}

	return h;
}

static unsigned int u32_mod(unsigned int a, unsigned int m)
{
	if (m == 0) {
		return 0;
	}
	return a % m;
}

static int z_strcmp(const char *a, const char *b)
{
	while ((unsigned int)(*a != '\0') & (unsigned int)(*a == *b)) {
		++a;
		++b;
	}
	return (unsigned char)*a - (unsigned char)*b;
}

/* GNU hash lookup */
static Elf64_Sym *lookup_gnu(mod_t *restrict m, const char *restrict name)
{
	unsigned int h;
	unsigned long bloom_idx;
	unsigned long bitmask;
	unsigned long tmp;
	unsigned int idx;
	unsigned int hv;
	Elf64_Sym *sym;

	if (m->gnu_buckets == NULL) {
		return NULL;
	}

	h = gnu_hash_str(name);
	bloom_idx = h / (sizeof(long) * 8) & m->gnu_maskwords - 1;
	bitmask = 1ull << h % (sizeof(long) * 8) | 1ull << (h >> m->gnu_shift2) % (sizeof(long) * 8);

	tmp = m->gnu_bloom[bloom_idx * 2 + 1];
	tmp <<= 32;
	tmp |= m->gnu_bloom[bloom_idx * 2];

	if ((tmp & bitmask) != bitmask) {
		return NULL;
	}

	idx = m->gnu_buckets[u32_mod(h, m->gnu_nbucket)];
	if (!idx) {
		return NULL;
	}

	while (1 == 1) {
		hv = m->gnu_chain[idx - m->gnu_symoffset];
		if ((hv | 1u) == (h | 1u)) {
			sym = m->dynsym + idx;
			if (sym->st_name != 0 && 0 == z_strcmp(m->dynstr + sym->st_name, name)) {
				return sym;
			}
		}
		if (hv & 1u) {
			break;
		}
		++idx;
	}
	return NULL;
}

static unsigned int sysv_hash(const char *s)
{
	unsigned int h;
	unsigned int g;

	h = 0;
	while (*s != '\0') {
		h = (h << 4) + (unsigned char)*s;
		++s;
		g = h & 0xF0000000U;
		if (g != 0) {
			h ^= g >> 24;
		}
		h &= ~g;
	}
	return h;
}

/* SysV hash lookup */
static Elf64_Sym *lookup_sysv(mod_t *restrict m, const char *restrict name)
{
	unsigned int i;
	unsigned int h;
	Elf64_Sym *sym;

	if (!m->buckets) {
		return NULL;
	}

	h = sysv_hash(name);
	for (i = m->buckets[u32_mod(h, m->nbucket)]; i != 0; i = m->chains[i]) {
		sym = &m->dynsym[i];
		if (sym->st_name != 0 && 0 == z_strcmp(m->dynstr + sym->st_name, name)) {
			return sym;
		}
	}
	return NULL;
}

static void *resolve_sym(mod_t *restrict m, const char *restrict name)
{
	Elf64_Sym *s;
	unn_syscall_result vp;
	const unsigned long stt_GNU_IFUNC = 10; /* Symbol is indirect code object */
	const unsigned long stt_FUNC = 2;	/* Symbol is a code object */

	s = lookup_gnu(m, name);
	if (s == NULL) {
		s = lookup_sysv(m, name);
	}

	if (RARELY(s == NULL)) {
		return NULL;
	}

	if (RARELY((unsigned int)((s->st_info & 0xF) != stt_FUNC) &
		   (unsigned int)((s->st_info & 0xF) != stt_GNU_IFUNC))) {
		return NULL;
	}

	vp.ul = m->base + s->st_value;
	return vp.p;
}

#if defined(FOREIGN_DLOPEN_STATIC)
#define MY_VISIBILITY static
#else
#define MY_VISIBILITY
#endif

MY_VISIBILITY double (*my_fabs)(double) = NULL;
MY_VISIBILITY double (*my_fmod)(double) = NULL;
MY_VISIBILITY double (*my_exp)(double) = NULL;
MY_VISIBILITY double (*my_log)(double) = NULL;
MY_VISIBILITY double (*my_log10)(double) = NULL;
MY_VISIBILITY double (*my_pow)(double, double) = NULL;
MY_VISIBILITY double (*my_sqrt)(double) = NULL;
MY_VISIBILITY double (*my_sin)(double) = NULL;
MY_VISIBILITY double (*my_cos)(double) = NULL;
MY_VISIBILITY double (*my_tan)(double) = NULL;
MY_VISIBILITY double (*my_asin)(double) = NULL;
MY_VISIBILITY double (*my_acos)(double) = NULL;
MY_VISIBILITY double (*my_atan)(double) = NULL;
MY_VISIBILITY double (*my_atan2)(double, double) = NULL;
MY_VISIBILITY double (*my_sinh)(double) = NULL;
MY_VISIBILITY double (*my_cosh)(double) = NULL;
MY_VISIBILITY double (*my_tanh)(double) = NULL;
MY_VISIBILITY double (*my_ceil)(double) = NULL;
MY_VISIBILITY double (*my_floor)(double) = NULL;
MY_VISIBILITY double (*my_frexp)(double) = NULL;
MY_VISIBILITY double (*my_ldexp)(double) = NULL;
MY_VISIBILITY double (*my_modf)(double) = NULL;

MY_VISIBILITY void *my_pthread_atfork = NULL;
MY_VISIBILITY void *my_pthread_attr_init = NULL;
MY_VISIBILITY void *my_pthread_attr_destroy = NULL;
MY_VISIBILITY void *my_pthread_cancel = NULL;
MY_VISIBILITY void *my_pthread_cleanup_push = NULL;
MY_VISIBILITY void *my_pthread_cleanup_pop = NULL;
MY_VISIBILITY void *my_pthread_cond_init = NULL;
MY_VISIBILITY void *my_pthread_cond_signal = NULL;
MY_VISIBILITY void *my_pthread_cond_broadcast = NULL;
MY_VISIBILITY void *my_pthread_cond_wait = NULL;
MY_VISIBILITY void *my_pthread_cond_timedwait = NULL;
MY_VISIBILITY void *my_pthread_cond_destroy = NULL;
MY_VISIBILITY void *my_pthread_create = NULL;
MY_VISIBILITY void *my_pthread_detach = NULL;
MY_VISIBILITY void *my_pthread_equal = NULL;
MY_VISIBILITY void *my_pthread_exit = NULL;
MY_VISIBILITY void *my_pthread_key_create = NULL;
MY_VISIBILITY void *my_pthread_key_delete = NULL;
MY_VISIBILITY void *my_pthread_setspecific = NULL;
MY_VISIBILITY void *my_pthread_getspecific = NULL;
MY_VISIBILITY void *my_pthread_kill = NULL;
MY_VISIBILITY void *my_pthread_mutex_lock = NULL;
MY_VISIBILITY void *my_pthread_mutex_unlock = NULL;
MY_VISIBILITY void *my_pthread_mutex_trylock = NULL;
MY_VISIBILITY void *my_pthread_mutex_init = NULL;
MY_VISIBILITY void *my_pthread_mutex_destroy = NULL;
MY_VISIBILITY void *my_pthread_mutexattr_destroy = NULL;
MY_VISIBILITY void *my_pthread_mutexattr_init = NULL;
MY_VISIBILITY void *my_pthread_join = NULL;

MY_VISIBILITY void *(*my_dlopen)(const char *, int) = NULL;
MY_VISIBILITY void *(*my_dlsym)(void *restrict, const char *restrict) = NULL;
MY_VISIBILITY int (*my_dlclose)(void *) = NULL;

extern void *gl_interp_base;

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

static int submain(void);

/* MUST ensure that stack is 16 byte aligned for calls to external functions */
/* especially ones with variadic arguments. We do this via the z_fdlentry.S wrapper */
extern void fdl_entry_impl(void)
{
	int cached;
	void *text_base;
	const char *cached_name;
	void *cached_base;
	const char *soname;

	void *tmp_dlopen;
	void *tmp_dlsym;
	void *tmp_dlclose;

	int exit_status;

	mod_t M;

	cached = 0;
	exit_status = 0;
	text_base = NULL;
	cached_name = NULL;
	cached_base = NULL;
	soname = NULL;

	if (0 > find_libc_base(&cached, &text_base, &cached_name, &cached_base, &soname)) {
		if (gl_interp_base != 0) {
			text_base = gl_interp_base;
		} else {
			goto l_exit_failure;
		}
	}

	z_memset(&M, 0, sizeof M);
	if (RARELY(mod_init(&M, text_base) < 0)) {
		goto l_exit_failure;
	}

	/* glibc: prefer __libc_dlopen_mode; fallback to dlopen/dlsym */

	tmp_dlopen = resolve_sym(&M, "__libc_dlopen_mode");
	if (!tmp_dlopen) {
		tmp_dlopen = resolve_sym(&M, "dlopen");
	}

	tmp_dlsym = resolve_sym(&M, "dlsym");
	tmp_dlclose = resolve_sym(&M, "dlclose");

	if ((unsigned int)(!tmp_dlopen) | (unsigned int)(!tmp_dlsym) | (unsigned int)(!tmp_dlclose)) {
		goto l_exit_failure;
	}

	my_dlopen = (void *(*)(const char *, int))tmp_dlopen;
	my_dlsym = (void *(*)(void *restrict, const char *restrict))tmp_dlsym;
	my_dlclose = (int (*)(void *))tmp_dlclose;

l_exit:
	sys_exit(exit_status == 0 ? submain() : exit_status);

l_exit_failure:
	exit_status = 1;
	goto l_exit;
}

#if !defined(EINVAL)
#define	EINVAL		22	/* Invalid argument */
#endif

static int submain(void)
{
	void *c;
	void *m;
	void *p;

	int (*my_printf)(const char *restrict, ...);
	float (*my_sinf)(float);
	void *sleepf;
	void *pth_create;
	void *pth_join;
	void *errno_location;
	void *lseek;

	unsigned long tid1;
	unsigned long tid2;
	struct worker_str ws1;
	struct worker_str ws2;
	void *dummy;

	c = dlopen(NULL, RTLD_NOW);
	my_printf = (int (*)(const char *restrict, ...))dlsym(c, "printf");

	m = dlopen("libm.so.6", RTLD_NOW);
	if (RARELY(m == NULL)) {
		goto l_exit_failure;
	}

	my_sinf = (float (*)(float))dlsym(m, "sinf");
	if (RARELY(my_sinf == NULL)) {
		goto l_exit_failure;
	}

	if (RARELY(my_printf == NULL)) {
		goto l_exit_failure;
	}

	errno_location = dlsym(c, "__errno_location");
	if (RARELY(errno_location == NULL)) {
		goto l_exit_failure;
	}

	lseek = dlsym(c, "lseek");
	if (RARELY(lseek == NULL)) {
		goto l_exit_failure;
	}

	if (*(*(int* (*)(void))errno_location)() != 0) {
		goto l_exit_failure;
	}

	(*(long (*)(int, long, int))lseek)(0, 0, 0xffffFFFF);
	if (*(*(int* (*)(void))errno_location)() != EINVAL) {
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

	ws1.printff = ws2.printff = (void *)my_printf;
	ws1.sleepf = ws2.sleepf = (void *)sleepf;

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

	return 0;

l_exit_failure:
	return 1;
}
