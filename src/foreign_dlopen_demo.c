#include <stdlib.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <syscall.h>

static void z_exit(int status);
__attribute__((always_inline)) static void exec_elf(const char *file, int argc, char *argv[]);

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



static void *z_memset(void *s, int c, size_t n)
{
	unsigned char *p = s, *e = p + n;
	while (p < e)
		*p++ = c;
	return s;
}

static void *z_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *p = src, *e = p + n;
	while (p < e)
		*d++ = *p++;
	return dest;
}

static char *z_strstr(const char *h, const char *n)
{
	if (!*n)
		return (char *)h;
	for (; *h; h++)
	{
		const char *p = h, *q = n;
		while (*p && *q && *p == *q)
		{
			p++;
			q++;
		}
		if (!*q)
			return (char *)h;
	}
	return NULL;
}

static int z_strcmp(const char *a, const char *b)
{
	while (*a && (*a == *b))
	{
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}



#define PRIVATE __attribute__((visibility ("hidden")))

PRIVATE long z_syscall(int n, ...);

static int errno;

static long check_error(long rc)
{
	if (rc < 0 && rc > -4096) {
		errno = -rc;
		rc = -1;
	}
	return rc;
}

#define SYSCALL(name, ...)  check_error(z_syscall(SYS_##name, __VA_ARGS__))
#define DEF_SYSCALL1(ret, name, t1, a1) \
static ret z_##name(t1 a1) \
{ \
	return (ret)SYSCALL(name, a1); \
}
#define DEF_SYSCALL2(ret, name, t1, a1, t2, a2) \
static ret z_##name(t1 a1, t2 a2) \
{ \
	return (ret)SYSCALL(name, a1, a2); \
}
#define DEF_SYSCALL3(ret, name, t1, a1, t2, a2, t3, a3) \
static ret z_##name(t1 a1, t2 a2, t3 a3) \
{ \
	return (ret)SYSCALL(name, a1, a2, a3); \
}

DEF_SYSCALL1(void, exit, int, status)
DEF_SYSCALL2(int, open, const char *, filename, int, flags)
DEF_SYSCALL3(ssize_t, read, int, fd, void *, buf, size_t, count)
DEF_SYSCALL1(int, close, int, fd)
DEF_SYSCALL3(int, lseek, int, fd, off_t, off, int, whence)
DEF_SYSCALL2(int, munmap, void *, addr, size_t, length)
DEF_SYSCALL3(int, mprotect, void *, addr, size_t, length, int, prot)

static void *
z_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	/* i386 has map (old_mmap) and mmap2, old_map is a legacy single arg
	 * function, use mmap2 but it needs offset in page units.
	 * In same time mmap2 does not exist on x86-64.
	 */
#ifdef SYS_mmap2
	return (void *)SYSCALL(mmap2, addr, length, prot, flags, fd, offset >> 12);
#else
	return (void *)SYSCALL(mmap, addr, length, prot, flags, fd, offset);
#endif
}



PRIVATE void z_trampo(void (*entry)(void), unsigned long *sp, void (*fini)(void));


PRIVATE void z_fdl_entry(void);


#define z_alloca __builtin_alloca


#if !defined(ELFCLASS)
#define ELFCLASS ELFCLASS64
#endif

#if ELFCLASS == ELFCLASS64
#  define Elf_Ehdr	Elf64_Ehdr
#  define Elf_Phdr	Elf64_Phdr
#  define Elf_Sym   Elf64_Sym
#  define Elf_Dyn   Elf64_Dyn
#  define Elf_auxv_t	Elf64_auxv_t
#elif ELFCLASS == ELFCLASS32
#  define Elf_Ehdr	Elf32_Ehdr
#  define Elf_Phdr	Elf32_Phdr
#  define Elf_Sym   Elf32_Sym
#  define Elf_Dyn   Elf32_Dyn
#  define Elf_auxv_t	Elf32_auxv_t
#else
#  error "ELFCLASS is not defined"
#endif

static int fdl_resolve_from_maps(unsigned long interp_base);
static void *fdl_dlopen_sym(void *p);
static void *fdl_dlsym_sym(void *p);

#define PAGE_SIZE 4096
#define ALIGN (PAGE_SIZE - 1)
#define ROUND_PG(x) (((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x) ((x) & ~(ALIGN))
#define PFLAGS(x) ((((x) & PF_R) ? PROT_READ : 0) |  \
				   (((x) & PF_W) ? PROT_WRITE : 0) | \
				   (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR ((unsigned long)-1)

/* Original sp (i.e. pointer to executable params) passed to entry, if any. */
unsigned long *entry_sp;

/* External fini function that the caller can provide us. */
static void (*x_fini)(void);
static unsigned long g_interp_base = 0;

static void z_fini(void)
{
	if (x_fini != NULL)
		x_fini();
}

// MUST ensure that stack is 16 byte aligned for calls to external functions
// especially ones with variadic arguments. We do this via the z_fdlentry.S wrapper
void fdl_entry_impl(void)
{
	if (fdl_resolve_from_maps(g_interp_base) == 0)
	{
#ifndef RTLD_NOW
#define RTLD_NOW 0x0002
#endif
		void *(*my_dlopen)(const char *, int) = (void *(*)(const char *, int))fdl_dlopen_sym(NULL);
		void *(*my_dlsym)(void *, const char *) = (void *(*)(void *, const char *))fdl_dlsym_sym(NULL);
		int (*libc_printf)(const char *, ...) = 0;

		void *h = my_dlopen(NULL, RTLD_NOW);

		libc_printf = (int (*)(const char *, ...))my_dlsym(h, "printf");
		

		if (libc_printf)
			libc_printf("[libc printf] hello via foreign dlopen\n");
		
	}
	z_exit(0);
}

static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
			e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
			e_ident[EI_CLASS] != ELFCLASS ||
			e_ident[EI_VERSION] != EV_CURRENT ||
			(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
			   ? 0
			   : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	minva = (unsigned long)-1;
	maxva = 0;

	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++)
	{
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
	base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;
	z_munmap(base, maxva - minva);

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++)
	{
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = z_mmap((void *)start, sz, PROT_READ | PROT_WRITE, flags, -1, 0);
		if (p == (void *)-1)
		{
			goto err;
		}
		if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
		{
			goto err;
		}
		if (z_read(fd, p + off, iter->p_filesz) !=
			(ssize_t)iter->p_filesz)
		{
			goto err;
		}
		z_mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	z_munmap(base, maxva - minva);
	return LOAD_ERR;
}

#define Z_PROG 0
#define Z_INTERP 1

void z_entry(unsigned long *sp, void (*fini)(void))
{
	int argc;
	char **argv;

	entry_sp = sp;
	x_fini = fini;
	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	main(argc, argv);
}

__attribute__((always_inline)) static void exec_elf(const char *file, int argc, char *argv[])
{
	Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
	Elf_Phdr *phdr, *iter;
	Elf_auxv_t *av;
	char **env, **p, *elf_interp = NULL;
	unsigned long *sp = entry_sp;
	unsigned long base[2], entry[2];
	ssize_t sz;
	int fd, i;

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
		while (*p++ != 0)
		{
			p++;
		}
		p++;

		unsigned long argv_sz = argc * sizeof(*p);
		unsigned sz = (char *)p - (char *)from;
		p = alloca(sizeof(*p) + argv_sz + sz);
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

	for (i = 0;; i++, ehdr++)
	{
		/* Open file, read and than check ELF header.*/
		if ((fd = z_open(file, O_RDONLY)) < 0)
			z_exit(1);
		if (z_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
			z_exit(1);
		if (!check_ehdr(ehdr))
			z_exit(1);

		/* Read the program header. */
		sz = ehdr->e_phnum * sizeof(Elf_Phdr);
		phdr = z_alloca(sz);
		if (z_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
			z_exit(1);
		if (z_read(fd, phdr, sz) != sz)
			z_exit(1);
		/* Time to load ELF. */
		if ((base[i] = loadelf_anon(fd, ehdr, phdr)) == LOAD_ERR)
			z_exit(1);

		/* Set the entry point, if the file is dynamic than add bias. */
		entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
		/* The second round, we've loaded ELF interp. */
		if (file == elf_interp)
			break;
		for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++)
		{
			if (iter->p_type != PT_INTERP)
				continue;
			elf_interp = z_alloca(iter->p_filesz);
			if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
				z_exit(1);
			if (z_read(fd, elf_interp, iter->p_filesz) !=
				(ssize_t)iter->p_filesz)
				z_exit(1);
			if (elf_interp[iter->p_filesz - 1] != '\0')
				z_exit(1);
			// z_printf("elf_interp: %s\n", elf_interp);
			file = elf_interp;
		}
		/* Looks like the ELF is static -- leave the loop. */
		if (elf_interp == NULL)
			break;
	}

	/* Reassign some vectors that are important for
	 * the dynamic linker and for lib C. */
#define AVSET(t, v, expr)         \
	case (t):                     \
		(v)->a_un.a_val = (expr); \
		break
	while (av->a_type != AT_NULL)
	{
		switch (av->a_type)
		{
			AVSET(AT_PHDR, av, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
			AVSET(AT_PHNUM, av, ehdrs[Z_PROG].e_phnum);
			AVSET(AT_PHENT, av, ehdrs[Z_PROG].e_phentsize);
			// AVSET(AT_ENTRY, av, entry[Z_PROG]);
			// We override the entrypoint with our own, thereby maintaining execution control
			AVSET(AT_ENTRY, av, (unsigned long)z_fdl_entry);
			AVSET(AT_EXECFN, av, (unsigned long)argv[1]);
			AVSET(AT_BASE, av, elf_interp ? base[Z_INTERP] : av->a_un.a_val);
		}
		++av;
	}
#undef AVSET
	++av;

	if (elf_interp)
	{
		g_interp_base = base[Z_INTERP];
	}
	

	
	z_trampo((void (*)(void))(elf_interp ? entry[Z_INTERP] : entry[Z_PROG]), sp, z_fini);
	/* Should not reach. */
	z_exit(0);
}


#ifndef ELF_ST_TYPE
#define ELF_ST_TYPE(i) ((i) & 0xF)
#endif

#ifndef MAPS_PATH
#define MAPS_PATH "/proc/self/maps"
#endif

static unsigned long text_base;
static const char *soname;

static void *fdl_dlopen_sym(void *p)
{
    static void *g_fdl_dlopen = NULL;
    if (p)
        g_fdl_dlopen = p;
    return g_fdl_dlopen;
}

static void *fdl_dlsym_sym(void *p)
{
    static void *g_fdl_dlsym = NULL;
    if (p)
        g_fdl_dlsym = p;
    return g_fdl_dlsym;
}

/* helper: turn a DT_* pointer/offset into an absolute VA */
static inline void *dyn_ptr(unsigned long base,
                            unsigned long lo, unsigned long hi,
                            unsigned long p)
{
    unsigned long v = p;
    /* if it's not already inside this module's mapped range, treat as offset */
    if (v < lo || v >= hi)
        v += base;
    return (void *)v;
}

static inline uint32_t u32_mod(uint32_t a, uint32_t m)
{
    if (m == 0)
        return 0;
    // shift-subtract reduction, no hardware/software div required
    // used to avoid __aeabi_uidivmod on arm..
    while (a >= m)
    {
        uint32_t t = m;
        /* grow t to the largest power-of-two multiple ≤ a */
        while ((t << 1) > t && (t << 1) <= a)
            t <<= 1;
        a -= t;
    }
    return a;
}

/* Minimal readers */
static int read_all(int fd, char *buf, int sz)
{
    int off = 0, n;
    while (off < sz && (n = z_read(fd, buf + off, sz - off)) > 0)
        off += n;
    return off;
}

/* parse one /proc/self/maps line; returns 0 on success */
static int parse_maps_line(const char *line,
                           unsigned long *start,
                           char perms_out[5],
                           unsigned long *offset,
                           const char **path_out)
{
    const char *p = line;
    unsigned long v = 0;
    int i;

    /* start */
    v = 0;
    for (; (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'); p++)
        v = (v << 4) | (unsigned long)((*p <= '9') ? *p - '0' : (*p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A'));
    if (*p != '-')
        return -1;
    *start = v;
    p++;

    /* end (skip) */
    for (; (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'); p++)
        ;
    while (*p == ' ')
        p++;

    /* perms (4 chars) */
    for (i = 0; i < 4; i++)
    {
        if (!p[i])
            return -1;
        perms_out[i] = p[i];
    }
    perms_out[4] = 0;
    p += 4;
    while (*p == ' ')
        p++;

    /* offset */
    v = 0;
    for (; (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'); p++)
        v = (v << 4) | (unsigned long)((*p <= '9') ? *p - '0' : (*p >= 'a' ? 10 + *p - 'a' : 10 + *p - 'A'));
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
    *path_out = (*p) ? p : NULL;
    return 0;
}

/* Parse /proc/self/maps to find libc mapping with offset 0 */
static int find_libc_base(void)
{
    static int cached = 0;
    static unsigned long cached_base = 0;
    static const char *cached_name = NULL;

    if (cached)
    {
        text_base = cached_base;
        soname = cached_name;
        return 0;
    }

    int fd = z_open(MAPS_PATH, O_RDONLY);
    if (fd < 0)
        return -1;

    char buf[65536];
    int n = read_all(fd, buf, sizeof(buf) - 1);
    z_close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    char *p = buf;
    while (*p)
    {
        char *line = p;
        while (*p && *p != '\n')
            p++;
        char save = *p;
        *p = 0;

        unsigned long start = 0, off = 0;
        char perms[5];
        const char *path = NULL;
        if (z_strstr(line, "libc"))
        {
            if (parse_maps_line(line, &start, perms, &off, &path) == 0 &&
                path && off == 0)
            {
                text_base = start;
                soname = path;
                cached = 1;
                cached_base = text_base;
                cached_name = soname;
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

/* In-memory ELF helpers */
typedef struct
{
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

static int mod_init(mod_t *m, unsigned long base)
{
    m->base = base;
    m->eh = (Elf_Ehdr *)base;
    if (m->eh->e_ident[0] != 0x7f || m->eh->e_ident[1] != 'E' ||
        m->eh->e_ident[2] != 'L' || m->eh->e_ident[3] != 'F')
        return -1;

    m->ph = (Elf_Phdr *)(base + m->eh->e_phoff);

    unsigned long lo = ~0UL, hi = 0;
    for (int i = 0; i < m->eh->e_phnum; i++)
    {
        Elf_Phdr *ph = &m->ph[i];
        if (ph->p_type == PT_LOAD)
        {
            unsigned long seg_lo = base + ph->p_vaddr;
            unsigned long seg_hi = seg_lo + ph->p_memsz;
            if (seg_lo < lo)
                lo = seg_lo;
            if (seg_hi > hi)
                hi = seg_hi;
        }
    }

    m->dyn = NULL;
    for (int i = 0; i < m->eh->e_phnum; i++)
    {
        if (m->ph[i].p_type == PT_DYNAMIC)
        {
            unsigned long dyn_addr = base + m->ph[i].p_vaddr;
            if (dyn_addr < lo || dyn_addr + sizeof(Elf_Dyn) > hi)
            {
                return -1;
            }
            m->dyn = (Elf_Dyn *)dyn_addr;
            break;
        }
    }
    if (!m->dyn)
    {
        return -1;
    }

    for (Elf_Dyn *d = m->dyn; d->d_tag != DT_NULL; d++)
    {
        switch (d->d_tag)
        {
        case DT_STRTAB:
            m->dynstr = (const char *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            break;
        case DT_SYMTAB:
            m->dynsym = (Elf_Sym *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            break;
        case DT_HASH:
        {
            uint32_t *h = (uint32_t *)dyn_ptr(base, lo, hi, (unsigned long)d->d_un.d_ptr);
            m->nbucket = h[0];
            m->nchain = h[1];
            m->buckets = &h[2];
            m->chains = &h[2 + m->nbucket];
            break;
        }
        case DT_GNU_HASH:
        {
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

    return (m->dynsym && m->dynstr) ? 0 : -1;
}

static uint32_t sysv_hash(const char *s)
{
    uint32_t h = 0, g;
    while (*s)
    {
        h = (h << 4) + (unsigned char)*s++;
        g = h & 0xF0000000U;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static uint32_t gnu_hash_str(const char *s)
{
    uint32_t h = 5381;
    for (unsigned char c; (c = *s++) != 0;)
        h = (h * 33) + c;
    return h;
}

/* GNU hash lookup */
static Elf_Sym *lookup_gnu(mod_t *m, const char *name)
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
    for (;;)
    {
        uint32_t hv = m->gnu_chain[idx - m->gnu_symoffset];
        if ((hv | 1U) == (h | 1U))
        {
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

/* SysV hash lookup */
static Elf_Sym *lookup_sysv(mod_t *m, const char *name)
{
    if (!m->buckets)
        return NULL;
    uint32_t h = sysv_hash(name);
    for (uint32_t i = m->buckets[u32_mod(h, m->nbucket)]; i != 0; i = m->chains[i])
    {
        Elf_Sym *sym = &m->dynsym[i];
        if (sym->st_name && !z_strcmp(m->dynstr + sym->st_name, name))
            return sym;
    }
    return NULL;
}

static void *resolve_sym(mod_t *m, const char *name)
{
    Elf_Sym *s = NULL;

    if (!s)
    {
        s = lookup_gnu(m, name);
    }
    if (!s)
    {
        s = lookup_sysv(m, name);
    }
    if (!s)
    {
        return NULL;
    }
    if (ELF_ST_TYPE(s->st_info) != STT_FUNC && ELF_ST_TYPE(s->st_info) != STT_GNU_IFUNC)
    {
        return NULL;
    }
    return (void *)(m->base + s->st_value);
}

static int fdl_resolve_from_maps(unsigned long interp_base)
{
    if (find_libc_base() < 0)
    {
        if (interp_base)
        {
            text_base = interp_base;
        }
        else
        {
            return -1;
        }
    }

    mod_t M;
    z_memset(&M, 0, sizeof(M));
    if (mod_init(&M, text_base) < 0)
        return -1;
        
    /* glibc: prefer __libc_dlopen_mode; fallback to dlopen/dlsym */
    void *dlopen = resolve_sym(&M, "__libc_dlopen_mode");
    if (!dlopen)
        dlopen = resolve_sym(&M, "dlopen");

    void *dlsym = resolve_sym(&M, "dlsym");

    fdl_dlopen_sym(dlopen);
    fdl_dlsym_sym(dlsym);
    return (dlopen && dlsym) ? 0 : -1;
}
