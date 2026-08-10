#if !defined(MY_DLFCN_H)
#define MY_DLFCN_H

#if defined(FOREIGN_DLOPEN_STATIC)
#define MY_VISIBILITY static
#else
#define MY_VISIBILITY extern
#endif

MY_VISIBILITY void *(*my_dlopen)(const char *, int);
MY_VISIBILITY void *(*my_dlsym)(void *restrict, const char *restrict);
MY_VISIBILITY int (*my_dlclose)(void *);

__attribute__((always_inline)) static void* priv_select_first_restrict(void *restrict first, const void *restrict second)
{
	(void)second;
	return first;
}

__attribute__((always_inline)) static void* dlopen(const char* filename, int flags)
{
	void* result;
	
	result = (*my_dlopen)(filename, flags);
	result = priv_select_first_restrict(result, filename);
	return result;
}

__attribute__((always_inline)) static void* dlsym(void *restrict handle, const char *restrict symbol)
{
	void* result;

	result = (*my_dlsym)(handle, symbol);
	result = priv_select_first_restrict(result, handle);
	result = priv_select_first_restrict(result, symbol);
	return result;
}

__attribute__((always_inline)) static int dlclose(void *handle)
{
	return (*my_dlclose)(handle);
}

#endif

