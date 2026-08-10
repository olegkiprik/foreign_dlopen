#if !defined(MY_PTHREAD_H)
#define MY_PTHREAD_H

#if defined(FOREIGN_DLOPEN_STATIC)
#define MY_VISIBILITY static
#else
#define MY_VISIBILITY extern
#endif

MY_VISIBILITY void *my_pthread_atfork;
MY_VISIBILITY void *my_pthread_attr_init;
MY_VISIBILITY void *my_pthread_attr_destroy;
MY_VISIBILITY void *my_pthread_cancel;
MY_VISIBILITY void *my_pthread_cleanup_push;
MY_VISIBILITY void *my_pthread_cleanup_pop;

MY_VISIBILITY void *my_pthread_cond_init;
MY_VISIBILITY void *my_pthread_cond_signal;
MY_VISIBILITY void *my_pthread_cond_broadcast;
MY_VISIBILITY void *my_pthread_cond_wait;
MY_VISIBILITY void *my_pthread_cond_timedwait;
MY_VISIBILITY void *my_pthread_cond_destroy;

MY_VISIBILITY void *my_pthread_create;
MY_VISIBILITY void *my_pthread_detach;
MY_VISIBILITY void *my_pthread_equal;
MY_VISIBILITY void *my_pthread_exit;

MY_VISIBILITY void *my_pthread_key_create;
MY_VISIBILITY void *my_pthread_key_delete;
MY_VISIBILITY void *my_pthread_setspecific;
MY_VISIBILITY void *my_pthread_getspecific;

MY_VISIBILITY void *my_pthread_kill;

MY_VISIBILITY void *my_pthread_mutex_lock;
MY_VISIBILITY void *my_pthread_mutex_unlock;
MY_VISIBILITY void *my_pthread_mutex_trylock;
MY_VISIBILITY void *my_pthread_mutex_init;
MY_VISIBILITY void *my_pthread_mutex_destroy;

MY_VISIBILITY void *my_pthread_mutexattr_destroy;
MY_VISIBILITY void *my_pthread_mutexattr_init;

MY_VISIBILITY void *my_pthread_join;

static int pthread_join(unsigned long thread, void **retval)
{
	return (*(int (*)(unsigned long, void **))my_pthread_join)(thread, retval);
}

static int pthread_mutexattr_destroy(void *attr)
{
	return (*(int (*)(void *))my_pthread_mutexattr_destroy)(attr);
}

static int pthread_mutexattr_init(void *attr)
{
	return (*(int (*)(void *))my_pthread_mutexattr_init)(attr);
}

static int pthread_mutex_lock(void *mutex)
{
	return (*(int (*)(void *))my_pthread_mutex_lock)(mutex);
}

static int pthread_mutex_unlock(void *mutex)
{
	return (*(int (*)(void *))my_pthread_mutex_unlock)(mutex);
}

static int pthread_mutex_trylock(void *mutex)
{
	return (*(int (*)(void *))my_pthread_mutex_trylock)(mutex);
}

static int pthread_mutex_init(void *restrict mutex, const void *mutexattr)
{
	return (*(int (*)(void *, const void *))my_pthread_mutex_init)(mutex, mutexattr);
}

static int pthread_mutex_destroy(void *mutex)
{
	return (*(int (*)(void *))my_pthread_mutex_destroy)(mutex);
}

static int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void))
{
	return (*(int (*)(void (*)(void), void (*)(void), void (*)(void)))my_pthread_atfork)(prepare, parent,
											     child);
}

static int pthread_attr_init(void *attr)
{
	return (*(int (*)(void *))my_pthread_attr_init)(attr);
}

static int pthread_attr_destroy(void *attr)
{
	return (*(int (*)(void *))my_pthread_attr_destroy)(attr);
}

static int pthread_cancel(unsigned long thread)
{
	return (*(int (*)(unsigned long))my_pthread_cancel)(thread);
}

static int pthread_detach(unsigned long thread)
{
	return (*(int (*)(unsigned long))my_pthread_detach)(thread);
}

static int pthread_equal(unsigned long t1, unsigned long t2)
{
	return (*(int (*)(unsigned long, unsigned long))my_pthread_equal)(t1, t2);
}

static void pthread_exit(void *retval)
{
	(*(void (*)(void *))my_pthread_exit)(retval);
}

static int pthread_key_create(void *key, void (*destr_function)(void *))
{
	return (*(int (*)(void *, void (*)(void *)))my_pthread_key_create)(key, destr_function);
}

static int pthread_key_delete(unsigned int key)
{
	return (*(int (*)(unsigned int))my_pthread_key_delete)(key);
}

static int pthread_setspecific(unsigned int key, const void *pointer)
{
	return (*(int (*)(unsigned int, const void *))my_pthread_setspecific)(key, pointer);
}

static void *pthread_getspecific(unsigned int key)
{
	return (*(void *(*)(unsigned int key))my_pthread_getspecific)(key);
}

static void pthread_cleanup_push(void (*routine)(void *), void *arg)
{
	(*(void (*)(void (*)(void *), void *))my_pthread_cleanup_push)(routine, arg);
}

static void pthread_cleanup_pop(int execute)
{
	(*(void (*)(int))my_pthread_cleanup_pop)(execute);
}

static int pthread_cond_init(void *restrict cond, void *restrict cond_attr)
{
	return (*(int (*)(void *, void *))my_pthread_cond_init)(cond, cond_attr);
}

static int pthread_cond_signal(void *cond)
{
	return (*(int (*)(void *))my_pthread_cond_signal)(cond);
}

static int pthread_cond_broadcast(void *cond)
{
	return (*(int (*)(void *))my_pthread_cond_broadcast)(cond);
}

static int pthread_cond_wait(void *restrict cond, void *restrict mutex)
{
	return (*(int (*)(void *, void *))my_pthread_cond_wait)(cond, mutex);
}

static int pthread_cond_timedwait(void *restrict cond, void *restrict mutex, const void *restrict abstime)
{
	return (*(int (*)(void *, void *, const void *))my_pthread_cond_timedwait)(cond, mutex, abstime);
}

static int pthread_cond_destroy(void *cond)
{
	return (*(int (*)(void *))my_pthread_cond_destroy)(cond);
}

static int pthread_create(void *restrict thread, const void *restrict attr, void *(*start_routine)(void *),
			  void *restrict arg)
{
	return (*(int (*)(void *, const void *, void *(*)(void *), void *))my_pthread_create)(
	    thread, attr, start_routine, arg);
}

static int pthread_kill(unsigned long thread, int sig)
{
	return (*(int (*)(unsigned long, int))my_pthread_kill)(thread, sig);
}

#endif /* MY_PTHREAD_H */
