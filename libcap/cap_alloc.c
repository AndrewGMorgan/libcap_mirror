/*
 * Copyright (c) 1997-8,2019,2021 Andrew G Morgan <morgan@kernel.org>
 *
 * This file deals with allocation and deallocation of internal
 * capability sets as specified by POSIX.1e (formerlly, POSIX 6).
 */

#include "libcap.h"

/*
 * These get set via the pre-main() executed constructor function below it.
 */
static cap_value_t _cap_max_bits;

__attribute__((constructor (300))) static void _initialize_libcap(void)
{
    if (_cap_max_bits) {
	return;
    }
    cap_set_syscall(NULL, NULL);
    _binary_search(_cap_max_bits, cap_get_bound, 0, __CAP_MAXBITS, __CAP_BITS);
    cap_proc_root("/proc");
}

cap_value_t cap_max_bits(void)
{
    return _cap_max_bits;
}

/*
 * capability allocation is all done in terms of this structure.
 */
struct _cap_alloc_s {
    __u32 magic;
    __u32 size;
    union {
	char string_start; /* enough memory is allocated for string */
	struct _cap_struct set;
	struct cap_iab_s iab;
	struct cap_launch_s launcher;
    } u;
};

/*
 * Obtain a blank set of capabilities
 */
cap_t cap_init(void)
{
    struct _cap_alloc_s *raw_data;
    cap_t result;

    raw_data = calloc(1, sizeof(struct _cap_alloc_s));
    if (raw_data == NULL) {
	_cap_debug("out of memory");
	errno = ENOMEM;
	return NULL;
    }
    raw_data->magic = CAP_T_MAGIC;
    raw_data->size = sizeof(struct _cap_alloc_s);

    result = &raw_data->u.set;
    result->head.version = _LIBCAP_CAPABILITY_VERSION;
    capget(&result->head, NULL);      /* load the kernel-capability version */

    switch (result->head.version) {
#ifdef _LINUX_CAPABILITY_VERSION_1
    case _LINUX_CAPABILITY_VERSION_1:
	break;
#endif
#ifdef _LINUX_CAPABILITY_VERSION_2
    case _LINUX_CAPABILITY_VERSION_2:
	break;
#endif
#ifdef _LINUX_CAPABILITY_VERSION_3
    case _LINUX_CAPABILITY_VERSION_3:
	break;
#endif
    default:                          /* No idea what to do */
	cap_free(result);
	result = NULL;
	break;
    }

    return result;
}

/*
 * This is an internal library function to duplicate a string and
 * tag the result as something cap_free can handle.
 */
char *_libcap_strdup(const char *old)
{
    struct _cap_alloc_s *raw_data;
    size_t len;

    if (old == NULL) {
	errno = EINVAL;
	return NULL;
    }
    len = strlen(old) + 1 + 2*sizeof(__u32);
    if (len < sizeof(struct _cap_alloc_s)) {
	len = sizeof(struct _cap_alloc_s);
    }
    if ((len & 0xffffffff) != len) {
	_cap_debug("len is too long for libcap to manage");
	errno = EINVAL;
	return NULL;
    }
    raw_data = calloc(1, len);
    if (raw_data == NULL) {
	errno = ENOMEM;
	return NULL;
    }
    raw_data->magic = CAP_S_MAGIC;
    raw_data->size = (__u32) len;
    strcpy(&raw_data->u.string_start, old);

    return &raw_data->u.string_start;
}

/*
 * This function duplicates an internal capability set with
 * malloc()'d memory. It is the responsibility of the user to call
 * cap_free() to liberate it.
 */
cap_t cap_dup(cap_t cap_d)
{
    cap_t result;

    __u32 *magic_p = -2 + (__u32 *) cap_d;
    if (*magic_p != CAP_T_MAGIC) {
	_cap_debug("bad argument");
	errno = EINVAL;
	return NULL;
    }

    result = cap_init();
    if (result == NULL) {
	_cap_debug("out of memory");
	return NULL;
    }

    memcpy(result, cap_d, sizeof(*cap_d));

    return result;
}

cap_iab_t cap_iab_init(void)
{
    struct _cap_alloc_s *base = calloc(1, sizeof(struct _cap_alloc_s));
    if (base == NULL) {
	_cap_debug("out of memory");
	return NULL;
    }
    base->magic = CAP_IAB_MAGIC;
    base->size = sizeof(struct _cap_alloc_s);
    return &base->u.iab;
}

/*
 * cap_new_launcher allocates some memory for a launcher and
 * initializes it.  To actually launch a program with this launcher,
 * use cap_launch(). By default, the launcher is a no-op from a
 * security perspective and will act just as fork()/execve()
 * would. Use cap_launcher_setuid() etc to override this.
 */
cap_launch_t cap_new_launcher(const char *arg0, const char * const *argv,
			      const char * const *envp)
{
    struct _cap_alloc_s *data = calloc(1, sizeof(struct _cap_alloc_s));
    if (data == NULL) {
	_cap_debug("out of memory");
	return NULL;
    }
    data->magic = CAP_LAUNCH_MAGIC;
    data->size = sizeof(struct _cap_alloc_s);

    struct cap_launch_s *attr = &data->u.launcher;
    attr->arg0 = arg0;
    attr->argv = argv;
    attr->envp = envp;
    return attr;
}

/*
 * cap_func_launcher allocates some memory for a launcher and
 * initializes it. The purpose of this launcher, unlike one created
 * with cap_new_launcher(), is to execute some function code from a
 * forked copy of the program. The forked process will exit when the
 * callback function, func, returns.
 */
cap_launch_t cap_func_launcher(int (callback_fn)(void *detail))
{
    struct _cap_alloc_s *data = calloc(1, sizeof(struct _cap_alloc_s));
    if (data == NULL) {
	_cap_debug("out of memory");
	return NULL;
    }
    data->magic = CAP_LAUNCH_MAGIC;
    data->size = sizeof(struct _cap_alloc_s);

    struct cap_launch_s *attr = &data->u.launcher;
    attr->custom_setup_fn = callback_fn;
    return attr;
}

/*
 * Scrub and then liberate the recognized allocated object.
 */
int cap_free(void *data_p)
{
    if (!data_p) {
	return 0;
    }

    /* confirm alignment */
    if ((sizeof(uintptr_t)-1) & (uintptr_t) data_p) {
	_cap_debug("whatever we're cap_free()ing it isn't aligned right: %p",
		   data_p);
	errno = EINVAL;
	return -1;
    }

    struct _cap_alloc_s *data = (void *) (-2 + (__u32 *) data_p);
    switch (data->magic) {
    case CAP_T_MAGIC:
    case CAP_IAB_MAGIC:
    case CAP_S_MAGIC:
	break;
    case CAP_LAUNCH_MAGIC:
	if (cap_free(data->u.launcher.iab) != 0) {
	    return -1;
	}
	data->u.launcher.iab = NULL;
	if (cap_free(data->u.launcher.chroot) != 0) {
	    return -1;
	}
	data->u.launcher.chroot = NULL;
	break;
    default:
	_cap_debug("don't recognize what we're supposed to liberate");
	errno = EINVAL;
	return -1;
    }

    memset(data, 0, data->size);
    free(data);
    data_p = NULL;
    data = NULL;
    return 0;
}
