/*
 * Copyright (c) 1997-8,2007,2011,2019 Andrew G Morgan <morgan@kernel.org>
 *
 * This file deals with getting and setting capabilities on processes.
 */

#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "libcap.h"

/*
 * libcap uses this abstraction for all system calls that change
 * kernel managed capability state. This permits the user to redirect
 * it for testing and also to better implement posix semantics when
 * using pthreads.
 */

static long int _cap_syscall(long int syscall_nr,
			     long int arg1, long int arg2, long int arg3)
{
    return syscall(syscall_nr, arg1, arg2, arg3);
}

static long int _cap_syscall6(long int syscall_nr,
			      long int arg1, long int arg2, long int arg3,
			      long int arg4, long int arg5, long int arg6)
{
    return syscall(syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6);
}

static long int (*_libcap_syscall)(long int, long int, long int, long int)
    = _cap_syscall;
static long int (*_libcap_syscall6)(long int, long int, long int, long int,
    long int, long int, long int) = _cap_syscall6;

void cap_set_syscall(long int (*new_syscall)(long int,
					     long int, long int, long int),
		     long int (*new_syscall6)(long int,
					      long int, long int, long int,
					      long int, long int, long int))
{
    _libcap_syscall = new_syscall;
    _libcap_syscall6 = new_syscall6;
}

/*
 * libcap<->libpsx subtle linking trick. If -lpsx is linked, then this
 * function will get called when psx is initialized. In so doing,
 * libcap will opt to use POSIX compliant syscalls for all state
 * changing system calls - via psx_syscall().
 */
void share_psx_syscall(long int (*syscall_fn)(long int,
					      long int, long int, long int),
		       long int (*syscall6_fn)(long int,
					       long int, long int, long int,
					       long int, long int, long int));

void share_psx_syscall(long int (*syscall_fn)(long int,
					      long int, long int, long int),
		       long int (*syscall6_fn)(long int,
					       long int, long int, long int,
					       long int, long int, long int))
{
    cap_set_syscall(syscall_fn, syscall6_fn);
}

static int _libcap_capset(cap_user_header_t header, const cap_user_data_t data)
{
    return _libcap_syscall(SYS_capset, (long int) header, (long int) data, 0);
}

static int _libcap_prctl(long int pr_cmd, long int arg1, long int arg2)
{
    return _libcap_syscall(SYS_prctl, pr_cmd, arg1, arg2);
}

static int _libcap_prctl6(long int pr_cmd, long int arg1, long int arg2,
			  long int arg3, long int arg4, long int arg5)
{
    return _libcap_syscall6(SYS_prctl, pr_cmd, arg1, arg2, arg3, arg4, arg5);
}

cap_t cap_get_proc(void)
{
    cap_t result;

    /* allocate a new capability set */
    result = cap_init();
    if (result) {
	_cap_debug("getting current process' capabilities");

	/* fill the capability sets via a system call */
	if (capget(&result->head, &result->u[0].set)) {
	    cap_free(result);
	    result = NULL;
	}
    }

    return result;
}

int cap_set_proc(cap_t cap_d)
{
    int retval;

    if (!good_cap_t(cap_d)) {
	errno = EINVAL;
	return -1;
    }

    _cap_debug("setting process capabilities");
    retval = _libcap_capset(&cap_d->head, &cap_d->u[0].set);

    return retval;
}

/* the following two functions are not required by POSIX */

/* read the caps on a specific process */

int capgetp(pid_t pid, cap_t cap_d)
{
    int error;

    if (!good_cap_t(cap_d)) {
	errno = EINVAL;
	return -1;
    }

    _cap_debug("getting process capabilities for proc %d", pid);

    cap_d->head.pid = pid;
    error = capget(&cap_d->head, &cap_d->u[0].set);
    cap_d->head.pid = 0;

    return error;
}

/* allocate space for and return capabilities of target process */

cap_t cap_get_pid(pid_t pid)
{
    cap_t result;

    result = cap_init();
    if (result) {
	if (capgetp(pid, result) != 0) {
	    int my_errno;

	    my_errno = errno;
	    cap_free(result);
	    errno = my_errno;
	    result = NULL;
	}
    }

    return result;
}

/*
 * set the caps on a specific process/pg etc.. The kernel has long
 * since deprecated this asynchronus interface.
 */

int capsetp(pid_t pid, cap_t cap_d)
{
    int error;

    if (!good_cap_t(cap_d)) {
	errno = EINVAL;
	return -1;
    }

    _cap_debug("setting process capabilities for proc %d", pid);
    cap_d->head.pid = pid;
    error = capset(&cap_d->head, &cap_d->u[0].set);
    cap_d->head.version = _LIBCAP_CAPABILITY_VERSION;
    cap_d->head.pid = 0;

    return error;
}

/* the kernel api requires unsigned long arguments */
#define pr_arg(x) ((unsigned long) x)

/* get a capability from the bounding set */

int cap_get_bound(cap_value_t cap)
{
    int result;

    result = _libcap_prctl(PR_CAPBSET_READ, pr_arg(cap), pr_arg(0));
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}

/* drop a capability from the bounding set */

int cap_drop_bound(cap_value_t cap)
{
    int result;

    result = _libcap_prctl(PR_CAPBSET_DROP, pr_arg(cap), pr_arg(0));
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}

/* get a capability from the ambient set */

int cap_get_ambient(cap_value_t cap)
{
    int result;
    result = prctl(PR_CAP_AMBIENT, pr_arg(PR_CAP_AMBIENT_IS_SET),
		   pr_arg(cap), pr_arg(0), pr_arg(0));
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}

/* modify a single ambient capability value */

int cap_set_ambient(cap_value_t cap, cap_flag_value_t set)
{
    int result, val;
    switch (set) {
    case CAP_SET:
	val = PR_CAP_AMBIENT_RAISE;
	break;
    case CAP_CLEAR:
	val = PR_CAP_AMBIENT_LOWER;
	break;
    default:
	errno = EINVAL;
	return -1;
    }
    result = _libcap_prctl6(PR_CAP_AMBIENT, pr_arg(val), pr_arg(cap),
			    pr_arg(0), pr_arg(0), pr_arg(0));
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}

/* erase all ambient capabilities */

int cap_reset_ambient()
{
    int result;

    result = _libcap_prctl6(PR_CAP_AMBIENT, pr_arg(PR_CAP_AMBIENT_CLEAR_ALL),
			    pr_arg(0), pr_arg(0), pr_arg(0), pr_arg(0));
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}
