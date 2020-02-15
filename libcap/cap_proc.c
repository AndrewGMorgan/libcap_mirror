/*
 * Copyright (c) 1997-8,2007,11,19,20 Andrew G Morgan <morgan@kernel.org>
 *
 * This file deals with getting and setting capabilities on processes.
 */

#define _GNU_SOURCE

#include <sys/prctl.h>
#include <sys/psx_syscall.h>
#include <sys/securebits.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <grp.h>

#include <linux/limits.h>

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

static long int (*_libcap_wsyscall3)(long int, long int, long int, long int)
    = _cap_syscall;
static long int (*_libcap_wsyscall6)(long int, long int, long int, long int,
    long int, long int, long int) = _cap_syscall6;

/*
 * This gets reset to 0 if we are *not* linked with libpsx.
 */
static int _libcap_overrode_syscalls = 1;

/*
 * psx_load_syscalls() is weakly defined so we can have it overriden
 * by libpsx if that library is linked. Specifically, when libcap
 * calls psx_load_sycalls() it is prepared to override the default
 * values for the syscalls that libcap uses to change security state.
 * As can be seen here this present function is mostly a
 * no-op. However, if libpsx is linked, the one present in that
 * library (not being weak) will replace this one and the
 * _libcap_overrode_syscalls value isn't forced to zero.
 */
__attribute__((weak))
void psx_load_syscalls(long int (**syscall_fn)(long int,
					      long int, long int, long int),
		       long int (**syscall6_fn)(long int,
					       long int, long int, long int,
					       long int, long int, long int))
{
    _libcap_overrode_syscalls = 0;
}

/*
 * cap_set_syscall overrides the state setting syscalls that libcap does.
 * Generally, you don't need to call this manually: libcap tries hard to
 * set things up appropriately.
 */
void cap_set_syscall(long int (*new_syscall)(long int,
					     long int, long int, long int),
			    long int (*new_syscall6)(long int, long int,
						     long int, long int,
						     long int, long int,
						     long int)) {
    if (new_syscall == NULL) {
	psx_load_syscalls(&_libcap_wsyscall3, &_libcap_wsyscall6);
    } else {
	_libcap_wsyscall3 = new_syscall;
	_libcap_wsyscall6 = new_syscall6;
    }
}

static int _libcap_capset(cap_user_header_t header, const cap_user_data_t data)
{
    if (_libcap_overrode_syscalls) {
	return _libcap_wsyscall3(SYS_capset,
				 (long int) header, (long int) data, 0);
    }
    return capset(header, data);
}

static int _libcap_wprctl3(long int pr_cmd, long int arg1, long int arg2)
{
    if (_libcap_overrode_syscalls) {
	return _libcap_wsyscall3(SYS_prctl, pr_cmd, arg1, arg2);
    }
    return prctl(pr_cmd, arg1, arg2, 0, 0, 0);
}

static int _libcap_wprctl6(long int pr_cmd, long int arg1, long int arg2,
			   long int arg3, long int arg4, long int arg5)
{
    if (_libcap_overrode_syscalls) {
	return _libcap_wsyscall6(SYS_prctl, pr_cmd, arg1, arg2,
				 arg3, arg4, arg5);
    }
    return prctl(pr_cmd, arg1, arg2, arg3, arg4, arg5);
}

/*
 * cap_get_proc obtains the capability set for the current process.
 */
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

    result = prctl(PR_CAPBSET_READ, pr_arg(cap), pr_arg(0));
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

    result = _libcap_wprctl3(PR_CAPBSET_DROP, pr_arg(cap), pr_arg(0));
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
    result = _libcap_wprctl6(PR_CAP_AMBIENT, pr_arg(val), pr_arg(cap),
			     pr_arg(0), pr_arg(0), pr_arg(0));
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}

/*
 * cap_reset_ambient erases all ambient capabilities - this reads the
 * ambient caps before performing the erase to workaround the corner
 * case where the set is empty already but the ambient cap API is
 * locked.
 */
int cap_reset_ambient()
{
    int olderrno = errno;
    cap_value_t c;
    int result = 0;

    for (c = 0; !result; c++) {
	result = cap_get_ambient(c);
	if (result == -1) {
	    errno = olderrno;
	    return 0;
	}
    }

    result = _libcap_wprctl6(PR_CAP_AMBIENT, pr_arg(PR_CAP_AMBIENT_CLEAR_ALL),
			     pr_arg(0), pr_arg(0), pr_arg(0), pr_arg(0));
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}

/*
 * Read the security mode of the current process.
 */
unsigned cap_get_secbits(void)
{
    return (unsigned) prctl(PR_GET_SECUREBITS, pr_arg(0), pr_arg(0));
}
/*
 * Set the security mode of the current process.
 */
int cap_set_secbits(unsigned bits)
{
    return _libcap_wprctl3(PR_SET_SECUREBITS, bits, 0);
}

/*
 * Some predefined
 */
#define CAP_SECURED_BITS_BASIC                                 \
    (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |                    \
     SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED |  \
     SECBIT_KEEP_CAPS_LOCKED)

#define CAP_SECURED_BITS_AMBIENT  (CAP_SECURED_BITS_BASIC |    \
     SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)

/*
 * cap_set_mode locks the overarching capability framework of the
 * present process and thus its children to a predefined flavor. Once
 * set, these modes cannot be undone by the affected process tree and
 * can only be done by "cap_setpcap" permitted processes. Note, a side
 * effect of this function, whether it succeeds or fails, is to clear
 * atleast the CAP_EFFECTIVE flags for the current process.
 */
int cap_set_mode(cap_mode_t flavor)
{
    const cap_value_t raise_cap_setpcap[] = {CAP_SETPCAP};
    cap_t working = cap_get_proc();
    unsigned secbits = CAP_SECURED_BITS_AMBIENT;

    int ret = cap_set_flag(working, CAP_EFFECTIVE,
			   1, raise_cap_setpcap, CAP_SET);
    ret = ret | cap_set_proc(working);

    if (ret == 0) {
	cap_flag_t c;

	switch (flavor) {
	case CAP_MODE_NOPRIV:
	    /* fall through */
	case CAP_MODE_PURE1E_INIT:
	    (void) cap_clear_flag(working, CAP_INHERITABLE);
	    /* fall through */
	case CAP_MODE_PURE1E:
	    if (!CAP_AMBIENT_SUPPORTED()) {
		secbits = CAP_SECURED_BITS_BASIC;
	    } else {
		ret = cap_reset_ambient();
		if (ret) {
		    break; /* ambient dropping failed */
		}
	    }
	    ret = cap_set_secbits(secbits);
	    if (flavor != CAP_MODE_NOPRIV) {
		break;
	    }

	    /* just for "case CAP_MODE_NOPRIV:" */

	    for (c = 0; cap_get_bound(c) >= 0; c++) {
		(void) cap_drop_bound(c);
	    }
	    (void) cap_clear_flag(working, CAP_PERMITTED);
	    break;
	default:
	    errno = EINVAL;
	    ret = -1;
	    break;
	}
    }

    (void) cap_clear_flag(working, CAP_EFFECTIVE);
    ret = cap_set_proc(working) | ret;
    (void) cap_free(working);
    return ret;
}

/*
 * cap_get_mode attempts to determine what the current capability mode
 * is. If it can find no match in the libcap pre-defined modes, it
 * returns CAP_MODE_UNCERTAIN.
 */
cap_mode_t cap_get_mode(void)
{
    unsigned secbits = cap_get_secbits();

    if ((secbits & CAP_SECURED_BITS_BASIC) != CAP_SECURED_BITS_BASIC) {
	return CAP_MODE_UNCERTAIN;
    }

    /* validate ambient is not set */
    int olderrno = errno;
    int ret = 0;
    cap_value_t c;
    for (c = 0; !ret; c++) {
	ret = cap_get_ambient(c);
	if (ret == -1) {
	    errno = olderrno;
	    if (c && secbits != CAP_SECURED_BITS_AMBIENT) {
		return CAP_MODE_UNCERTAIN;
	    }
	    break;
	}
	if (ret) {
	    return CAP_MODE_UNCERTAIN;
	}
    }

    cap_t working = cap_get_proc();
    cap_t empty = cap_init();
    int cf = cap_compare(empty, working);
    cap_free(empty);
    cap_free(working);

    if (CAP_DIFFERS(cf, CAP_INHERITABLE)) {
	return CAP_MODE_PURE1E;
    }
    if (CAP_DIFFERS(cf, CAP_PERMITTED) || CAP_DIFFERS(cf, CAP_EFFECTIVE)) {
	return CAP_MODE_PURE1E_INIT;
    }

    for (c = 0; ; c++) {
	int v = cap_get_bound(c);
	if (v == -1) {
	    break;
	}
	if (v) {
	    return CAP_MODE_PURE1E_INIT;
	}
    }

    return CAP_MODE_NOPRIV;
}

/*
 * cap_setuid attempts to set the uid of the process without dropping
 * any permitted capabilities in the process. A side effect of a call
 * to this function is that the effective set will be cleared by the
 * time the function returns.
 */
int cap_setuid(uid_t uid)
{
    const cap_value_t raise_cap_setuid[] = {CAP_SETUID};
    cap_t working = cap_get_proc();
    (void) cap_set_flag(working, CAP_EFFECTIVE,
			1, raise_cap_setuid, CAP_SET);
    /*
     * Note, we are cognizant of not using glibc's setuid in the case
     * that we've modified the way libcap is doing setting
     * syscalls. This is because prctl needs to be working in a POSIX
     * compliant way for the code below to work, so we are either
     * all-broken or not-broken and don't allow for "sort of working".
     */
    (void) _libcap_wprctl3(PR_SET_KEEPCAPS, 1, 0);
    int ret = cap_set_proc(working);
    if (ret == 0) {
	if (_libcap_overrode_syscalls) {
	    ret = _libcap_wsyscall3(SYS_setuid, (long int) uid, 0, 0);
	    if (ret < 0) {
		errno = -ret;
		ret = -1;
	    }
	} else {
	    ret = setuid(uid);
	}
    }
    int olderrno = errno;
    (void) _libcap_wprctl3(PR_SET_KEEPCAPS, 0, 0);

    (void) cap_clear_flag(working, CAP_EFFECTIVE);
    (void) cap_set_proc(working);
    (void) cap_free(working);

    errno = olderrno;
    return ret;
}

#if defined(__arm__) || defined(__i386__) || \
    defined(__i486__) || defined(__i586__) || defined(__i686__)
#define sys_setgroups_variant  SYS_setgroups32
#else
#define sys_setgroups_variant  SYS_setgroups
#endif

/*
 * cap_setgroups combines setting the gid with changing the set of
 * supplemental groups for a user into one call that raises the needed
 * capabilities to do it for the duration of the call. A side effect
 * of a call to this function is that the effective set will be
 * cleared by the time the function returns.
 */
int cap_setgroups(gid_t gid, size_t ngroups, const gid_t groups[])
{
    const cap_value_t raise_cap_setgid[] = {CAP_SETGID};
    cap_t working = cap_get_proc();
    (void) cap_set_flag(working, CAP_EFFECTIVE,
			1, raise_cap_setgid, CAP_SET);
    /*
     * Note, we are cognizant of not using glibc's setgid etc in the
     * case that we've modified the way libcap is doing setting
     * syscalls. This is because prctl needs to be working in a POSIX
     * compliant way for the other functions of this file so we are
     * all-broken or not-broken and don't allow for "sort of working".
     */
    int ret = cap_set_proc(working);
    if (_libcap_overrode_syscalls) {
	if (ret == 0) {
	    ret = _libcap_wsyscall3(SYS_setgid, (long int) gid, 0, 0);
	}
	if (ret == 0) {
	    ret = _libcap_wsyscall3(sys_setgroups_variant, (long int) ngroups,
				  (long int) groups, 0);
	}
	if (ret < 0) {
	    errno = -ret;
	    ret = -1;
	}
    } else {
	if (ret == 0) {
	    ret = setgid(gid);
	}
	if (ret == 0) {
	    ret = setgroups(ngroups, groups);
	}
    }
    int olderrno = errno;

    (void) cap_clear_flag(working, CAP_EFFECTIVE);
    (void) cap_set_proc(working);
    (void) cap_free(working);

    errno = olderrno;
    return ret;
}
