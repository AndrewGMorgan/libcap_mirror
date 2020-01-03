/*
 * Copyright (c) 2019 Andrew G Morgan <morgan@kernel.org>
 *
 * This file contains a collection of routines that perform thread
 * synchronization to ensure that a whole process is running as a
 * single privilege object - independent of the number of pthreads.
 *
 * The whole file would be unnecessary if glibc exported an explicit
 * psx_syscall()-like function that leveraged the nptl:setxid
 * mechanism to synchronize thread state over the whole process.
 */
#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/psx_syscall.h>
#include <sys/syscall.h>

/*
 * psx_load_syscalls() is weakly defined so we can have it overriden
 * by libpsx if it is linked. Specifically, when libcap calls
 * psx_load_sycalls it will override their defaut values. As can be
 * seen here this present function is a no-op. However, if libpsx is
 * linked, the one present in that library (not being weak) will
 * replace this one.
 */
void psx_load_syscalls(long int (**syscall_fn)(long int,
					      long int, long int, long int),
		       long int (**syscall6_fn)(long int,
					       long int, long int, long int,
					       long int, long int, long int))
{
    *syscall_fn = psx_syscall3;
    *syscall6_fn = psx_syscall6;
}

/*
 * type to keep track of registered threads.
 */
typedef struct registered_thread_s {
    struct registered_thread_s *next, *prev;
    pthread_t thread;
} registered_thread_t;

static pthread_once_t psx_tracker_initialized = PTHREAD_ONCE_INIT;

typedef int psx_tracker_state_t;

#define _PSX_IDLE    ((psx_tracker_state_t) 0)
#define _PSX_SETUP   ((psx_tracker_state_t) 1)
#define _PSX_SYSCALL ((psx_tracker_state_t) 2)
#define _PSX_CREATE  ((psx_tracker_state_t) 3)

/*
 * This global structure holds the global coordination state for
 * libcap's psx_posix_syscall() support.
 */
static struct psx_tracker_s {
    pthread_mutex_t state_mu;
    pthread_cond_t cond;
    psx_tracker_state_t state;

    int initialized;
    int psx_sig;

    struct {
	long syscall_nr;
	long arg1, arg2, arg3, arg4, arg5, arg6;
	int six;
	int active;
	int todo;
    } cmd;

    struct sigaction sig_action;
    registered_thread_t *root;
} psx_tracker;

/*
 * psx_posix_syscall_actor performs the system call on the targeted
 * thread and decreases the outstanding syscall counter.
 */
static void psx_posix_syscall_actor(int signum, siginfo_t *info, void *ignore) {
    /* bail early if this isn't something we recognize */
    if (signum != psx_tracker.psx_sig || !psx_tracker.cmd.active ||
	info == NULL || info->si_code != SI_TKILL || info->si_pid != getpid()) {
	return;
    }

    if (!psx_tracker.cmd.six) {
	(void) syscall(psx_tracker.cmd.syscall_nr,
		       psx_tracker.cmd.arg1,
		       psx_tracker.cmd.arg2,
		       psx_tracker.cmd.arg3);
    } else {
	(void) syscall(psx_tracker.cmd.syscall_nr,
		       psx_tracker.cmd.arg1,
		       psx_tracker.cmd.arg2,
		       psx_tracker.cmd.arg3,
		       psx_tracker.cmd.arg4,
		       psx_tracker.cmd.arg5,
		       psx_tracker.cmd.arg6);
    }

    pthread_mutex_lock(&psx_tracker.state_mu);
    --psx_tracker.cmd.todo;
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);
}

long int psx_syscall3(long int syscall_nr,
		      long int arg1, long int arg2, long int arg3) {
    return psx_syscall(syscall_nr, arg1, arg2, arg3);
}

long int psx_syscall6(long int syscall_nr,
		      long int arg1, long int arg2, long int arg3,
		      long int arg4, long int arg5, long int arg6) {
    return psx_syscall(syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6);
}

/*
 * psx_signal_start initializes the signal handler as a constructor
 * using a linker trick. This runs before Go has a chance to mess with
 * all the signal handlers. The constructor index is the priority we
 * can use without generating a linker complaint.
 */
static void psx_signal_start(void) {
    /*
     * glibc nptl picks from the SIGRTMIN end, so we pick from the
     * SIGRTMAX end
     */
    psx_tracker.psx_sig = SIGRTMAX;
    psx_tracker.sig_action.sa_sigaction = psx_posix_syscall_actor;
    sigemptyset(&psx_tracker.sig_action.sa_mask);
    psx_tracker.sig_action.sa_flags = SA_SIGINFO | SA_RESTART;;
    sigaction(psx_tracker.psx_sig, &psx_tracker.sig_action, NULL);
}

/*
 * psx_syscall_start initializes the subsystem.
 */
static void psx_syscall_start(void) {
    psx_tracker.initialized = 1;
    psx_signal_start();
}

static void psx_do_registration(pthread_t thread) {
    int first_time = !psx_tracker.initialized;
    (void) pthread_once(&psx_tracker_initialized, psx_syscall_start);

    if (first_time) {
	/* First invocation, use recursion to register main() thread. */
	psx_do_registration(pthread_self());
    }

    registered_thread_t *node = calloc(1, sizeof(registered_thread_t));
    node->next = psx_tracker.root;
    if (node->next) {
	node->next->prev = node;
    }
    node->thread = thread;
    psx_tracker.root = node;
}

/*
 * psx_register registers the a thread as pariticipating in the single
 * (POSIX) pool of privilege used by the library.
 *
 * In normal, expected, use you should never need to call this because
 * the linker magic wrapping will arrange for this function to be
 * called implicitly every time a pthread is created with
 * pthread_create() or psx_pthread_create(). If, however, you are
 * unable to use the linker trick to wrap pthread_create(), you should
 * include this line in one and only one place in your code. Just
 * after the end of the main() function would be a good place, for
 * example:
 *
 *   int main(int argc, char **argv) {

 *      ...
 *   }
 *
 *   PSX_NO_LINKER_WRAPPING
 *
 * This is required for libpsx to link. It also requires the coder to
 * explicitly use psx_register() for all threads not started with
 * psx_pthread_create().
 *
 * Note, there is no need to ever register the main() process thread.
 */
void psx_register(pthread_t thread) {
    pthread_mutex_lock(&psx_tracker.state_mu);
    psx_do_registration(thread);
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);
}

/* provide a prototype */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			  void *(*start_routine) (void *), void *arg);

/*
 * psx_wait_for_idle waits for the psx_tracker to become idle and then
 * announces a thread creation is in progress.
 */
static void psx_wait_for_idle(void) {
    psx_tracker_state_t state;
    sigset_t old;
    int unblocked = 0;

    pthread_mutex_lock(&psx_tracker.state_mu);
    for (;;) {
	state = psx_tracker.state;
	if (state == _PSX_IDLE) {
	    if (unblocked) {
		pthread_sigmask(SIG_BLOCK, &old, NULL);
	    }
	    psx_tracker.state = _PSX_CREATE;
	    break;
	}
	if (state == _PSX_SYSCALL && !unblocked) {
	    /*
	     * We may have signals blocked, in which case we
	     * atomically unblock that signal and wait for the syscall
	     * to complete. This will cause the current thread to
	     * perform the signal handling.
	     */
	    sigset_t new;
	    sigemptyset(&new);
	    sigaddset(&new, psx_tracker.psx_sig);
	    pthread_cond_broadcast(&psx_tracker.cond);
	    pthread_mutex_unlock(&psx_tracker.state_mu);

	    pthread_sigmask(SIG_UNBLOCK, &new, &old);
	    unblocked = 1;

	    pthread_mutex_lock(&psx_tracker.state_mu);
	}
	pthread_cond_wait(&psx_tracker.cond, &psx_tracker.state_mu);
    }
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);
}

/*
 * psx_resume_idle announces completion of a thread creation by
 * restoring the psx_tracker state to idle.
 */
static void psx_resume_idle(void) {
    pthread_mutex_lock(&psx_tracker.state_mu);
    psx_tracker.state = _PSX_IDLE;
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);
}

/*
 * psx_pthread_create is a wrapper for pthread_create() that registers
 * the newly created thread. If your threads are created already, they
 * can be individually registered with psx_register().
 */
int psx_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
		       void *(*start_routine) (void *), void *arg) {
    if (pthread_create == __wrap_pthread_create) {
	return __wrap_pthread_create(thread, attr, start_routine, arg);
    }

    psx_wait_for_idle();
    int ret = pthread_create(thread, attr, start_routine, arg);
    if (ret != -1) {
	psx_do_registration(*thread);
    }
    psx_resume_idle();
    return ret;
}

/*
 * __wrap_pthread_create is the wrapped destination of all regular
 * pthread_create calls.
 */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			  void *(*start_routine) (void *), void *arg) {
    psx_wait_for_idle();
    int ret = __real_pthread_create(thread, attr, start_routine, arg);
    if (ret != -1) {
	psx_do_registration(*thread);
    }
    psx_resume_idle();
    return ret;
}

/*
 * __psx_syscall performs the syscall on the current thread and if no
 * error is detected it ensures that the syscall is also performed on
 * all (other) registered threads. The return code is the value for
 * the first invocation. It uses a trick to figure out how many
 * arguments the user has supplied. The other half of the trick is
 * provided by the macro psx_syscall() in the <sys/psx_syscall.h>
 * file. The trick is the 7th optional argument (8th over all) to
 * __psx_syscall is the count of arguments supplied to psx_syscall.
 *
 * User:
 *                       psx_syscall(nr, a, b);
 * Expanded by macro to:
 *                       __psx_syscall(nr, a, b, 6, 5, 4, 3, 2, 1, 0);
 * The eighth arg is now ------------------------------------^
 */
long int __psx_syscall(long int syscall_nr, ...) {
    long int arg[7];
    int i;

    va_list aptr;
    va_start(aptr, syscall_nr);
    for (i = 0; i < 7; i++) {
	arg[i] = va_arg(aptr, long int);
    }
    va_end(aptr);

    int count = arg[6];
    if (count < 0 || count > 6) {
	errno = EINVAL;
	return -1;
    }

    long int ret;

    pthread_mutex_lock(&psx_tracker.state_mu);
    while (psx_tracker.state != _PSX_IDLE) {
	pthread_cond_wait(&psx_tracker.cond, &psx_tracker.state_mu);
    }
    psx_tracker.state = _PSX_SETUP;
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);

    psx_tracker.cmd.syscall_nr = syscall_nr;
    psx_tracker.cmd.arg1 = count > 0 ? arg[0] : 0;
    psx_tracker.cmd.arg2 = count > 1 ? arg[1] : 0;
    psx_tracker.cmd.arg3 = count > 2 ? arg[2] : 0;
    if (count > 3) {
	psx_tracker.cmd.six = 1;
	psx_tracker.cmd.arg1 = arg[3];
	psx_tracker.cmd.arg2 = count > 4 ? arg[4] : 0;
	psx_tracker.cmd.arg3 = count > 5 ? arg[5] : 0;

	ret = syscall(syscall_nr,
		      psx_tracker.cmd.arg1,
		      psx_tracker.cmd.arg2,
		      psx_tracker.cmd.arg3,
		      psx_tracker.cmd.arg4,
		      psx_tracker.cmd.arg5,
		      psx_tracker.cmd.arg6);
    } else {
	psx_tracker.cmd.six = 0;

	ret = syscall(syscall_nr,
		      psx_tracker.cmd.arg1,
		      psx_tracker.cmd.arg2,
		      psx_tracker.cmd.arg3);
    }

    if (ret == -1 || !psx_tracker.initialized) {
	goto defer;
    }

    int restore_errno = errno;

    pthread_mutex_lock(&psx_tracker.state_mu);
    psx_tracker.state = _PSX_SYSCALL;
    psx_tracker.cmd.active = 1;
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);

    pthread_t self = pthread_self();
    registered_thread_t *next = NULL, *ref;
    for (ref = psx_tracker.root; ref; ref = next) {
	next = ref->next;
	if (ref->thread == self) {
	    continue;
	}
	pthread_mutex_lock(&psx_tracker.state_mu);
	psx_tracker.cmd.todo++;
	pthread_cond_broadcast(&psx_tracker.cond);
	pthread_mutex_unlock(&psx_tracker.state_mu);
	if (pthread_kill(ref->thread, psx_tracker.psx_sig) == 0) {
	    continue;
	}
	/*
	 * need to remove now invalid thread id from linked list
	 */
	pthread_mutex_lock(&psx_tracker.state_mu);
	psx_tracker.cmd.todo--;
	if (ref == psx_tracker.root) {
	    psx_tracker.root = next;
	} else if (ref->prev) {
	    ref->prev->next = next;
	}
	if (next) {
	    next->prev = ref->prev;
	}
	pthread_cond_broadcast(&psx_tracker.cond);
	pthread_mutex_unlock(&psx_tracker.state_mu);
	free(ref);
    }

    pthread_mutex_lock(&psx_tracker.state_mu);
    while (psx_tracker.cmd.todo) {
	pthread_cond_wait(&psx_tracker.cond, &psx_tracker.state_mu);
    }
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);

    errno = restore_errno;

defer:
    pthread_mutex_lock(&psx_tracker.state_mu);
    psx_tracker.state = _PSX_IDLE;
    psx_tracker.cmd.active = 0;
    pthread_cond_broadcast(&psx_tracker.cond);
    pthread_mutex_unlock(&psx_tracker.state_mu);

    return ret;
}
