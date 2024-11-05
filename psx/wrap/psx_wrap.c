#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

extern int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
				 void *(*start_routine) (void *), void *arg);

/*
 * psx requires this function to be provided by the linkage wrapping.
 */
int __attribute__((weak))
__real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
		      void *(*start_routine) (void *), void *arg) {
    fprintf(stderr, "libpsx is not linked correctly\n");
    exit(1);
}
