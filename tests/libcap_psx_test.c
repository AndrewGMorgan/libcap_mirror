#include <pthread.h>
#include <stdio.h>
#include <sys/capability.h>
#include <sys/psx_syscall.h>

int main(int argc, char **argv) {
    printf("hello libcap and libpsx\n");
    psx_register(pthread_self());
    cap_t start = cap_get_proc();
    cap_set_proc(start);
    return 0;
}
