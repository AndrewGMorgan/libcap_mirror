/*
 * Copyright (c) 1997,2008 Andrew G. Morgan  <morgan@kernel.org>
 *
 * This displays the capabilities of given target process(es).
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/capability.h>

static void usage(int code)
{
    fprintf(stderr,
"usage: getcaps <pid> [<pid> ...]\n\n"
"  This program displays the capabilities on the queried process(es).\n"
	    "  The capabilities are displayed in the cap_from_text(3) format.\n"
	    "\n"
	    "  Optional arguments:\n"
	    "     --help, -h or --usage display this message.\n"
	    "     --verbose             use a more verbose output format.\n"
	    "     --ugly or --legacy    use the archaic legacy output format.\n"
	    "     --iab                 show IAB of process too.\n"
	    "     --license             display license info\n");
    exit(code);
}

int main(int argc, char **argv)
{
    int retval = 0;
    int verbose = 0;
    int iab = 0;
    cap_iab_t noiab = cap_iab_init();

    if (argc < 2) {
	usage(1);
    }

    for ( ++argv; --argc > 0; ++argv ) {
	long lpid;
	int pid;
	char *endarg;
	cap_t cap_d;

	if (!strcmp(argv[0], "--help") || !strcmp(argv[0], "--usage") ||
	    !strcmp(argv[0], "-h")) {
	    usage(0);
	} else if (!strcmp(argv[0], "--license")) {
	    printf("%s see LICENSE file for details.\n"
		   "[Copyright (c) 1997-8,2007,19,21"
		   " Andrew G. Morgan <morgan@kernel.org>]\n",
		   argv[0]);
	    exit(0);
	} else if (!strcmp(argv[0], "--verbose")) {
	    verbose = 1;
	    continue;
	} else if (!strcmp(argv[0], "--ugly") || !strcmp(argv[0], "--legacy")) {
	    verbose = 2;
	    continue;
	} else if (!strcmp(argv[0], "--iab")) {
	    iab = 1;
	    continue;
	}

	errno = 0;
	lpid = strtol(argv[0], &endarg, 10);
	if (*endarg != '\0') {
	    errno = EINVAL;
	}
	if (errno == 0) {
	    if (lpid < 0 || pid != (pid_t) pid)
		errno = EOVERFLOW;
	}
	if (errno != 0) {
	    fprintf(stderr, "Cannot parse pid %s (%s)\n",
		    argv[0], strerror(errno));
	    retval = 1;
	    continue;
	}
	pid = lpid;

	cap_d = cap_get_pid(pid);
	if (cap_d == NULL) {
		fprintf(stderr, "Failed to get cap's for process %d:"
			" (%s)\n", pid, strerror(errno));
		retval = 1;
		continue;
	} else {
	    char *result = cap_to_text(cap_d, NULL);
	    if (iab) {
		printf("%s:", *argv);
		if (verbose || strcmp("=", result) != 0) {
		    printf(" \"%s\"", result);
		}
		cap_iab_t iab_val = cap_iab_get_pid(pid);
		if (iab_val == NULL) {
		    fprintf(stderr, " no IAB value for %d\n", pid);
		    exit(1);
		}
		int cf = cap_iab_compare(noiab, iab_val);
		if (verbose ||
		    CAP_IAB_DIFFERS(cf, CAP_IAB_AMB) ||
		    CAP_IAB_DIFFERS(cf, CAP_IAB_BOUND)) {
		    char *iab_text = cap_iab_to_text(iab_val);
		    if (iab_text == NULL) {
			perror(" no text for IAB");
			exit(1);
		    }
		    printf(" [%s]", iab_text);
		    cap_free(iab_text);
		}
		cap_free(iab_val);
		printf("\n");
	    } else if (verbose == 1) {
		printf("Capabilities for '%s': %s\n", *argv, result);
	    } else if (verbose == 2) {
		fprintf(stderr, "Capabilities for `%s': %s\n", *argv, result);
	    } else {
		printf("%s: %s\n", *argv, result);
	    }
	    cap_free(result);
	    result = NULL;
	    cap_free(cap_d);
	}
    }

    return retval;
}
