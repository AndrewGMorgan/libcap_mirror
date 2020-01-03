/*
 * Copyright (c) 1999,2007,2019 Andrew G. Morgan <morgan@kernel.org>
 *
 * The purpose of this module is to enforce inheritable, bounding and
 * ambient capability sets for a specified user.
 */

/* #define DEBUG */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <linux/limits.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#define USER_CAP_FILE           "/etc/security/capability.conf"
#define CAP_FILE_BUFFER_SIZE    4096
#define CAP_FILE_DELIMITERS     " \t\n"

struct pam_cap_s {
    int debug;
    const char *user;
    const char *conf_filename;
};

/*
 * load_groups obtains the list all of the groups associated with the
 * requested user: gid & supplemental groups.
 */
static int load_groups(const char *user, char ***groups, int *groups_n) {
    struct passwd *pwd;
    gid_t grps[NGROUPS_MAX];
    int ngrps = NGROUPS_MAX;

    *groups = NULL;
    *groups_n = 0;

    pwd = getpwnam(user);
    if (pwd == NULL) {
	return -1;
    }

    /* must include at least pwd->pw_gid, hence < 1 test. */
    if (getgrouplist(user, pwd->pw_gid, grps, &ngrps) < 1) {
	return -1;
    }

    *groups = calloc(ngrps, sizeof(char *));
    int g_n = 0, i;
    for (i = 0; i < ngrps; i++) {
	const struct group *g = getgrgid(grps[i]);
	if (g == NULL) {
	    continue;
	}
	D(("noting [%s] is a member of [%s]", user, g->gr_name));
	(*groups)[g_n++] = strdup(g->gr_name);
    }

    *groups_n = g_n;
    return 0;
}

/* obtain the inheritable capabilities for the current user */

static char *read_capabilities_for_user(const char *user, const char *source)
{
    char *cap_string = NULL;
    char buffer[CAP_FILE_BUFFER_SIZE], *line;
    char **groups;
    int groups_n;
    FILE *cap_file;

    if (load_groups(user, &groups, &groups_n)) {
	D(("unknown user [%s]", user));
	return NULL;
    }

    cap_file = fopen(source, "r");
    if (cap_file == NULL) {
	D(("failed to open capability file"));
	goto defer;
    }

    int found_one = 0;
    while (!found_one &&
	   (line = fgets(buffer, CAP_FILE_BUFFER_SIZE, cap_file))) {
	const char *cap_text;

	char *next = NULL;
	cap_text = strtok_r(line, CAP_FILE_DELIMITERS, &next);

	if (cap_text == NULL) {
	    D(("empty line"));
	    continue;
	}
	if (*cap_text == '#') {
	    D(("comment line"));
	    continue;
	}

	/*
	 * Explore whether any of the ids are a match for the current
	 * user.
	 */
	while ((line = strtok_r(next, CAP_FILE_DELIMITERS, &next))) {
	    if (strcmp("*", line) == 0) {
		D(("wildcard matched"));
		found_one = 1;
		break;
	    }

	    if (strcmp(user, line) == 0) {
		D(("exact match for user"));
		found_one = 1;
		break;
	    }

	    if (line[0] != '@') {
		D(("user [%s] is not [%s] - skipping", user, line));
	    }

	    int i;
	    for (i=0; i < groups_n; i++) {
		if (!strcmp(groups[i], line+1)) {
		    D(("user group matched [%s]", line));
		    found_one = 1;
		    break;
		}
	    }
	    if (found_one) {
		break;
	    }
	}

	if (found_one) {
	    cap_string = strdup(cap_text);
	    D(("user [%s] matched - caps are [%s]", user, cap_string));
	}

	cap_text = NULL;
	line = NULL;
    }

    fclose(cap_file);

defer:
    memset(buffer, 0, CAP_FILE_BUFFER_SIZE);

    int i;
    for (i = 0; i < groups_n; i++) {
	char *g = groups[i];
	_pam_overwrite(g);
	_pam_drop(g);
    }
    if (groups != NULL) {
	memset(groups, 0, groups_n * sizeof(char *));
	_pam_drop(groups);
    }

    return cap_string;
}

/*
 * Set capabilities for current process to match the current
 * permitted+executable sets combined with the configured inheritable
 * set.
 */
static int set_capabilities(struct pam_cap_s *cs)
{
    cap_t cap_s;
    char *conf_caps;
    int ok = 0;
    int has_ambient = 0, has_bound = 0;
    int *bound = NULL, *ambient = NULL;
    cap_flag_value_t had_setpcap = 0;
    cap_value_t max_caps = 0;
    const cap_value_t wanted_caps[] = { CAP_SETPCAP };

    cap_s = cap_get_proc();
    if (cap_s == NULL) {
	D(("your kernel is capability challenged - upgrade: %s",
	   strerror(errno)));
	return 0;
    }
    if (cap_get_flag(cap_s, CAP_SETPCAP, CAP_EFFECTIVE, &had_setpcap)) {
	D(("failed to read a e capability: %s", strerror(errno)));
	goto cleanup_cap_s;
    }
    if (cap_set_flag(cap_s, CAP_EFFECTIVE, 1, wanted_caps, CAP_SET) != 0) {
	D(("unable to raise CAP_SETPCAP: %s", strerrno(errno)));
	goto cleanup_cap_s;
    }

    conf_caps =	read_capabilities_for_user(cs->user,
					   cs->conf_filename
					   ? cs->conf_filename:USER_CAP_FILE );
    if (conf_caps == NULL) {
	D(("no capabilities found for user [%s]", cs->user));
	goto cleanup_cap_s;
    }

    ssize_t conf_caps_length = strlen(conf_caps);
    if (!strcmp(conf_caps, "all")) {
	/*
	 * all here is interpreted as no change/pass through, which is
	 * likely to be the same as none for sensible system defaults.
	 */
	ok = 1;
	goto cleanup_caps;
    }

    if (cap_set_proc(cap_s) != 0) {
	D(("unable to use CAP_SETPCAP: %s", strerrno(errno)));
	goto cleanup_caps;
    }
    if (cap_reset_ambient() == 0) {
	/* Ambient set fully declared by this config. */
	has_ambient = 1;
    }

    if (!strcmp(conf_caps, "none")) {
	/* clearing CAP_INHERITABLE will also clear the ambient caps. */
	cap_clear_flag(cap_s, CAP_INHERITABLE);
    } else {
	/*
	 * we know we have to perform some capability operations and
	 * we need to know how many capabilities there are to do it
	 * successfully.
	 */
	while (cap_get_bound(max_caps) >= 0) {
	    max_caps++;
	}
	if (max_caps != cap_max_bits()) {
	    D(("this vintage of libcap cannot be trusted; give up"));
	    goto cleanup_caps;
	}
	has_bound = (max_caps != 0);
	if (has_bound) {
	    bound = calloc(max_caps, sizeof(int));
	    if (has_ambient) {
		/* In kernel lineage, bound came first. */
		ambient = calloc(max_caps, sizeof(int));
	    }
	}

	/*
	 * Scan the configured capability string for:
	 *
	 *   cap_name: add to cap_s' inheritable vector
	 *   ^cap_name: add to cap_s' inheritable vector and ambient set
	 *   !cap_name: drop from bounding set
	 *
	 * Setting ambient capabilities requires that we first enable
	 * the corresponding inheritable capability to set them. So,
	 * there is an order we use: parse the config line, building
	 * the inheritable, ambient and bounding sets in three separate
	 * arrays. Then, set I set A set B. Finally, at the end, we
	 * restore the E value for CAP_SETPCAP.
	 */
	char *token = NULL;
	char *next = conf_caps;
	while ((token = strtok_r(next, ",", &next))) {
	    if (strlen(token) < 4) {
		D(("bogus cap: [%s] - ignored\n", token));
		goto cleanup_caps;
	    }
	    int is_a = 0, is_b = 0;
	    if (*token == '^') {
		if (!has_ambient) {
		    D(("want ambient [%s] but kernel has no support", token));
		    goto cleanup_caps;
		}
		is_a = 1;
		token++;
	    } else if (*token == '!') {
		if (!has_bound) {
		    D(("want bound [%s] dropped - no kernel support", token));
		}
		is_b = 1;
		token++;
	    }

	    cap_value_t c;
	    if (cap_from_name(token, &c) != 0) {
		D(("unrecognized name [%s]: %s - ignored", token,
		   strerror(errno)));
		goto cleanup_caps;
	    }

	    if (is_b) {
		bound[c] = 1;
	    } else {
		if (cap_set_flag(cap_s, CAP_INHERITABLE, 1, &c, CAP_SET)) {
		    D(("failed to raise inheritable [%s]: %s", token,
		       strerror(errno)));
		    goto cleanup_caps;
		}
		if (is_a) {
		    ambient[c] = 1;
		}
	    }
	}

#ifdef DEBUG
	{
	    char *temp = cap_to_text(cap_s, NULL);
	    D(("abbreviated caps for process will be [%s]", temp));
	    cap_free(temp);
	}
#endif /* DEBUG */
    }

    if (cap_set_proc(cap_s)) {
	D(("failed to set specified capabilities: %s", strerror(errno)));
    } else {
	cap_value_t c;
	for (c = 0; c < max_caps; c++) {
	    if (ambient != NULL && ambient[c]) {
		cap_set_ambient(c, CAP_SET);
	    }
	    if (bound != NULL && bound[c]) {
		cap_drop_bound(c);
	    }
	}
	ok = 1;
    }

cleanup_caps:
    if (has_ambient) {
	memset(ambient, 0, max_caps * sizeof(*ambient));
	_pam_drop(ambient);
	ambient = NULL;
    }
    if (has_bound) {
	memset(bound, 0, max_caps * sizeof(*bound));
	_pam_drop(bound);
	bound = NULL;
    }
    memset(conf_caps, 0, conf_caps_length);
    _pam_drop(conf_caps);

cleanup_cap_s:
    if (!had_setpcap) {
	/* Only need to lower if it wasn't raised by caller */
	if (!cap_set_flag(cap_s, CAP_EFFECTIVE, 1, wanted_caps,
			  CAP_CLEAR)) {
	    cap_set_proc(cap_s);
	}
    }
    if (cap_s) {
	cap_free(cap_s);
	cap_s = NULL;
    }
    return ok;
}

/* log errors */

static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog("pam_cap", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

static void parse_args(int argc, const char **argv, struct pam_cap_s *pcs)
{
    /* step through arguments */
    for (; argc-- > 0; ++argv) {
	if (!strcmp(*argv, "debug")) {
	    pcs->debug = 1;
	} else if (!strncmp(*argv, "config=", 7)) {
	    pcs->conf_filename = 7 + *argv;
	} else {
	    _pam_log(LOG_ERR, "unknown option; %s", *argv);
	}
    }
}

/*
 * pam_sm_authenticate parses the config file with respect to the user
 * being authenticated and determines if they are covered by any
 * capability inheritance rules.
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
    int retval;
    struct pam_cap_s pcs;
    char *conf_caps;

    memset(&pcs, 0, sizeof(pcs));
    parse_args(argc, argv, &pcs);

    retval = pam_get_user(pamh, &pcs.user, NULL);
    if (retval == PAM_CONV_AGAIN) {
	D(("user conversation is not available yet"));
	memset(&pcs, 0, sizeof(pcs));
	return PAM_INCOMPLETE;
    }

    if (retval != PAM_SUCCESS) {
	D(("pam_get_user failed: %s", pam_strerror(pamh, retval)));
	memset(&pcs, 0, sizeof(pcs));
	return PAM_AUTH_ERR;
    }

    conf_caps =	read_capabilities_for_user(pcs.user,
					   pcs.conf_filename
					   ? pcs.conf_filename:USER_CAP_FILE );
    memset(&pcs, 0, sizeof(pcs));

    if (conf_caps) {
	D(("it appears that there are capabilities for this user [%s]",
	   conf_caps));

	/* We could also store this as a pam_[gs]et_data item for use
	   by the setcred call to follow. As it is, there is a small
	   race associated with a redundant read. Oh well, if you
	   care, send me a patch.. */

	_pam_overwrite(conf_caps);
	_pam_drop(conf_caps);

	return PAM_SUCCESS;

    } else {

	D(("there are no capabilities restrctions on this user"));
	return PAM_IGNORE;

    }
}

/*
 * pam_sm_setcred applies inheritable capabilities loaded by the
 * pam_sm_authenticate pass for the user.
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    int retval;
    struct pam_cap_s pcs;

    if (!(flags & PAM_ESTABLISH_CRED)) {
	D(("we don't handle much in the way of credentials"));
	return PAM_IGNORE;
    }

    memset(&pcs, 0, sizeof(pcs));
    parse_args(argc, argv, &pcs);

    retval = pam_get_item(pamh, PAM_USER, (const void **)&pcs.user);
    if ((retval != PAM_SUCCESS) || (pcs.user == NULL) || !(pcs.user[0])) {
	D(("user's name is not set"));
	return PAM_AUTH_ERR;
    }

    retval = set_capabilities(&pcs);
    memset(&pcs, 0, sizeof(pcs));

    return (retval ? PAM_SUCCESS:PAM_IGNORE );
}
