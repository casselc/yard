/*
 * yard-exec-shim -- the privileged last mile of a per-call child jail
 * (HARNESS.md "Per-call child jail"). yard-spawn (root) forks this; it
 *
 *   1. sets the process audit state (setaudit_addr) -- must precede the
 *      attach: inside a jail the audit syscalls are not permitted, and the
 *      BSM zonename token then names the per-call jail (Phase 0 S7);
 *   2. applies the task login class (rlimits, priority, umask) with
 *      setusercontext() -- also before the attach, so the HOST login.conf.db
 *      is read, not the jail's;
 *   3. attaches with jail_attach(jid), NOT jail_attach_jd(): attach-by-jid
 *      works on release hosts, where jail_attach_jd() leaks a prison
 *      reference (fixed in stable/15, 3584cde63e);
 *   4. chdir, drops to the task uid/gid (and checks it cannot regain root),
 *   5. closes every fd above 2 and execs the command (PATH search inside the jail).
 *
 * usage: yard-exec-shim -j JID -u UID -g GID [-c CLASS] [-a AUID -m MASK] [-d DIR] -- argv...
 *
 * Exit status 120..127 means the shim itself failed at a step; it then prints
 * "yard-exec-shim: <step>: <error>" on stderr.
 */
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/types.h>

#include <bsm/audit.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <login_cap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

enum {
	X_USAGE = 120,
	X_AUDIT = 121,
	X_CLASS = 122,
	X_ATTACH = 123,
	X_CHDIR = 124,
	X_CRED = 125,
	X_EXEC = 127,
};

static void fail(int code, const char *step)
{
	int e = errno;
	fprintf(stderr, "yard-exec-shim: %s: %s\n", step, strerror(e));
	_exit(code);
}

static long num(const char *s, long lo, long hi)
{
	char *end;
	errno = 0;
	long long v = strtoll(s, &end, 0);
	if (errno != 0 || *end != '\0' || v < lo || v > hi) {
		fprintf(stderr, "yard-exec-shim: bad number %s\n", s);
		_exit(X_USAGE);
	}
	return (long)v;
}

int main(int argc, char **argv)
{
	long jid = -1, uid = -1, gid = -1, auid = -1;
	unsigned long mask = 0;
	const char *class = NULL, *dir = "/";
	int ch;

	while ((ch = getopt(argc, argv, "j:u:g:c:a:m:d:")) != -1) {
		switch (ch) {
		case 'j': jid = num(optarg, 1, INT_MAX); break;
		case 'u': uid = num(optarg, 1, UINT_MAX - 1); break;
		case 'g': gid = num(optarg, 1, UINT_MAX - 1); break;
		case 'c': class = optarg; break;
		case 'a': auid = num(optarg, 0, UINT_MAX - 1); break;
		case 'm': mask = (unsigned long)num(optarg, 0, UINT_MAX); break;
		case 'd': dir = optarg; break;
		default: _exit(X_USAGE);
		}
	}
	argc -= optind;
	argv += optind;
	if (jid < 0 || uid < 0 || gid < 0 || argc < 1) {
		fprintf(stderr, "usage: yard-exec-shim -j JID -u UID -g GID [-c CLASS] [-a AUID -m MASK] [-d DIR] -- argv...\n");
		_exit(X_USAGE);
	}
	if (getuid() != 0 || geteuid() != 0) {
		errno = EPERM;
		fail(X_USAGE, "must start as root");
	}

	/* 1. audit state, inherited by everything the call runs */
	if (auid >= 0) {
		auditinfo_addr_t ai;
		memset(&ai, 0, sizeof(ai));
		ai.ai_auid = (au_id_t)auid;
		ai.ai_mask.am_success = (unsigned int)mask;
		ai.ai_mask.am_failure = (unsigned int)mask;
		ai.ai_termid.at_type = AU_IPv4;
		ai.ai_asid = AU_ASSIGN_ASID;
		if (setaudit_addr(&ai, sizeof(ai)) != 0)
			fail(X_AUDIT, "setaudit_addr");
	}

	/* 2. login class resources, priority and umask (host login.conf.db) */
	if (class != NULL) {
		login_cap_t *lc = login_getclass(class);
		if (lc == NULL)
			fail(X_CLASS, "login_getclass");
		if (strcmp(lc->lc_class, class) != 0) {
			errno = ENOENT;
			fail(X_CLASS, "login class not found (got default)");
		}
		if (setusercontext(lc, NULL, (uid_t)uid,
		    LOGIN_SETRESOURCES | LOGIN_SETPRIORITY | LOGIN_SETUMASK) != 0)
			fail(X_CLASS, "setusercontext");
		login_close(lc);
	}

	/* 3. attach by jid */
	if (jail_attach((int)jid) != 0)
		fail(X_ATTACH, "jail_attach");

	/* 4. cwd and credentials */
	if (chdir(dir) != 0)
		fail(X_CHDIR, "chdir");
	gid_t g = (gid_t)gid;
	if (setgroups(1, &g) != 0)
		fail(X_CRED, "setgroups");
	if (setgid(g) != 0)
		fail(X_CRED, "setgid");
	if (setuid((uid_t)uid) != 0)
		fail(X_CRED, "setuid");
	if (getuid() != (uid_t)uid || geteuid() != (uid_t)uid || getgid() != g || getegid() != g)
		fail(X_CRED, "credential check");
	if (setuid(0) == 0) {
		errno = EPERM;
		fail(X_CRED, "regained root");
	}

	/* 5. no inherited descriptors beyond stdio */
	closefrom(3);
	execvp(argv[0], argv);
	fail(X_EXEC, argv[0]);
	return X_EXEC;
}
