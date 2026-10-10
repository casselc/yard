/*
 * sr3j-launch -- SR3J spike: start a process as a dedicated VM uid inside a jail, optionally handing it a
 * netgraph data socket that is already connected to a per-VM ng_eiface (bhyve "netgraph,datafd=3").
 *
 * Runs as root (from the SR3J root test script; in production from yard-spawn's privileged side):
 *
 *   1. with -n PATH: NgMkSockNode() creates an ng_socket(4) node (control + data socket), NGM_CONNECT
 *      joins its hook "vmlink" to PATH's hook -h (default "ether", the ng_eiface hook), the control socket
 *      is closed and the data socket becomes fd 3. Creating/connecting nodes needs PRIV_NETGRAPH_CONTROL;
 *      using the data socket afterwards does not, so the privilege never reaches the unprivileged side.
 *      The node lives exactly as long as the data socket: when bhyve exits (suspend, poweroff, crash) the
 *      node shuts down and the eiface's hook is free for the next bhyve (restore). A second launch while
 *      the first bhyve still holds the hook fails at NGM_CONNECT (EISCONN): never two VMs on one eiface.
 *      -I FILE writes the node's address "[id]:" to FILE (the isolation test aims at it).
 *   2. jail_attach(JID), chdir(DIR), setgroups/setgid/setuid to GID/UID, refuses to continue if root
 *      can be regained, umask 077, closes every fd above 2 (above 3 with -n), a fixed minimal
 *      environment, execvp(argv) (PATH search inside the jail).
 *
 * Why exec-with-inherited-fd and not SCM_RIGHTS to a running unprivileged launcher: the fd exists only
 * in this process and then in bhyve (same process image after execve); there is no long-lived
 * privileged daemon, no socket to authenticate peers on, and no window in which another uid could
 * receive the descriptor.
 *
 * usage: sr3j-launch -j JID -u UID -g GID [-d DIR] [-n NGPATH [-h HOOK] [-I FILE]] -- argv...
 * Exit status 120..127 = the launcher failed at a step ("sr3j-launch: <step>: <error>" on stderr).
 */
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netgraph.h>
#include <netgraph/ng_message.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static char *minenv[] = { "PATH=/usr/local/yard/sr3j:/sbin:/bin:/usr/sbin:/usr/bin", "HOME=/", NULL };

enum { X_USAGE = 120, X_NG = 121, X_ATTACH = 123, X_CHDIR = 124, X_CRED = 125, X_EXEC = 127 };

static void __dead2
fail(int code, const char *step)
{
	int e = errno;

	fprintf(stderr, "sr3j-launch: %s: %s\n", step, strerror(e));
	_exit(code);
}

static long
num(const char *s, long lo, long hi)
{
	char *end;
	long long v;

	errno = 0;
	v = strtoll(s, &end, 0);
	if (errno != 0 || *end != '\0' || v < lo || v > hi) {
		fprintf(stderr, "sr3j-launch: bad number %s\n", s);
		_exit(X_USAGE);
	}
	return ((long)v);
}

int
main(int argc, char **argv)
{
	long jid = -1, uid = -1, gid = -1;
	const char *dir = "/", *ngpath = NULL, *hook = "ether", *idfile = NULL;
	int ch, keep = 2;

	while ((ch = getopt(argc, argv, "j:u:g:d:n:h:I:")) != -1) {
		switch (ch) {
		case 'j': jid = num(optarg, 1, INT_MAX); break;
		case 'u': uid = num(optarg, 1, UINT_MAX - 1); break;
		case 'g': gid = num(optarg, 1, UINT_MAX - 1); break;
		case 'd': dir = optarg; break;
		case 'n': ngpath = optarg; break;
		case 'h': hook = optarg; break;
		case 'I': idfile = optarg; break;
		default: _exit(X_USAGE);
		}
	}
	argc -= optind;
	argv += optind;
	if (jid < 0 || uid < 0 || gid < 0 || argc < 1) {
		fprintf(stderr, "usage: sr3j-launch -j JID -u UID -g GID [-d DIR] [-n NGPATH [-h HOOK] [-I FILE]] -- argv...\n");
		_exit(X_USAGE);
	}
	if (getuid() != 0 || geteuid() != 0) {
		fprintf(stderr, "sr3j-launch: must run as root\n");
		_exit(X_USAGE);
	}

	if (ngpath != NULL) {
		struct ngm_connect ngc;
		struct ng_mesg *resp;
		int cs, ds;

		if (strlen(ngpath) >= NG_PATHSIZ || strlen(hook) >= NG_HOOKSIZ) {
			fprintf(stderr, "sr3j-launch: netgraph path or hook too long\n");
			_exit(X_USAGE);
		}
		if (NgMkSockNode(NULL, &cs, &ds) < 0)
			fail(X_NG, "NgMkSockNode");
		memset(&ngc, 0, sizeof(ngc));
		strlcpy(ngc.path, ngpath, sizeof(ngc.path));
		strlcpy(ngc.ourhook, "vmlink", sizeof(ngc.ourhook));
		strlcpy(ngc.peerhook, hook, sizeof(ngc.peerhook));
		if (NgSendMsg(cs, ".", NGM_GENERIC_COOKIE, NGM_CONNECT, &ngc, sizeof(ngc)) < 0)
			fail(X_NG, "NGM_CONNECT");
		if (idfile != NULL) {
			FILE *f;

			if (NgSendMsg(cs, ".", NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0) < 0 ||
			    NgAllocRecvMsg(cs, &resp, NULL) < 0)
				fail(X_NG, "NGM_NODEINFO");
			if ((f = fopen(idfile, "w")) == NULL)
				fail(X_NG, idfile);
			fprintf(f, "[%x]:\n", ((struct nodeinfo *)resp->data)->id);
			fclose(f);
			free(resp);
		}
		close(cs);
		if (ds != 3) {
			if (dup2(ds, 3) < 0)
				fail(X_NG, "dup2");
			close(ds);
		}
		keep = 3;
	}

	if (jail_attach((int)jid) != 0)
		fail(X_ATTACH, "jail_attach");
	if (chdir(dir) != 0)
		fail(X_CHDIR, "chdir");
	{
		gid_t g = (gid_t)gid;

		if (setgroups(1, &g) != 0)
			fail(X_CRED, "setgroups");
	}
	if (setgid((gid_t)gid) != 0)
		fail(X_CRED, "setgid");
	if (setuid((uid_t)uid) != 0)
		fail(X_CRED, "setuid");
	if (setuid(0) == 0 || geteuid() == 0 || getegid() == 0) {
		errno = EPERM;
		fail(X_CRED, "could regain root");
	}
	umask(077);
	closefrom(keep + 1);
	/* env must outlive this scope: execvp reads environ (a block-scoped array here was dead by then; SIGSEGV) */
	environ = minenv;
	execvp(argv[0], argv);
	fail(X_EXEC, argv[0]);
}
