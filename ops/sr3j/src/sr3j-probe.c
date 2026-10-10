/*
 * sr3j-probe -- SR3J spike: one access attempt per invocation, for the isolation checks of
 * ops/sr3j/sr3j-20-e2e.sh. Unprivileged; never changes anything it does not create itself
 * (vmcreate/vmdestroy act on whatever name they are given -- the test only gives them names
 * it owns, or names it must NOT be able to touch).
 *
 *   sr3j-probe open PATH          open(PATH, O_RDWR)
 *   sr3j-probe read PATH          open(PATH, O_RDONLY)
 *   sr3j-probe vmcreate NAME      ioctl(/dev/vmmctl, VMMCTL_VM_CREATE)
 *   sr3j-probe vmdestroy NAME     ioctl(/dev/vmmctl, VMMCTL_VM_DESTROY)
 *   sr3j-probe sysctl-destroy NAME  sysctlbyname("hw.vmm.destroy", NAME)
 *   sr3j-probe ngctl              socket(PF_NETGRAPH, SOCK_DGRAM, NG_CONTROL)
 *   sr3j-probe ngdata PATH        socket(PF_NETGRAPH, SOCK_DGRAM, NG_DATA) + connect to PATH (e.g. "[1f]:")
 *   sr3j-probe kill PID           kill(PID, 0)
 *   sr3j-probe unix PATH          connect(AF_UNIX stream) to PATH
 *
 * Prints "PROBE <op> <arg> -> OK" or "-> <ENAME> (<n>: <text>)"; exit 0 when the attempt was made.
 */
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>

#include <dev/vmm/vmm_dev.h>
#include <netgraph/ng_socket.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
ename(int e)
{
	static const struct { int e; const char *n; } t[] = {
		{ EPERM, "EPERM" }, { ENOENT, "ENOENT" }, { ESRCH, "ESRCH" }, { ENXIO, "ENXIO" },
		{ EACCES, "EACCES" }, { EBUSY, "EBUSY" }, { EEXIST, "EEXIST" }, { ENOTDIR, "ENOTDIR" },
		{ EINVAL, "EINVAL" }, { ENOTTY, "ENOTTY" }, { EPROTONOSUPPORT, "EPROTONOSUPPORT" },
		{ EAFNOSUPPORT, "EAFNOSUPPORT" }, { EADDRINUSE, "EADDRINUSE" }, { EISCONN, "EISCONN" },
		{ ECONNREFUSED, "ECONNREFUSED" }, { EOPNOTSUPP, "EOPNOTSUPP" }, { ENOTCONN, "ENOTCONN" },
	};
	for (size_t i = 0; i < nitems(t); i++)
		if (t[i].e == e)
			return (t[i].n);
	return ("E?");
}

static int
report(const char *op, const char *arg, int rc)
{
	int e = errno;

	if (rc == 0)
		printf("PROBE %s %s -> OK\n", op, arg);
	else
		printf("PROBE %s %s -> %s (%d: %s)\n", op, arg, ename(e), e, strerror(e));
	return (0);
}

int
main(int argc, char **argv)
{
	const char *op, *arg;
	int fd, rc;

	if (argc < 2) {
		fprintf(stderr, "usage: sr3j-probe OP [ARG]\n");
		return (2);
	}
	op = argv[1];
	arg = argc > 2 ? argv[2] : "-";
	if (strcmp(op, "open") == 0 || strcmp(op, "read") == 0) {
		fd = open(arg, strcmp(op, "open") == 0 ? O_RDWR : O_RDONLY);
		return (report(op, arg, fd < 0 ? -1 : 0));
	}
	if (strcmp(op, "vmcreate") == 0 || strcmp(op, "vmdestroy") == 0) {
		if ((fd = open("/dev/vmmctl", O_RDWR)) < 0)
			return (report(op, "(open /dev/vmmctl)", -1));
		if (strcmp(op, "vmcreate") == 0) {
			struct vmmctl_vm_create c;

			memset(&c, 0, sizeof(c));
			strlcpy(c.name, arg, sizeof(c.name));
			rc = ioctl(fd, VMMCTL_VM_CREATE, &c);
		} else {
			struct vmmctl_vm_destroy d;

			memset(&d, 0, sizeof(d));
			strlcpy(d.name, arg, sizeof(d.name));
			rc = ioctl(fd, VMMCTL_VM_DESTROY, &d);
		}
		return (report(op, arg, rc));
	}
	if (strcmp(op, "sysctl-destroy") == 0)
		return (report(op, arg, sysctlbyname("hw.vmm.destroy", NULL, NULL, arg, strlen(arg) + 1)));
	if (strcmp(op, "ngctl") == 0) {
		fd = socket(PF_NETGRAPH, SOCK_DGRAM, NG_CONTROL);
		return (report(op, arg, fd < 0 ? -1 : 0));
	}
	if (strcmp(op, "ngdata") == 0) {
		struct sockaddr_ng sg;

		if ((fd = socket(PF_NETGRAPH, SOCK_DGRAM, NG_DATA)) < 0)
			return (report(op, "(socket NG_DATA)", -1));
		memset(&sg, 0, sizeof(sg));
		sg.sg_family = AF_NETGRAPH;
		strlcpy(sg.sg_data, arg, sizeof(sg.sg_data));
		sg.sg_len = strlen(sg.sg_data) + 3;
		return (report(op, arg, connect(fd, (struct sockaddr *)&sg, sg.sg_len)));
	}
	if (strcmp(op, "kill") == 0)
		return (report(op, arg, kill((pid_t)strtol(arg, NULL, 10), 0)));
	if (strcmp(op, "unix") == 0) {
		struct sockaddr_un sun;

		if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
			return (report(op, "(socket)", -1));
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		strlcpy(sun.sun_path, arg, sizeof(sun.sun_path));
		sun.sun_len = SUN_LEN(&sun);
		return (report(op, arg, connect(fd, (struct sockaddr *)&sun, sun.sun_len)));
	}
	fprintf(stderr, "sr3j-probe: unknown op %s\n", op);
	return (2);
}
