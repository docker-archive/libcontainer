#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <linux/limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <sched.h>
#include <signal.h>

/* All arguments should be above stack, because it grows down */
struct clone_arg {
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place
	 */
	char stack[4096] __attribute__ ((aligned(8)));
	char stack_ptr[0];
	jmp_buf *env;
};

#define pr_perror(fmt, ...) fprintf(stderr, "nsenter: " fmt ": %m\n", ##__VA_ARGS__)

static int child_func(void *_arg)
{
	struct clone_arg *arg = (struct clone_arg *)_arg;
	longjmp(*arg->env, 1);
}

// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#define _GNU_SOURCE
#include "syscall.h"
#if defined(__NR_setns) && !defined(SYS_setns)
#define SYS_setns __NR_setns
#endif
#ifdef SYS_setns
int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif
#endif

static int clone_parent(jmp_buf * env) __attribute__ ((noinline));
static int clone_parent(jmp_buf * env)
{
	struct clone_arg ca;
	int child;

	ca.env = env;
	child = clone(child_func, ca.stack_ptr, CLONE_PARENT | SIGCHLD, &ca);

	return child;
}

// namespacesLength returns the number of additional namespaces to setns. The
// argument is a comma-separated string of namespace paths.
static int namespacesLength(char *nspaths)
{
	int size = 0, i = 0;
	for (i = 0; nspaths[i]; i++) {
		if (nspaths[i] == ',') {
			size += 1;
		}
	}
	return size + 1;
}

void nsexec()
{
	jmp_buf env;
	char buf[PATH_MAX], *val, *nspaths;
	int nsLen, child, len, pipenum, consolefd = -1;
	char *console;

	// _LIBCONTAINER_NSPATH if exists is a comma-separated list of namespaces
	// paths that the process should join.
	nspaths = getenv("_LIBCONTAINER_NSPATH");
	if (nspaths == NULL) {
		return;
	}
	// get the init pipe to communicate with parent
	val = getenv("_LIBCONTAINER_INITPIPE");
	if (val == NULL) {
		pr_perror("Child pipe not found");
		exit(1);
	}
	pipenum = atoi(val);
	snprintf(buf, sizeof(buf), "%d", pipenum);
	if (strcmp(val, buf)) {
		pr_perror("Unable to parse _LIBCONTAINER_INITPIPE");
		exit(1);
	}
	// get the console path before setns because it may change mnt namespace
	console = getenv("_LIBCONTAINER_CONSOLE_PATH");
	if (console != NULL) {
		consolefd = open(console, O_RDWR);
		if (consolefd < 0) {
			pr_perror("Failed to open console %s", console);
			exit(1);
		}
	}
	// open all namespaces' descriptors and perform setns on them
	nsLen = namespacesLength(nspaths);
	if (nsLen == 0) {
		return;
	}
	int fds[nsLen];
	char *nsList[nsLen];
	int i, j, savedErr = -1;
	char *ns, *saveptr;
	for (i = 0; i < nsLen; i++) {
		ns = strtok_r(nspaths, ",", &saveptr);
		if (ns == NULL) {
			break;
		}
		fds[i] = open(ns, O_RDONLY);
		if (fds[i] == -1) {
			savedErr = errno;
			// failed to open a particular path, we need to close all opened
			// file descriptors
			for (j = 0; j < i; j++) {
				close(fds[j]);
			}
			errno = savedErr;
			pr_perror("Failed to open %s", ns);
			exit(1);
		}
		nsList[i] = ns;
		nspaths = NULL;
	}
	for (i = 0; i < nsLen; i++) {
		if (fds[i] != -1 && setns(fds[i], 0) != 0) {
			savedErr = errno;
			// failed to setns, we need to close all opended file descriptors
			for (j = 0; j < nsLen; j++) {
				close(fds[j]);
			}
			errno = savedErr;
			pr_perror("Failed to setns to %s", nsList[i]);
			exit(1);
		}
		close(fds[i]);
	}
	// if we dont need to clone, then just let the Go runtime take over
	val = getenv("_LIBCONTAINER_DOCLONE");
	if (val == NULL || strcmp(val, "true") != 0) {
		return;
	}

	if (setjmp(env) == 1) {
		// Child
		val = getenv("_LIBCONTAINER_SETSID");
		if (val != NULL && strcmp(val, "true") == 0) {
			if (setsid() == -1) {
				pr_perror("setsid failed");
				exit(1);
			}
		}

		if (consolefd != -1) {
			if (ioctl(consolefd, TIOCSCTTY, 0) == -1) {
				pr_perror("ioctl TIOCSCTTY failed");
				exit(1);
			}
			if (dup3(consolefd, STDIN_FILENO, 0) != STDIN_FILENO) {
				pr_perror("Failed to dup 0");
				exit(1);
			}
			if (dup3(consolefd, STDOUT_FILENO, 0) != STDOUT_FILENO) {
				pr_perror("Failed to dup 1");
				exit(1);
			}
			if (dup3(consolefd, STDERR_FILENO, 0) != STDERR_FILENO) {
				pr_perror("Failed to dup 2");
				exit(1);
			}
		}
		// Finish executing, let the Go runtime take over.
		return;
	}
	// Parent

	// We must fork to actually enter the PID namespace, use CLONE_PARENT
	// so the child can have the right parent, and we don't need to forward
	// the child's exit code or resend its death signal.
	child = clone_parent(&env);
	if (child < 0) {
		pr_perror("Unable to fork");
		exit(1);
	}

	len = snprintf(buf, sizeof(buf), "{ \"pid\" : %d }\n", child);

	if (write(pipenum, buf, len) != len) {
		pr_perror("Unable to send a child pid");
		kill(child, SIGKILL);
		exit(1);
	}

	exit(0);
}
