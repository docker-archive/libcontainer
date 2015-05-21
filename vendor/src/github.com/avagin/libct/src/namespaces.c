#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include "namespaces.h"
#include "vzsyscalls.h"
#include "bug.h"
#include "log.h"

struct ns_desc pid_ns = {
	.name = "pid",
	.cflag = CLONE_NEWPID,
};

struct ns_desc net_ns = {
	.name = "net",
	.cflag = CLONE_NEWNET,
};

static struct ns_desc mnt_ns = {
	.name = "mnt",
	.cflag = CLONE_NEWNS,
};

static struct ns_desc ipc_ns = {
	.name = "ipc",
	.cflag = CLONE_NEWIPC,
};

static struct ns_desc uts_ns = {
	.name = "uts",
	.cflag = CLONE_NEWUTS,
};

struct ns_desc *namespaces[] = {
	&pid_ns,
	&net_ns,
	&ipc_ns,
	&uts_ns,
	/*
	 * mnt_ns must be the last one. After switching in a mount namespace,
	 * the old /proc becomes inaccessible and we are not able switch other
	 * namespaces
	 */
	&mnt_ns,
	NULL
};

int setns(int fd, int nstype) __attribute__((weak));

static int libct_setns(int fd, int nstype)
{
	int ret;

	if (setns)
		ret = setns(fd, nstype);
	else
		ret = syscall(__NR_setns, fd, nstype);

	if (ret)
		pr_perror("Unable to switch namespace %d", nstype);

	return ret;
}

int switch_ns(int pid, struct ns_desc *nd, int *rst)
{
	char buf[32];
	int nsfd;
	int ret = -1;

	snprintf(buf, sizeof(buf), "/proc/%d/ns/%s", pid, nd->name);
	nsfd = open(buf, O_RDONLY);
	if (nsfd < 0) {
		pr_perror("Unable to open %s", buf);
		goto err_ns;
	}

	if (rst) {
		snprintf(buf, sizeof(buf), "/proc/self/ns/%s", nd->name);
		*rst = open(buf, O_RDONLY);
		if (*rst < 0) {
			pr_perror("Unable to open %s", buf);
			goto err_rst;
		}
	}

	ret = libct_setns(nsfd, nd->cflag);
	if (ret < 0) {
		pr_perror("Unable setns into %s:%d", nd->name, pid);
		goto err_set;
	}

	close(nsfd);
	return 0;

err_set:
	if (rst)
		close(*rst);
err_rst:
	close(nsfd);
err_ns:
	return -1;
}

void restore_ns(int rst, struct ns_desc *nd)
{
	if (libct_setns(rst, nd->cflag))
		BUG();
	close(rst);
}
