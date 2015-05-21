#include <dirent.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <mntent.h>

#include <sys/types.h>

#include "linux-kernel.h"
#include "cgroups.h"
#include "log.h"

unsigned long kernel_ns_mask;

int linux_get_ns_mask(void)
{
	DIR *d;

	d = opendir("/proc/self/ns");
	if (d) {
		struct dirent *de;

		while ((de = readdir(d)) != NULL) {
			if (!strcmp(de->d_name, "."))
				continue;
			if (!strcmp(de->d_name, ".."))
				continue;

			if (!strcmp(de->d_name, "ipc"))
				kernel_ns_mask |= CLONE_NEWIPC;
			else if (!strcmp(de->d_name, "net"))
				kernel_ns_mask |= CLONE_NEWNET;
			else if (!strcmp(de->d_name, "mnt"))
				kernel_ns_mask |= CLONE_NEWNS;
			else if (!strcmp(de->d_name, "pid"))
				kernel_ns_mask |= CLONE_NEWPID;
			else if (!strcmp(de->d_name, "uts"))
				kernel_ns_mask |= CLONE_NEWUTS;
			else if (!strcmp(de->d_name, "user"))
				kernel_ns_mask |= CLONE_NEWUSER;
		}
	}

	closedir(d);
	return 0;
}

int linux_get_cgroup_mounts(void)
{
	int ret = 0;
	FILE *f;
	struct mntent *me;

	f = setmntent("/proc/mounts", "r");
	if (!f)
		return -1;

	while ((me = getmntent(f)) != NULL) {
		if (!strcmp(me->mnt_type, "cgroup")) {
			ret = cgroup_add_mount(me);
			if (ret)
				break;
		}
	}

	fclose(f);
	return ret;
}

int linux_get_last_capability(void)
{
	FILE *f;
	static int last_cap = -1;
	int ret;

	if (last_cap > 0)
		return last_cap;

	f = fopen("/proc/sys/kernel/cap_last_cap", "r");
	ret = fscanf(f, "%d", &last_cap);
	fclose(f);
	if (ret != 1) {
		pr_err("Unable to parse /proc/sys/kernel/cap_last_cap");
		return -1;
	}

	return last_cap;
}

