#include <stdio.h>
#include <stdlib.h>
#include <libct.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sys/ioctl.h>

#include "test.h"

#define FS_ROOT		"/"
#define VZCTLDEV	"/dev/vzctl"

/* FIXME duplicates vziolimit.h */
struct iolimit_state {
	unsigned int id;
	unsigned int speed;
	unsigned int burst;
	unsigned int latency;
};
#define VZCTL_GET_IOPSLIMIT	_IOR('I', 3, struct iolimit_state)


#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define CT_ID 1339
#define CT_NAME	STR(CT_ID)	
#define IOPSLIMIT 1
#define IOPSLIMIT_STR STR(IOPSLIMIT)
#define IOPRIOLIMIT 7
#define IOPRIOLIMIT_STR STR(IOPRIOLIMIT)

int is_iopslimit_correct(unsigned int expected_limit)
{
	int fd = -1;
	int ret = 0;
	struct iolimit_state io;

	fd = open(VZCTLDEV, O_RDWR); 
	if (fd == -1) {
		fprintf(stderr, "Unable to open %s!\n", VZCTLDEV);
		goto err;
	}
	
	io.id = CT_ID;
	if (ioctl(fd, VZCTL_GET_IOPSLIMIT, &io)) {
		perror("ioctl");
		goto err;
	}
	ret = (io.speed == expected_limit);

err:
	close(fd);
	return ret;
}

int is_iopriolimit_correct(unsigned int expected_limit)
{
	int ret = 0;
	FILE *f = NULL;
	int limit;
	char buf[1024];

	f = fopen("/proc/bc/" CT_NAME "/ioprio", "r");
	if (!f) {
		fprintf(stderr, "Unable to open /proc/bc/" CT_NAME "/ioprio!\n");
		goto err;
	}

	if (fscanf(f, "%s %d", buf, &limit) != 2) {
		fprintf(stderr, "fscanf failed!\n");
		goto err;
	}
	ret = (limit == expected_limit);
err:
	fclose(f);
	return ret;
}

int main(int argc, char *argv[])
{
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	ct_process_t pr;
	char *sleep_a[] = { "sleep", "2", NULL};

	s = libct_session_open_local();
	ct = libct_container_create(s, CT_NAME);
	p = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);

	libct_container_set_nsmask(ct,
			CLONE_NEWNS |
			CLONE_NEWUTS |
			CLONE_NEWIPC |
			CLONE_NEWNET |
			CLONE_NEWPID);

	libct_controller_add(ct, CTL_BLKIO);
	libct_controller_configure(ct, CTL_BLKIO, "throttle.write_iops_device", IOPSLIMIT_STR);
	libct_controller_configure(ct, CTL_BLKIO, "weight", IOPRIOLIMIT_STR);
	pr = libct_container_spawn_execv(ct, p, "/bin/sleep", sleep_a);
	if (libct_handle_is_err(pr))
		goto err;

	if (!is_iopslimit_correct(IOPSLIMIT))
		goto err;
	if (!is_iopriolimit_correct(IOPRIOLIMIT))
		goto err;
	
	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
