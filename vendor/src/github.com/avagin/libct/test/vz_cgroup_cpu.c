#include <stdio.h>
#include <stdlib.h>
#include <libct.h>
#include <unistd.h>
#include <string.h>
#include <linux/sched.h>

#include "test.h"

#define FS_ROOT		"/"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define CT_ID 1339
#define CT_NAME	STR(CT_ID)	
#define CPUS "0-1,3"

int is_cpu_count_correct(const char *expected_cpus)
{
	int ret = 0;
	FILE *f = NULL;
	char buf[1024] = {'\0'};

	f = fopen("/proc/vz/fairsched/" CT_NAME "/cpuset.cpus", "r");
	if (!f) {
		fprintf(stderr, "Unable to open /proc/vz/fairsched/" CT_NAME "/cpuset.cpus!\n");
		goto err;
	}

	if (fscanf(f, "%s", buf) != 1) {
		fprintf(stderr, "fscanf failed!\n");
		goto err;
	}
	ret = !strcmp(buf, expected_cpus);
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

	libct_controller_add(ct, CTL_CPUSET);
	libct_controller_configure(ct, CTL_CPUSET, "cpuset.cpus", CPUS);
	pr = libct_container_spawn_execv(ct, p, "/bin/sleep", sleep_a);
	if (libct_handle_is_err(pr))
		goto err;

	if (!is_cpu_count_correct(CPUS))
		goto err;

	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
