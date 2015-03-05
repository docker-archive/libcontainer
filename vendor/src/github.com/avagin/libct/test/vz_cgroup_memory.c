#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libct.h>
#include <unistd.h>
#include <linux/sched.h>

#include "test.h"

#define FS_ROOT		"/"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define MEMLIMIT 134217728
#define MEMLIMIT_STR STR(MEMLIMIT)

#define CT_ID 1339
#define CT_NAME	STR(CT_ID)	

int is_memory_correct(unsigned long expected_limit)
{
	int ret = 0;
	FILE *f = NULL;
	char buf[1024] = {'\0'};
	unsigned long flds[5] = {0};
	unsigned long limit = 0;

	f = fopen("/proc/bc/" CT_NAME "/resources", "r");
	if (!f) {
		fprintf(stderr, "Unable to open /proc/bc/" CT_NAME "/resources!\n");
		goto err;
	}

	while (fscanf(f, "%s %lu %lu %lu %lu %lu", buf, &flds[0], &flds[1], &flds[2], &flds[3], &flds[4]) == 6) {
		if (strcmp(buf, "physpages") == 0 && flds[2] == flds[3]) {
			limit = flds[2] * getpagesize();
			break;
		}
	}
	if (!limit) {
		fprintf(stderr, "unable to read \n");
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
	char *run_a[3] = { "sleep", "2", NULL};

	test_init(argc, argv);

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

	libct_controller_add(ct, CTL_MEMORY);
	libct_controller_configure(ct, CTL_MEMORY, "limit_in_bytes", MEMLIMIT_STR);

	pr = libct_container_spawn_execv(ct, p, "/bin/sleep", run_a);
	if (libct_handle_is_err(pr))
		goto err;

	if (!is_memory_correct(MEMLIMIT))
		goto err;

	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
