/*
 * Test how cgroups subgroups work inside containers
 * (LIBCT_OPT_CGROUP_SUBMOUNT option).
 */
#include <unistd.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "test.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif  

#define FS_ROOT		"libct_test_root_ns"
#define FS_PRIVATE	"libct_test_private_ns"
#define FS_CG		"cg"

static int check_cgroup(void *a)
{
	int *s = a;

	s[0] = 1;
	mkdir("/"FS_CG"/freezer/x", 0600);
	if (access("/"FS_CG"/freezer/x/freezer.state", F_OK) == 0)
		s[1] = 1;
	rmdir("/"FS_CG"/freezer/x");

	return 0;
}

int main(int argc, char **argv)
{
	int *ct_status;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	int fs_err = 0;

	test_init();

	mkdir(FS_ROOT, 0600);
	mkdir(FS_PRIVATE, 0600);
	mkdir(FS_PRIVATE "/" FS_CG, 0600);

	ct_status = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	ct_status[0] = 0;
	ct_status[1] = 0;

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	p = libct_process_desc_create(s);
	libct_container_set_nsmask(ct, CLONE_NEWNS);
	libct_controller_add(ct, CTL_FREEZER);
	libct_fs_set_root(ct, FS_ROOT);
	libct_fs_set_private(ct, CT_FS_SUBDIR, FS_PRIVATE);
	libct_container_set_option(ct, LIBCT_OPT_CGROUP_SUBMOUNT, FS_CG);
	libct_container_spawn_cb(ct, p, check_cgroup, ct_status);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (rmdir(FS_PRIVATE "/" FS_CG) < 0)
		fs_err |= 1;
	if (rmdir(FS_PRIVATE) < 0)
		fs_err |= 2;
	if (rmdir(FS_ROOT) < 0)
		fs_err |= 3;

	if (fs_err) {
		printf("FS remove failed %x\n", fs_err);
		return fail("FS broken");
	}

	if (!ct_status[0])
		return fail("CT not running");
	if (!ct_status[1])
		return fail("CG not sub-mounted");

	return pass("OK");
}
