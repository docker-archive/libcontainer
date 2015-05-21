/*
 * Test how proc automount works (LIBCT_OPT_AUTO_PROC_MOUNT)
 */
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <stdlib.h>

#include "test.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif  
                
#ifndef CLONE_NEWPID
#define CLONE_NEWPID    0x20000000
#endif

static int set_ct_root_pids(void *a)
{
	int *pids = a;
	char buf[32];

	memset(buf, 0, sizeof(buf));
	pids[0] = getpid();
	readlink("/proc/self", buf, sizeof(buf));
	pids[1] = atoi(buf);

	return 0;
}

int main(int argc, char **argv)
{
	int *ct_root_pids;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;

	test_init();

	ct_root_pids = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	ct_root_pids[0] = 0;
	ct_root_pids[1] = 0;

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	p = libct_process_desc_create(s);
	if (libct_container_set_nsmask(ct, CLONE_NEWPID | CLONE_NEWNS)) {
		tst_err("No pid & mount NS");
		return 2;
	}

	libct_container_set_option(ct, LIBCT_OPT_AUTO_PROC_MOUNT, NULL);

	libct_container_spawn_cb(ct, p, set_ct_root_pids, ct_root_pids);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	/* Should be init */
	if ((ct_root_pids[0] != 1) || (ct_root_pids[1] != 1))
		return fail("Pid mismatch");
	else
		return pass("Pids are OK");
}
