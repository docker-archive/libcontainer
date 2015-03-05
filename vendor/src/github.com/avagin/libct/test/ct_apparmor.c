/*
 * Test empty "container" creation
 */
#include <unistd.h>
#include <sys/types.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "test.h"

static int set_ct_alive(void *a)
{
	int fd;

	fd = open("/proc/self/stat", O_RDONLY);
	if (fd >= 0)
		return 1;

	*(int *)a = 1;
	return 0;
}

int main(int argc, char **argv)
{
	int *ct_alive;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;

	if (system("apparmor_parser -r apparmor.test"))
		return 1;

	ct_alive = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	*ct_alive = 0;

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	p = libct_process_desc_create(s);
	libct_process_desc_set_lsm_label(p, "libct-test");
	libct_container_spawn_cb(ct, p, set_ct_alive, ct_alive);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (!*ct_alive)
		return fail("Container is not alive");
	else
		return pass("Container is alive");
}
