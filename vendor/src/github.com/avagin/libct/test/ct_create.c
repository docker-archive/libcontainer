/*
 * Test empty "container" creation
 */
#include <unistd.h>
#include <sys/types.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include "test.h"

#define UID	31451
#define GID	92653

static int set_ct_alive(void *a)
{
	if (getuid() != UID)
		return -1;
	if (getgid() != GID)
		return -1;
	*(int *)a = 1;
	return 0;
}

int main(int argc, char **argv)
{
	int *ct_alive;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	ct_process_t pr;

	ct_alive = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	if (ct_alive == MAP_FAILED)
		return tst_perr("Unable to allocate memory");
	*ct_alive = 0;

	s = libct_session_open_local();
	if (libct_handle_is_err(s))
		return fail("Unable to create a new session");

	ct = libct_container_create(s, "test");
	if (libct_handle_is_err(ct))
		return fail("Unable to create a container object");

	p = libct_process_desc_create(s);
	if (libct_handle_is_err(p))
		return fail("Unable to create a process descriptor");

	libct_process_desc_setuid(p, UID);
	libct_process_desc_setgid(p, GID);

	pr = libct_container_spawn_cb(ct, p, set_ct_alive, ct_alive);
	if (libct_handle_is_err(pr))
		return fail("Unable to start CT");

	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (!*ct_alive)
		return fail("Container is not alive");
	else
		return pass("Container is alive");
}
