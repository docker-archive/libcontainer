/*
 * Test empty "container" creation
 */
#include <unistd.h>
#include <libct.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "test.h"

static int set_ct_alive(void *a)
{
	int *pfd = (int *)a;
	char buf;

	close(pfd[1]);
	if (read(pfd[0], &buf, sizeof(buf)) < 0)
		return 1;

	close(pfd[0]);
	return 0;
}

int main(int argc, char **argv)
{
	int pfd[2], status;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	ct_process_t pr;

	test_init();

	if (pipe(pfd) < 0)
		return 1;

	s = libct_session_open_local();
	if (libct_handle_is_err(s))
		return fail("Unable to create a new session");

	ct = libct_container_create(s, "test");
	if (libct_handle_is_err(ct))
		return fail("Unable to create a container object");
	libct_controller_add(ct, CTL_FREEZER);

	p = libct_process_desc_create(s);
	if (libct_handle_is_err(p))
		return fail("Unable to create a process descriptor");

	pr = libct_container_spawn_cb(ct, p, set_ct_alive, pfd);
	close(pfd[0]);
	if (libct_handle_is_err(pr))
		return fail("Unable to start CT");

	if (libct_container_pause(ct)) {
		fail("Unable to pause");
		return 1;
	}
	if (libct_container_resume(ct)) {
		fail("Unable to resume");
		return 1;
	}

	close(pfd[1]);
	if (wait(&status) < 0)
		return 1;
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (status == 0)
		pass("Container is alive");
	else {
		fail("%x", status);
		return 1;
	}
	return 0;
}
