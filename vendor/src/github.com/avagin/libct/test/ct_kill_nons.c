/*
 * Test that service cgroup works
 */
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "test.h"

struct ct_arg {
	int start_fd;
	int *mark;
};

static int loop_in_ct(void *a)
{
	struct ct_arg *cta = a;
	char c = 'a';
	int cpid;

	cpid = fork();
	if (cpid == 0)
		goto loop;

	cta->mark[0] = getpid();
	cta->mark[1] = cpid;

	write(cta->start_fd, &c, 1);

loop:
	/*
	 * Don't close the pipe. If killing cgroup
	 * failed, test would hang forever FIXME
	 */

	while (1)
		sleep(10);
	exit(1);
}

int main(int argc, char **argv)
{
	struct ct_arg cta;
	int p[2];
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t pd;
	ct_process_t pr;
	char c;

	pipe(p);
	cta.mark = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	cta.mark[0] = 0;
	cta.mark[1] = 0;
	cta.start_fd = p[1];

	s = libct_session_open_local();
	ct = libct_container_create(s, "test-k");
	pd = libct_process_desc_create(s);
	if (libct_container_set_option(ct, LIBCT_OPT_KILLABLE, NULL))
		return tst_err("can't set killable");

	pr = libct_container_spawn_cb(ct, pd, loop_in_ct, &cta);
	if (libct_handle_is_err(pr))
		return tst_err("can't start CT");

	close(p[1]);
	read(p[0], &c, 1);

	libct_container_kill(ct);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (read(p[0], &c, 1) != 0) /* FIXME -- this may block on error */
		return fail("Pipes are alive?");

	if (!cta.mark[0])
		return fail("CT is not alive");

	if (!cta.mark[1])
		return fail("CT hasn't forked");

	return pass("killed OK");
}
