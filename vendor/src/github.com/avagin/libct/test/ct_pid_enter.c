/*
 * Test entering into living container with pidns
 */
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test.h"

#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

struct ct_arg {
	int wait_fd;
	int *mark;
};

static int set_ct_alive(void *a)
{
	struct ct_arg *cta = a;
	char c;

	cta->mark[0] = getpid();
	cta->mark[1] = getppid();
	read(cta->wait_fd, &c, 1);
	return 0;
}

static int set_ct_enter(void *a)
{
	struct ct_arg *cta = a;
	cta->mark[2] = getpid();
	cta->mark[3] = getppid();
	return 0;
}

int main(int argc, char **argv)
{
	struct ct_arg cta;
	int p[2], status;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t pd;
	ct_process_t pr;

	pipe(p);
	cta.mark = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	cta.mark[0] = -1;
	cta.mark[1] = -1;
	cta.mark[2] = -1;
	cta.mark[3] = -1;
	cta.wait_fd = p[0];

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	pd = libct_process_desc_create(s);
	libct_container_set_nsmask(ct, CLONE_NEWPID);
	libct_container_spawn_cb(ct, pd, set_ct_alive, &cta);
	pr = libct_container_enter_cb(ct, pd, set_ct_enter, &cta);
	libct_process_wait(pr, &status);

	write(p[1], "a", 1);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (cta.mark[0] == -1)
		return fail("CT is not alive");

	if (cta.mark[1] == -1)
		return fail("CT is not enterable");

	printf("pids (%d:%d) (%d:%d)\n", cta.mark[0], cta.mark[1], cta.mark[2], cta.mark[3]);

	return pass("OK");
}
