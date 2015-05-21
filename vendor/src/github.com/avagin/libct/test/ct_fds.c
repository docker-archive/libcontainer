/*
 * Test empty "container" creation
 */
#include <unistd.h>
#include <sys/types.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include "test.h"


static int set_ct_alive(void *a)
{
	int t;

	if (read(0, &t, sizeof(t)) != sizeof(t))
		return -1;

	t = t * 2;

	if (write(1, &t, sizeof(t)) != sizeof(t))
		return -1;
	close(1);

	if (read(3, &t, sizeof(t)) != sizeof(t))
		return -1;

	t = t * 3;

	if (write(2, &t, sizeof(t)) != sizeof(t))
		return -1;
	close(2);

	if (read(0, &t, sizeof(t)) != 0)
		return -1;

	if (read(3, &t, sizeof(t)) != 0)
		return -1;

	return 0;
}

int check(int *inp, int *outp, int *errp, int *extp, int *fds, int v)
{
	int i, t;

	for (i = 0; i < 4; i++)
		close(fds[i]);

	t = v;
	if (write(inp[1], &t, sizeof(t)) != sizeof(t)) {
		fail();
		return -1;
	}
	close(inp[1]);
	if (read(outp[0], &t, sizeof(t)) != sizeof(t)) {
		fail();
		return -11;
	}
	if (t != v * 2) {
		fail();
		return -11;
	}
	if (read(outp[0], &t, sizeof(t)) != 0) {
		fail();
		return -11;
	}

	t = v;
	if (write(extp[1], &t, sizeof(t)) != sizeof(t)) {
		fail();
		return -11;
	}
	close(extp[1]);
	if (read(errp[0], &t, sizeof(t)) != sizeof(t)) {
		fail();
		return -11;
	}
	if (t != v * 3) {
		fail();
		return -11;
	}
	if (read(errp[0], &t, sizeof(t)) != 0) {
		fail();
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	int fds[4], efds[4];

	int inp[2], outp[2], errp[2], extp[2];
	int einp[2], eoutp[2], eerrp[2], eextp[2];

	if (pipe(inp) || pipe(outp) || pipe(errp) || pipe(extp))
		return -1;

	fds[0] = inp[0];
	fds[1] = outp[1];
	fds[2] = errp[1];
	fds[3] = extp[0];

	if (pipe(einp) || pipe(eoutp) || pipe(eerrp) || pipe(eextp))
		return -1;

	efds[0] = einp[0];
	efds[1] = eoutp[1];
	efds[2] = eerrp[1];
	efds[3] = eextp[0];

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	p = libct_process_desc_create(s);
	libct_process_desc_set_fds(p, fds, 4);
	libct_container_spawn_cb(ct, p, set_ct_alive, NULL);
	libct_process_desc_set_fds(p, efds, 4);
	libct_container_enter_cb(ct, p, set_ct_alive, NULL);

	if (check(einp, eoutp, eerrp, eextp, efds, 5) ||
	    check(inp, outp, errp, extp, fds, 7))
		return 1;


	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	pass("Container is alive");
	return 0;
}
