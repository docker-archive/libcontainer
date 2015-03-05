#include <stdio.h>
#include <stdlib.h>
#include <libct.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "test.h"

#define FS_ROOT		"root"
int main(int argc, char *argv[])
{
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t pd;
	ct_process_t pr, p;
	char *sleep_a[] = { "cat", NULL};
	char *ls_a[] = { "sh", "-c", "cat; echo ok", NULL};
	int fds[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
	int pfd[2], tfd[2], ifd[2], status;
	char buf[10];

	test_init();

	s = libct_session_open_local();
	ct = libct_container_create(s, "1339");
	pd = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);

	libct_container_set_nsmask(ct,
			CLONE_NEWNS |
			CLONE_NEWUTS |
			CLONE_NEWIPC |
			CLONE_NEWNET |
			CLONE_NEWPID);

	if (pipe(pfd))
		goto err;

	fds[0] = pfd[0];
	fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
	libct_process_desc_set_fds(pd, fds, 3);
	p = libct_container_spawn_execv(ct, pd, "/bin/cat", sleep_a);
	if (libct_handle_is_err(p))
		goto err;
	close(pfd[0]);

	if (pipe(tfd))
		goto err;
	if (pipe(ifd))
		goto err;

	fds[0] = ifd[0];
	fds[1] = tfd[1];
	fcntl(tfd[0], F_SETFD, FD_CLOEXEC);
	libct_process_desc_set_fds(pd, fds, 3);
	pr = libct_container_enter_execv(ct, pd, "/bin/sh", ls_a);
	if (libct_handle_is_err(pr))
		goto err;
	close(tfd[1]);
	close(ifd[0]);
	close(ifd[1]);

	if (read(tfd[0], buf, sizeof(buf)) != 3)
		goto err;

	if (libct_process_wait(pr, &status))
		goto err;

	close(pfd[1]);

	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
