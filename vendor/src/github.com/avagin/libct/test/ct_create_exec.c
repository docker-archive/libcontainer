/*
 * Test creation of container using executable
 */
#define _XOPEN_SOURCE
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "test.h"

#define PIGGY_FILE	"libct_piggy_file"
#define PIGGY_DATA	"libct_piggy_data"

int main(int argc, char **argv)
{
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t pd;
	ct_process_t p;
	char *piggy_a[4];
	int fd, master, slave;
	char dat[sizeof(PIGGY_DATA)];
	char *slavename;
	int fds[3];

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	pd = libct_process_desc_create(s);

	piggy_a[0] = "file_piggy";
	piggy_a[1] = PIGGY_FILE;
	piggy_a[2] = PIGGY_DATA;
	piggy_a[3] = NULL;

	master = open("/dev/ptmx", O_RDWR);
	if (master < 0)
		goto err;

	grantpt(master);
	unlockpt(master);

	slavename = ptsname(master);
	if (slavename == NULL)
		goto err;
	slave = open(slavename, O_RDWR);
	if (slave < 0)
		goto err;

	if (libct_container_set_console_fd(ct, slave) < 0)
		goto err;

	fds[0] = fds[1] = fds[2] = slave;
	if (libct_process_desc_set_fds(pd, fds, 3))
		goto err;

	p = libct_container_spawn_execv(ct, pd, "./file_piggy", piggy_a);
	if (libct_handle_is_err(p))
		goto err;

	read(master, dat, 3);
	write(master, "\3", 1); /* Ctrl-C */
	if (libct_container_wait(ct) < 0)
		goto err;

	libct_container_destroy(ct);
	libct_session_close(s);

	fd = open(PIGGY_FILE, O_RDONLY);
	if (fd < 0)
		return fail("Piggy file not created");

	memset(dat, 0, sizeof(dat));
	read(fd, dat, sizeof(dat));
	close(fd);

	if (strcmp(dat, PIGGY_DATA))
		return fail("Piggy data differs");
	else
		return pass("Piggy file is OK");
err:
	return fail("Something wrong");
}
