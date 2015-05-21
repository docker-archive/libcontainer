/*
 * Test that entering into chroot()-ed CT works
 */
#include <unistd.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "test.h"

#define FS_ROOT	"libct_test_root"
#define FS_DATA	"libct_test_string"
#define FS_FILE "file"
#define ENTER_DOFF	1024

struct ct_arg {
	int wait_fd;
	char *fs_data;
};

static int read_fs_data(char *a)
{
	int fd;

	fd = open("/" FS_FILE, O_RDONLY);
	if (fd < 0)
		return 1;

	read(fd, a, sizeof(FS_DATA));
	close(fd);

	return 0;
}

static int ct_main_fn(void *a)
{
	struct ct_arg *cta = a;
	char c;

	if (read_fs_data(cta->fs_data))
		return 1;

	read(cta->wait_fd, &c, 1);
	return 0;
}

static int ct_enter_fn(void *a)
{
	struct ct_arg *cta = a;

	return read_fs_data(cta->fs_data + ENTER_DOFF);
}

int main(int argc, char **argv)
{
	int fd, p[2], status;
	struct ct_arg cta;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t pd;
	ct_process_t pr;

	pipe(p);

	mkdir(FS_ROOT, 0600);
	fd = open(FS_ROOT "/" FS_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		tst_perr("Can't create file");
		return 2;
	}

	write(fd, FS_DATA, sizeof(FS_DATA));
	close(fd);

	cta.fs_data = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	cta.fs_data[0] = '\0';
	cta.fs_data[ENTER_DOFF] = '\0';
	cta.wait_fd = p[0];

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	pd = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);
	libct_container_spawn_cb(ct, pd, ct_main_fn, &cta);
	pr = libct_container_enter_cb(ct, pd, ct_enter_fn, &cta);
	if (libct_handle_is_err(pr))
		fail("Unable to enter into CT");
	libct_process_wait(pr, &status);
	write(p[1], "a", 1);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	unlink(FS_ROOT "/" FS_FILE);
	rmdir(FS_ROOT);

	if (strcmp(cta.fs_data, FS_DATA))
		return fail("FS not accessed");

	if (strcmp(cta.fs_data + ENTER_DOFF, FS_DATA))
		return fail("FS not entered");

	return pass("FS is created and entered");
}
