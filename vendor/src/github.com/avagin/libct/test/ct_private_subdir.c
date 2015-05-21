/*
 * Test subdir as private FS (CT_FS_SUBDIR)
 */
#include <unistd.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "test.h"

#define FS_ROOT		"libct_test_root"
#define FS_PRIVATE	"libct_test_private"
#define FS_FILE		"libct_test_file"

static int check_fs_data(void *a)
{
	int fd;
	int *fs_data = a;

	fd = open("/" FS_FILE, O_RDONLY);
	if (fd < 0)
		return 0;

	*fs_data = 1;
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	char *fs_data;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	int fs_err = 0;

	mkdir(FS_ROOT, 0600);
	mkdir(FS_PRIVATE, 0600);
	if (creat(FS_PRIVATE "/" FS_FILE, 0600) < 0)
		return tst_perr("Can't create file");
	unlink(FS_ROOT "/" FS_FILE);

	fs_data = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	fs_data[0] = '\0';

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	p = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);
	libct_fs_set_private(ct, CT_FS_SUBDIR, FS_PRIVATE);
	libct_container_spawn_cb(ct, p, check_fs_data, fs_data);
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (unlink(FS_PRIVATE "/" FS_FILE) < 0)
		fs_err |= 1;
	if (rmdir(FS_PRIVATE) < 0)
		fs_err |= 2;
	if (rmdir(FS_ROOT) < 0)
		fs_err |= 3;

	if (fs_err) {
		printf("FS remove failed %x\n", fs_err);
		return fail("FS broken");
	}

	if (!fs_data[0])
		return fail("FS private not accessible");

	return pass("Subdir as private is OK");
}
