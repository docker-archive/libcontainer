/*
 * Test external bind mount works
 */
#include <unistd.h>
#include <libct.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "test.h"

#define FS_ROOT	"libct_test_root"
#define FS_EXT	"libct_test_external"
#define FS_ACT	"libct_test_actions"
#define FS_PTS	"libct_test_devpts"
#define FS_DIR	"dir"
#define FS_FILE	"file"

static int check_fs_data(void *a)
{
	int fd;
	int *fs_data = a;
	struct statfs sfs;

	fd = open("/" FS_DIR "/" FS_FILE, O_RDONLY);
	if (fd < 0)
		return 0;

	close(fd);

	if (statfs("/" FS_PTS, &sfs)) {
		printf("stafs(%s): %m", FS_PTS);
		return 1;
	}

	if (sfs.f_type != DEVPTS_SUPER_MAGIC) {
		printf("Unexpected fs magic %lx instead of %x\n", sfs.f_type, DEVPTS_SUPER_MAGIC);
		return 1;
	}

	if (access(FS_ACT "/hello", F_OK)) {
		tst_err("Unable to access %s", FS_ACT "/hello");
		return 1;
	}

	*fs_data = 1;
	return 0;
}

int main(int argc, char **argv)
{
	char *fs_data;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	int fs_err = 0;
	char *preargv[] = {"echo", "premount", NULL};
	struct libct_cmd premount = {
		.path = "echo",
		.argv = preargv,
	};
	char *postargv[] = {"touch", FS_ROOT "/" FS_ACT "/hello", NULL};
	struct libct_cmd postmount = {
		.path = "touch",
		.argv = postargv,
	};

	mkdir(FS_EXT, 0600);
	if (creat(FS_EXT "/" FS_FILE, 0600) < 0)
		return tst_perr("Can't create file");

	mkdir(FS_ROOT, 0600);
	mkdir(FS_ROOT "/" FS_DIR, 0600);
	unlink(FS_ROOT "/" FS_DIR "/" FS_FILE);

	fs_data = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	fs_data[0] = '\0';

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	p = libct_process_desc_create(s);
	printf("Set root\n");
	libct_fs_set_root(ct, FS_ROOT);
	printf("Set bind\n");
	libct_fs_add_bind_mount(ct, FS_EXT, FS_DIR, 0);
	libct_fs_add_mount(ct, "test_devpts", FS_PTS, 0, "devpts", "newinstance");
	libct_fs_add_mount_with_actions(ct, "test_actions", FS_ACT, 0, "tmpfs", "", &premount, &postmount);
	printf("Spawn\n");
	libct_container_spawn_cb(ct, p, check_fs_data, fs_data);
	printf("Done\n");
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (rmdir(FS_ROOT "/" FS_DIR) < 0)
		fs_err |= 1;
	if (rmdir(FS_ROOT "/" FS_PTS) < 0)
		fs_err |= 16;
	if (rmdir(FS_ROOT "/" FS_ACT) < 0)
		fs_err |= 32;
	if (rmdir(FS_ROOT) < 0)
		fs_err |= 2;
	if (unlink(FS_EXT "/" FS_FILE) < 0)
		fs_err |= 4;
	if (rmdir(FS_EXT) < 0)
		fs_err |= 8;

	if (fs_err) {
		printf("FS remove failed %x\n", fs_err);
		return fail("FS broken");
	}

	if (!fs_data[0])
		return fail("FS private not accessible");

	return pass("Subdir as private is OK");
}
