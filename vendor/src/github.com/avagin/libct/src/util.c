#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/socket.h>

#include "uapi/libct.h"
#include "xmalloc.h"
#include "util.h"
#include "log.h"

static int create_dest(char *path, mode_t mode, bool isdir)
{
	char *tok;
	int ret;

	tok = path;
	while (1) {
		char c = 0;

		tok = strchr(tok + 1, '/');
		if (tok != NULL) {
			c = *tok;
			*tok = 0;
		}

		if (tok == NULL && !isdir) {
			ret = open(path, O_CREAT | O_WRONLY, mode);
			if (ret >= 0)
				close(ret);
		} else
			ret = mkdir(path, mode);

		if (ret < 0 && errno != EEXIST) {
			pr_perror("couldn't create %s", path);
			if (tok != NULL)
				*tok = c;
			return -1;
		}

		if (tok == NULL)
			break;

		*tok = c;
	}

	return 0;
}

int do_mount(char *src, char *dst, int flags, char *fstype, char *data)
{
	unsigned long mountflags = 0;
	struct stat st;
	bool isdir = true;

	if (flags & CT_FS_BIND) {
		if (fstype || data)
			return -1;

		mountflags |= MS_BIND;

		if (stat(src, &st)) {
			pr_perror("Unable to stat %s", src);
			return -1;
		}
		isdir = S_ISDIR(st.st_mode);
	}

	if (create_dest(dst, 0755, isdir))
		return -1;

	if (flags & CT_FS_RDONLY)
		mountflags |= MS_RDONLY;
	if (flags & CT_FS_NOEXEC)
		mountflags |= MS_NOEXEC;
	if (flags & CT_FS_NOSUID)
		mountflags |= MS_NOSUID;
	if (flags & CT_FS_NODEV)
		mountflags |= MS_NODEV;
	if (flags & CT_FS_STRICTATIME)
		mountflags |= MS_STRICTATIME;
	if (flags & CT_FS_REC)
		mountflags |= MS_REC;

	if (mount(src, dst, fstype, mountflags, data) == -1) {
		pr_perror("Unable to mount %s -> %s\n", src, dst);
		return -1;
	}

	if (flags & CT_FS_PRIVATE) {
		if (mount(NULL, dst, NULL, MS_PRIVATE, NULL) == -1) {
			pr_perror("Unable to mark %s as private", dst);
			umount(dst);
			return -1;
		}
	}

	return 0;
}

int set_string(char **dest, char *src)
{
	char *t;

	t = xstrdup(src);
	if (t == NULL)
		return -1;

	xfree(*dest);
	*dest = t;

	return 0;
}

int parse_uint(const char *str, unsigned int *val)
{
	char *tail;
	long int n;

	if (*str == '\0')
		return -1;

	errno = 0;
	n = strtoul(str, &tail, 10);
	if (*tail != '\0' || n >= UINT_MAX)
		return -1;
	*val = (unsigned int)n;

	return 0;
}

int parse_int(const char *str, int *val)
{
	char *tail;
	long int n;

	if (*str == '\0')
		return -1;

	errno = 0;
	n = strtol(str, &tail, 10);
	if (*tail != '\0' || errno == ERANGE || n > INT_MAX)
		return -1;
	*val = (int)n;

	return 0;
}

/*
	1 - exist
	0 - doesn't exist
	-1 - error
*/
int stat_file(const char *file)
{
	struct stat st;

	if (stat(file, &st)) {
		if (errno != ENOENT) {
			pr_perror("unable to stat %s", file);
			return -1;
		}
		return 0;
	}
	return 1;
}

/* Close all file descriptors, which are not less than n */
static int close_fds(int proc_fd, int n)
{
	struct dirent *de;
	DIR *d;
	int fd;

	fd = openat(proc_fd, "self/fd", O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open /proc/self/fd");
		return -1;
	}

	d = fdopendir(fd);
	if (d == NULL) {
		pr_perror("Unable to open /proc/self/fd");
		close(fd);
		return -1;
	}

	while ((de = readdir(d))) {
		int fd;

		if (de->d_name[0] == '.')
			continue;

		fd = atoi(de->d_name);
		if (dirfd(d) == fd)
			continue;
		if (fd < n)
			continue;
		close(fd);
	}

	closedir(d);

	return 0;
}

/*
 * Setup file descriptors from the fds array according to the positions in the
 * arrays and close other file descriptros.
 *
 * proc_self_d has to point on /proc/self/fd
 */
int setup_fds_at(int proc_fd, int *fds, int n)
{
	int i;

	libct_log_init(-1, 0); /* close */

	for (i = 0; i < n; i++) {
		if (fds[i] == LIBCT_CONSOLE_FD) {
			fds[i] = open("/dev/console", O_RDWR);
			if (fds[i] == -1) {
				pr_perror("Unable to open /dev/console");
				return -1;
			}
		}
	}

	/* skip used file descriptors and fill all unused descriptors  */
	for (i = 0; i < n; i++) {
		if (fcntl(i, F_GETFD) != -1 || errno != EBADF)
			continue; /* inuse */

		if (dup2(fds[i], i) == -1) {
			pr_perror("Unable to dup %d -> %d", fds[i], i);
			return -1;
		}

		fds[i] = i;
	}

	if (proc_fd < n)
		proc_fd = dup(proc_fd);

	/* move target descriptros from target places */
	for (i = 0; i < n; i++) {
		int ret;

		if (fds[i] == i || fds[i] >= n)
			continue;

		ret = dup(fds[i]);
		if (ret == -1) {
			pr_perror("Unable to dup %d", fds[i]);
			return -1;
		}

		fds[i] = ret;
	}

	for (i = 0; i < n; i++) {
		if (fds[i] == i)
			continue;

		if (dup2(fds[i], i) == -1) {
			pr_perror("Unable to dup %d -> %d", fds[i], i);
			return -1;
		}

		fds[i] = i;
	}

	return close_fds(proc_fd, n);
}

int spawn_sock_wait(sk)
{
	int ret = INT_MIN;
	read(sk, &ret, sizeof(ret));
	return ret;
}

int spawn_sock_wait_and_close(int sk)
{
	int ret = spawn_sock_wait(sk);
	shutdown(sk, SHUT_RD);
	return ret;
}

void spawn_sock_wake(int sk, int ret)
{
	write(sk, &ret, sizeof(ret));
}

void spawn_sock_wake_and_close(int sk, int ret)
{
	write(sk, &ret, sizeof(ret));
	shutdown(sk, SHUT_WR);
}
