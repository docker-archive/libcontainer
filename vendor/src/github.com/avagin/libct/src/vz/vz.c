#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/personality.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/socket.h>

#include "beancounter.h"
#include "vzcalluser.h"
#include "vzlist.h"
#include "vziolimit.h"
#include "linux-kernel.h"
#include "vz.h"
#include "ct.h"
#include "xmalloc.h"
#include "fs.h"
#include "vzsyscalls.h"
#include "readelf.h"
#include "cgroups.h"
#include "net.h"
#include "util.h"
#include "vz_net.h"
#include "err.h"

#define MAX_SHTD_TM 			120
#define VZCTLDEV			"/dev/vzctl"
#define ENVRETRY 			3
#define IOPRIO_CLASS_BE			2
#define IOPRIO_CLASS_SHIFT		13
#define IOPRIO_WHO_UBC			1000

typedef enum {
	M_HALT,
	M_REBOOT,
	M_KILL,
	M_KILL_FORCE,
} stop_mode_e;

struct info_pipes {
	int *in;
	int *out;
	int *err;
	int wait_sock;
};

static int __vzctlfd = -1;

void vzctl_close(void)
{
	if (__vzctlfd != -1)
		close(__vzctlfd);
}

int vzctl_open(void)
{
	if (__vzctlfd != -1)
		return 0;

	__vzctlfd = open(VZCTLDEV, O_RDWR);
	if (__vzctlfd == -1) {
		pr_perror("Unable to open " VZCTLDEV);
		return -1;
	}

	return 0;
}

int get_vzctlfd(void)
{
	if (__vzctlfd == -1)
		vzctl_open();

	return __vzctlfd;
}

static int configure_sysctl(const char *var, const char *val)
{
	int fd = -1, len = -1, ret = -1;

	if (!var || !val)
		return -LCTERR_BADARG;

	fd = open(var, O_WRONLY);
	if (fd == -1)
		return -1;

	len = strlen(val);
	ret = write(fd, val, strlen(val));
	close(fd);

	return ret == len ? 0 : -1;
}

static int set_personality(unsigned long mask)
{
	unsigned long per;

	per = personality(0xffffffff) | mask;
	if (personality(per) == -1)
		return -1;
	return 0;
}

static int set_personality32(void)
{
#ifdef  __x86_64__
	if (get_arch_from_elf("/sbin/init") == elf_32)
		return set_personality(PER_LINUX32);
#endif
	return 0;
}

static void vz_ct_destroy(ct_handler_t h)
{
	struct container *ct = cth2ct(h);

	cgroups_free(ct);
	fs_free(ct);
	net_release(ct);

	xfree(ct->name);
	xfree(ct->hostname);
	xfree(ct->domainname);
	xfree(ct->cgroup_sub);
	xfree(ct);
}

static int env_is_run(unsigned veid)
{
	struct vzctl_env_create env_create;
	int errcode;
	int retry = 0;

	memset(&env_create, 0, sizeof(env_create));
	env_create.veid = veid;
	env_create.flags = VE_TEST;
	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE, &env_create);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);

	if (errcode < 0 && (errno == ESRCH || errno == ENOTTY)) {
		return 0;
	} else if (errcode < 0) {
		pr_perror("unable to get Container state");
		return -1;
	}
	return 1;
}

static int env_get_pids_ioctl(unsigned veid, pid_t **pid)
{
	struct vzlist_vepidctl ve;
	int i, ret, size;
	pid_t buf[4096 * 2];
	pid_t *tmp;

	ve.veid = veid;
	ve.num = sizeof(buf) / 2;
	ve.pid = buf;
	while (1) {
		ret = ioctl(get_vzctlfd(), VZCTL_GET_VEPIDS, &ve);
		if (ret <= 0) {
			goto err;
		} else if (ret <= ve.num)
			break;
		size = ret + 20;
		if (ve.pid == buf)
			tmp = malloc(size * (2 * sizeof(pid_t)));
		else
			tmp = realloc(ve.pid, size * (2 * sizeof(pid_t)));
		if (tmp == NULL) {
			ret = -1;
			goto err;
		}
		ve.num = size;
		ve.pid = tmp;
	}
	*pid = malloc(ret * sizeof(pid_t));
	if (*pid == NULL) {
		ret = -1;
		goto err;
	}
	/* Copy pid from [pid:vpid] pair */
	for (i = 0; i < ret; i++)
		(*pid)[i] = ve.pid[2*i];
err:
	if (ve.pid != buf)
		free(ve.pid);
	return ret;
}

static int ublimit_mem_syscall(unsigned int veid, int type, unsigned long value)
{
	unsigned long param[2] = {value, value};

	return syscall(__NR_setublimit, veid, type, param);
}

static int vz_set_memory_param(struct container *ct, char *param, char *value)
{
	unsigned long ram = 0;
	unsigned long swap = 0;
	float overcommit = LONG_MAX;
	float memory;
	unsigned int veid = 0;;

	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID\n");
		return -1;
	}

	if (strcmp(param, "limit_in_bytes") == 0) {
		if (parse_uint(value, (unsigned int *)&ram) < 0) {
			pr_err("Unable to parse container's RAM\n");
			return -1;
		}
		ram /= getpagesize();

		if (ublimit_mem_syscall(veid, UB_PHYSPAGES, ram)) {
			pr_perror("Unable to set UB_LOCKEDPAGES");
			return -1;
		}

		if (ublimit_mem_syscall(veid, UB_SWAPPAGES, 0)) {
			pr_perror("Unable to set UB_LOCKEDPAGES");
			return -1;
		}

		if (ublimit_mem_syscall(veid, UB_LOCKEDPAGES, ram)) {
			pr_perror("Unable to set UB_LOCKEDPAGES");
			return -1;
		}

		if (ublimit_mem_syscall(veid, UB_OOMGUARPAGES, ram)) {
			pr_perror("Unable to set UB_OOMGUARPAGES");
			return -1;
		}

		if (ublimit_mem_syscall(veid, UB_VMGUARPAGES, ram + swap)) {
			pr_perror("Unable to set UB_VMGUARPAGES");
			return -1;
		}

		memory = (ram + swap) * overcommit;
		if (memory > LONG_MAX)
			memory = UINT_MAX;

		if (ublimit_mem_syscall(veid, UB_PRIVVMPAGES, memory)) {
			pr_perror("Unable to set UB_PRIVVMPAGES");
			return -1;
		}
		return 0;
	}

	pr_err("Unsupported param for CTL_MEMORY: %s\n", param);
	return -1;
}

static int vzctl2_set_iopslimit(unsigned veid, int limit)
{
	int ret;
	struct iolimit_state io;

	if (limit < 0)
		return -LCTERR_BADARG;
	io.id = veid;
	io.speed = limit;
	io.burst = limit * 3;
	io.latency = 10*1000;
	pr_info("Set up iopslimit: %d\n", limit);
	ret = ioctl(get_vzctlfd(), VZCTL_SET_IOPSLIMIT, &io);
	if (ret) {
		if (errno == ESRCH) {
			pr_err("Container is not running\n");
			return -LCTERR_BADCTSTATE;
		}
		else if (errno == ENOTTY) {
			pr_warn("iopslimit feature is not supported"
				" by the kernel; iopslimit configuration is skipped\n");
			return -LCTERR_OPNOTSUPP;
		}
		pr_perror("Unable to set iopslimit");
		return -1;
	}
	return 0;
}

static int vzctl2_set_ioprio(unsigned veid, int prio)
{
	int ret;

	if (prio < 0)
		return -LCTERR_BADARG;

	pr_info("Set up ioprio: %d\n", prio);
	ret = syscall(__NR_ioprio_set, IOPRIO_WHO_UBC, veid,
			prio | IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT);
	if (ret) {
		if (errno == ESRCH) {
			pr_err("Container is not running\n");
			return -LCTERR_BADCTSTATE;
		}
		else if (errno == EINVAL) {
			pr_warn("ioprio feature is not supported"
				" by the kernel: ioprio configuration is skippe\n");
			return -LCTERR_OPNOTSUPP;
		}
		pr_perror("Unable to set ioprio");
		return -1;
	}
	return 0;
}

static int vz_set_io_param(struct container *ct, char *param, char *value)
{
	unsigned int veid = 0;

	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID\n");
		return -1;
	}

	if (strcmp(param, "weight") == 0) {
		int prio = -1;
		if (parse_int(value, &prio)) {
			pr_err("Unable to parse priority from '%s'\n", value);
			return -1;
		}
		return vzctl2_set_ioprio(veid, prio);
	} else if (strcmp(param, "throttle.write_iops_device") == 0 ||
			strcmp(param, "throttle.read_iops_device") == 0) {
		int limit = -1;
		if (parse_int(value, &limit)) {
			pr_err("Unable to parse limit from '%s'\n", value);
			return -1;
		}
		return vzctl2_set_iopslimit(veid, limit);
	}

	pr_err("Unsupported param for CTL_BLKIO: %s\n", param);
	return -1;
}


static int vz_bc_resources_set(struct container *ct)
{
	struct cg_config *cfg;
	int ret = 0;

	list_for_each_entry(cfg, &ct->cg_configs, l) {
		switch (cfg->ctype) {
		case CTL_MEMORY:
			ret = vz_set_memory_param(ct, cfg->param, cfg->value);
			if (ret)
				return -LCTERR_CGCONFIG;
			break;
		case CTL_BLKIO:
			ret = vz_set_io_param(ct, cfg->param, cfg->value);
			if (ret)
				return -LCTERR_CGCONFIG;
			break;
		case CTL_CPU:
		case CTL_CPUSET:
			ret = config_controller(ct, cfg->ctype, cfg->param, cfg->value);
			if (ret) {
				pr_err("local_config_controller failed %d\n", ret);
				return -LCTERR_CGCONFIG;
			}
			break;
		default:
			return -LCTERR_OPNOTSUPP;
			break;
		}
	}

	return 0;
}

int pre_setup_env(ct_handler_t h, struct info_pipes *pipes)
{
	struct container *ct = NULL;
	int fd;
	int ret = 0;
	if (!h)
		return -1;
	ct = cth2ct(h);

	/* Clear supplementary group IDs */
	setgroups(0, NULL);

	if ((ret = set_personality32()))
		return ret;

	/* Create /fastboot to skip run fsck */
	fd = creat("/fastboot", 0644);
	if (fd != -1)
		close(fd);

	if (ct->flags & CT_AUTO_PROC)
		mount("proc", "/proc", "proc", 0, 0);
	if (stat_file("/sys"))
		mount("sysfs", "/sys", "sysfs", 0, 0);

	if (ct->flags & CT_AUTO_PROC)
		configure_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");

	spawn_sock_wake(pipes->wait_sock, 0);
	ret = spawn_sock_wait(pipes->wait_sock);
	if (ret)
		return -1;

	return 0;
}

static int env_kill(unsigned veid)
{
	int ret, i;
	pid_t *pids = NULL;

	ret = env_get_pids_ioctl(veid, &pids);
	if (ret < 0)
		return -1;
	/* Kill all Container processes from VE0 */
	for (i = 0; i < ret; i++)
		kill(pids[i], SIGKILL);

	if (pids != NULL) free(pids);

	/* Wait for real Container shutdown */
	for (i = 0; i < (MAX_SHTD_TM / 2); i++) {
		if (!env_is_run(veid))
			return 0;
		usleep(500000);
	}
	return -1;
}

static int env_wait(int pid, int timeout, int *retcode)
{
	int ret, status;

	while ((ret = waitpid(pid, &status, 0)) == -1) {
		if (errno != EINTR) {
			pr_perror("Error in waitpid(%d)", pid);
			return -1;
		}
	}

	ret = -1;
	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (retcode != NULL) {
			*retcode = ret;
			ret = 0;
		}
	} else if (WIFSIGNALED(status)) {
		pr_info("Got signal %d\n", WTERMSIG(status));
		if (timeout) {
			pr_err("Timeout while waiting\n");
			return -1;
		}
	}

	return ret;
}

static int vzctl_chroot(const char *root)
{
	int i;
	sigset_t sigset;
	struct sigaction act;

	if (root == NULL)
		return -1;

        if (chdir(root)) {
                pr_perror("unable to change dir to %s", root);
		return -1;
	}
	if (chroot(".")) {
		pr_perror("chroot %s failed", root);
		return -1;
	}
	if (setsid() == -1)
		pr_perror("setsid()");

	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);
	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;
	for (i = 1; i <= NSIG; ++i)
		sigaction(i, &act, NULL);
	return 0;
}

static int vzctl_env_create_ioctl(unsigned veid, int flags)
{
	struct vzctl_env_create env_create;
	int errcode;
	int retry = 0;

	memset(&env_create, 0, sizeof(env_create));
	env_create.veid = veid;
	env_create.flags = flags;
	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE, &env_create);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);
#ifdef  __x86_64__
	/* Set personality PER_LINUX32 for i386 based VEs */
	if (errcode >= 0 && (flags & VE_ENTER))
		set_personality32();
#endif
	return errcode;
}

int env_create_data_ioctl(struct vzctl_env_create_data *data)
{
	int errcode;
	int retry = 0;

	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE_DATA, data);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);
#ifdef  __x86_64__
	/* Set personality PER_LINUX32 for i386 based VEs */
	if (errcode >= 0)
		set_personality32();
#endif
	return errcode;
}

static int exec_init(struct execv_args *ea)
{
	if (ea == NULL)
		return -LCTERR_BADARG;

	pr_info("executing command %s\n", ea->path);

	execve(ea->path, ea->argv, ea->env);
	return -1;
}

static int env_exec_create_data_ioctl(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	int ret, eno;
	unsigned int veid;
	struct vzctl_env_create_data env_create_data;
	struct env_create_param3 create_param;

	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID\n");
		return -1;
	}

	memset(&create_param, 0, sizeof(struct env_create_param3));

	env_create_data.veid = veid;
	env_create_data.class_id = 0;
	env_create_data.flags = VE_CREATE | VE_EXCLUSIVE;
	env_create_data.data = &create_param;
	env_create_data.datalen = sizeof(struct env_create_param3);

try:
	ret = env_create_data_ioctl(&env_create_data);
	if (ret < 0) {
		eno = errno;
		switch(eno) {
		case EINVAL:
			ret = -1;
			/* Run-time kernel did not understand the
			 * latest create_param -- so retry with
			 * the old env_create_param structs.
			 */
			switch (env_create_data.datalen) {
			case sizeof(struct env_create_param3):
				env_create_data.datalen =
					sizeof(struct env_create_param2);
				goto try;
			case sizeof(struct env_create_param2):
				env_create_data.datalen =
					sizeof(struct env_create_param);
				goto try;
			}
			break;
		case EACCES:
			pr_err("License is not loaded\n");
			break;
		case ENOTTY:
			pr_err("Some vz modules are not present\n");
			break;
		default:
			pr_perror("VZCTL_ENV_CREATE_DATA");
			break;
		}
		ret = -1;
		return ret;
	}

	return 0;
}

static int env_create(ct_handler_t h, struct info_pipes *pipes)
{
	int ret;
	struct container *ct = cth2ct(h);

	if (ct->nsmask) {
		if ((ret = env_exec_create_data_ioctl(h)))
			return ret;
	}
	if ((ret = pre_setup_env(h, pipes)))
		return ret;

	return 0;
}

static int vz_resources_create(struct container *ct)
{
	struct controller *ctl;
	int ret = 0;
	unsigned int veid;

	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID\n");
		return -1;
	}

	list_for_each_entry(ctl, &ct->cgroups, ct_l) {
		switch (ctl->ctype) {
		case CTL_MEMORY:
		case CTL_BLKIO:
			ret = syscall(__NR_setluid, veid);
			if (ret)
				return -LCTERR_CGCREATE;
			break;
		case CTL_CPU:
		case CTL_CPUSET:
			if (ct->nsmask == 0) {
				ret = cgroup_create_one(ct, ctl);
				if (ret)
					return -LCTERR_CGCREATE;
			}
			break;
		default:
			return -LCTERR_OPNOTSUPP;
			break;
		}
	}

	return 0;
}


struct ct_clone_arg {
	char stack[PAGE_SIZE] __attribute__((aligned (8)));
	char stack_ptr[0];
	ct_handler_t h;
	struct info_pipes *pipes;
	struct execv_args *ea;
	unsigned int veid;
	int proc_fd;
	int *fds;
	int fdn;
};

static int ct_clone(void *arg)
{
	struct ct_clone_arg *ca = arg;
	int ret;

	ret = env_create(ca->h, ca->pipes);
	if (ret)
		goto err;

	if (ca->fds) {
		ca->fds[ca->fdn] = ca->pipes->wait_sock;
		if (setup_fds_at(ca->proc_fd, ca->fds, ca->fdn + 1))
			goto err;
		ca->pipes->wait_sock = ca->fdn;
		if (fcntl(ca->pipes->wait_sock, F_SETFD, FD_CLOEXEC))
			goto err;
	}

	spawn_sock_wake(ca->pipes->wait_sock, 0);

	exec_init(ca->ea);
err:
	spawn_sock_wake_and_close(ca->pipes->wait_sock, -1);
	_exit(ret);
}

static int vz_env_create(ct_handler_t h, ct_process_desc_t ph, struct info_pipes *pipes, struct execv_args *ea)
{
	struct ct_clone_arg ca;
	int ret, pid;
	struct container *ct = cth2ct(h);
	struct process_desc *p = prh2pr(ph);
	unsigned int veid;

	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID\n");
		return -1;
	}

	ca.proc_fd = open("/proc/", O_DIRECTORY | O_RDONLY);
	if (ca.proc_fd == -1) {
		pr_perror("Unable to open /proc");
		return -1;
	}

	if (!ct->root_path) {
		pr_err("Container %s root_path is empty!\n", ct->name);
		return -1;
	}
	if ((ret = vzctl_chroot(ct->root_path)))
		goto err;

	ret = vz_resources_create(ct);
	if (ret)
		goto err;

	ca.pipes = pipes;
	ca.ea = ea;
	ca.h = h;
	ca.fds = p->fds;
	ca.fdn = p->fdn;
	pid = clone(ct_clone, &ca.stack_ptr, SIGCHLD | CLONE_PARENT, &ca);
	if (pid < 0) {
		pr_perror("Can not fork");
		ret = -1;
		goto err;
	}
	if (write(pipes->wait_sock, &pid, sizeof(pid)) == -1) {
		pr_perror("Unable to write to parent_wait pipe");
		goto err;
	}

	return 0;

err:
	if (write(pipes->wait_sock, &ret, sizeof(ret)) == -1)
		pr_perror("Failed write() pipes->parent_wait[1] vz_env_create");
	return ret;
}

static ct_process_t vz_spawn_cb(ct_handler_t h, ct_process_desc_t p, int (*cb)(void *), void *arg)
{
	pr_err("Spawn with callback is not supported\n");
	return ERR_PTR(-1);
}

static ct_process_t vz_spawn_execve(ct_handler_t h, ct_process_desc_t p, char *path, char **argv, char **env)
{
	int ret = -1;
	struct container *ct = cth2ct(h);
	struct execv_args ea = {
		.path = path,
		.argv = argv,
		.env = env,
	};
	struct info_pipes pipes = {
		.wait_sock = -1,
	};
	struct sigaction act;
	int pid = -1;
	int root_pid = -1;
	int wait_socks[2];
	int wait_sock = -1;

	if (ct->state != CT_STOPPED) {
		ret = -LCTERR_BADCTSTATE;
		goto err;
	}

	if (socketpair(AF_FILE, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, wait_socks)) {
		pr_perror("Unable to create a socket pair");
		goto err;
	}

	wait_sock = wait_socks[0];
	pipes.wait_sock = wait_socks[1];

	ret = fs_mount(ct);
	if (ret) {
		pr_err("Unable to mount fs\n");
		goto err_pipe;
	}

	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGPIPE, &act, NULL);
	pid = fork();
	if (pid < 0) {
		pr_perror("Cannot fork");
		close(pipes.wait_sock);
		ret = -1;
		goto err_fork;
	} else if (pid == 0) {
		close(wait_sock);
		sigaction(SIGCHLD, &act, NULL);

		ret = vz_env_create(h, p, &pipes, &ea);

		_exit(ret);
	}
	close(pipes.wait_sock);

	root_pid = spawn_sock_wait(wait_sock);
	if (root_pid < 0) {
		pr_perror("Unable to read parent_wait pipe");
		env_wait(pid, 0, NULL);
		ret = -1;
		goto err_fork;
	}
	ct->p.pid = root_pid;

	env_wait(pid, 0, NULL);

	if (spawn_sock_wait(wait_sock) == -1) {
		ret = -1;
		goto err_res;
	}

	ret = vz_bc_resources_set(ct);
	if (ret) {
		pr_err("vz_bc_resource_set\n");
		goto err_res;
	}

	ret = net_start(ct);
	if (ret) {
		pr_err("Unable to start network\n");
		goto err_net;
	}

	spawn_sock_wake_and_close(wait_sock, 0);

	/* Wait while network would be configured inside container */
	if (spawn_sock_wait(wait_sock)) {
		ret = -1;
		goto err_wait;
	}

	/* Wait while network would be configured inside container */
	if (spawn_sock_wait_and_close(wait_sock) != INT_MIN) {
		ret = -1;
		goto err_wait;
	}

	close(wait_sock);

	ct->state = CT_RUNNING;
	return &ct->p.h;

err_wait:
	net_stop(ct);
err_net:
err_res:
	spawn_sock_wake_and_close(wait_sock, -1);
	libct_process_wait(&ct->p.h, NULL);
err_fork:
	fs_umount(ct);
err_pipe:
	close(wait_sock);
err:
	return ERR_PTR(ret);
}

static int vz_set_option(ct_handler_t h, int opt, void *args)
{
	int ret = -LCTERR_BADTYPE;
	struct container *ct = cth2ct(h);

	switch (opt) {
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		ret = 0;
		ct->flags |= CT_AUTO_PROC;
		break;
	case LIBCT_OPT_CGROUP_SUBMOUNT:
		pr_warn("LIBCT_OPT_CGROUP_SUBMOUNT is currently unsupported");
		ret = -1;
		break;
	case LIBCT_OPT_KILLABLE:
		pr_warn("LIBCT_OPT_KILLABLE option is always set for VZ containers");
		ret = -1;
		break;
	case LIBCT_OPT_NOSETSID:
		pr_warn("LIBCT_OPT_NOSETSID option is always set for VZ containers");
		ret = -1;
		break;
	}

	return ret;
}

static int vz_ct_kill(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	unsigned int veid;

	if (parse_uint(ct->name, &veid) == -1)
		return -LCTERR_NOTFOUND;

	if (ct->state != CT_RUNNING)
		return -LCTERR_BADCTSTATE;
	if (ct->nsmask & CLONE_NEWPID)
		return kill(ct->p.pid, SIGKILL);
	return env_kill(veid); /* for VZ containers CT_KILLABLE option is ignored */
}

static int vz_ct_wait(ct_handler_t h)
{
	struct container *ct = NULL;
	unsigned int veid = -1;

	if (!h)
		return -LCTERR_BADARG;

	ct = cth2ct(h);
	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID\n");
		return -1;
	}

	if (ct->state != CT_RUNNING)
		return -LCTERR_BADCTSTATE;

	if (ct->p.pid > 0)
		libct_process_wait(&ct->p.h, NULL);
	if (!env_is_run(veid)) {
		pr_info("Container was stopped\n");
		return 0;
	}
	fs_umount(ct);
	cgroups_destroy(ct);
	net_stop(ct);

	pr_info("Forcibly kill the Container...\n");
	if (env_kill(veid)) {
		pr_err("Unable to stop Container: operation timed out\n");
		return -1;
	}
	ct->state = CT_STOPPED;
	return 0;
}

static int vz_uname(ct_handler_t h, char *host, char *dom)
{
	struct container *ct = NULL;

	if (!h)
		return -LCTERR_BADARG;

	ct = cth2ct(h);
	if (!(ct->nsmask & CLONE_NEWUTS))
		return -LCTERR_NONS;
	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE; /* FIXME */

	if (host) {
		host = xstrdup(host);
		if (!host)
			return -1;
	}
	xfree(ct->hostname);
	ct->hostname = host;

	if (dom) {
		dom = xstrdup(dom);
		if (!dom)
			return -1;
	}
	xfree(ct->domainname);
	ct->domainname = dom;

	return 0;
}

static enum ct_state vz_get_state(ct_handler_t h)
{
	if (!h)
		return CT_ERROR;
	return cth2ct(h)->state;
}

static int vz_set_console_fd(ct_handler_t h, int fd)
{
	struct container *ct = NULL;
	if (!h || fd == -1)
		return -LCTERR_BADARG;
	ct = cth2ct(h);
	ct->tty_fd = fd;
	return 0;
}

static int vz_set_nsmask(ct_handler_t h, unsigned long nsmask)
{
	struct container *ct = NULL;
	if (!h)
		return -LCTERR_BADARG;
	ct = cth2ct(h);
	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;
	/* Are all of these bits supported by kernel? */
	if (nsmask & ~kernel_ns_mask)
		return -LCTERR_NONS;

	if (!(nsmask & CLONE_NEWIPC &&
	      nsmask & CLONE_NEWNET &&
	      nsmask & CLONE_NEWNS &&
	      nsmask & CLONE_NEWPID &&
	      nsmask & CLONE_NEWUTS)) {
		pr_err("Only full nsmask is supported in VZ containers\n");
		return -LCTERR_NONS;
	}
	ct->nsmask = nsmask;
	return 0;
}

static int ct_enter(void *arg)
{
	struct ct_clone_arg *ca = arg;
	struct container *ct = cth2ct(ca->h);
	int ret;

	if (ct->nsmask) {
		ret = vzctl_env_create_ioctl(ca->veid, VE_ENTER);
		if (ret < 0) {
			pr_perror("ioctl failed");
			_exit(1);
		}
	}

	if (ca->fds) {
		ca->fds[ca->fdn] = ca->pipes->wait_sock;
		if (setup_fds_at(ca->proc_fd, ca->fds, ca->fdn + 1))
			goto err;
		ca->pipes->wait_sock = ca->fdn;
		if (fcntl(ca->pipes->wait_sock, F_SETFD, FD_CLOEXEC))
			goto err;
	}

	spawn_sock_wake(ca->pipes->wait_sock, 0);

	exec_init(ca->ea);
	pr_perror("Unable to execve");
err:
	spawn_sock_wake_and_close(ca->pipes->wait_sock, -1);
	_exit(-1);
	return -1;
}

static ct_process_t vz_enter_execve(ct_handler_t h, ct_process_desc_t ph, char *path, char **argv, char **env)
{
	struct ct_clone_arg ca;
	struct container *ct = NULL;
	struct process_desc *p = prh2pr(ph);
	struct process *pr;
	unsigned int veid = -1;
	int pid, child_pid, ret = 0;
	struct execv_args ea = {
		.path = path,
		.argv = argv,
		.env = env,
	};
	int wait_socks[2], wait_sock = -1;
	struct info_pipes pipes = {
		.wait_sock = -1,
	};

	if (!h)
		return ERR_PTR(-LCTERR_BADARG);

	ct = cth2ct(h);

	if (ct->state != CT_RUNNING)
		return ERR_PTR(-LCTERR_BADCTSTATE);

	if (parse_uint(ct->name, &veid) < 0) {
		pr_err("Unable to parse container's ID\n");
		return ERR_PTR(-LCTERR_BADARG);
	}

	pr = xmalloc(sizeof(struct process));
	if (pr == NULL)
		return ERR_PTR(-1);

	local_process_init(pr);

	if (socketpair(AF_FILE, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, wait_socks)) {
		pr_perror("Unable to create a socket pair");
		goto err;
	}
	wait_sock = wait_socks[0];
	pipes.wait_sock = wait_socks[1];

	pid = fork();
	if (pid < 0) {
		close(pipes.wait_sock);
		pr_perror("Cannot fork");
		goto err;
	} else if (pid == 0) {
		close(wait_sock);

		ca.proc_fd = open("/proc/", O_DIRECTORY | O_RDONLY);
		if (ca.proc_fd == -1)
			_exit(-1);

		ret = vz_resources_create(ct);
		if (ret) {
			pr_perror("Unable to create resources for container %ld", veid);
			_exit(ret);
		}

		ret = vzctl_chroot(ct->root_path);
		if (ret)
			_exit(ret);

		ca.ea = &ea;
		ca.h = h;
		ca.veid = veid;
		ca.pipes = &pipes;
		ca.fds = p->fds;
		ca.fdn = p->fdn;

		pr_info("Entering the Container %ld\n", veid);
		child_pid = clone(ct_enter, &ca.stack_ptr, SIGCHLD | CLONE_PARENT, &ca);
		if (child_pid < 0) {
			pr_perror("Unable to stop Container, fork failed");
			_exit(1);
		}

		spawn_sock_wake(pipes.wait_sock, child_pid);
		_exit(0);
	}
	close(pipes.wait_sock);

	child_pid = spawn_sock_wait(wait_sock);
	if (child_pid < 0) {
		pr_perror("Unable to read parent_wait pipe");
		env_wait(pid, 0, NULL);
		ret = -1;
		goto err;
	}
	env_wait(pid, 0, NULL);

	if (spawn_sock_wait(wait_sock)) {
		ret = -1;
		goto err_wait;
	}

	if (spawn_sock_wait_and_close(wait_sock) != INT_MIN) {
		ret = -1;
		goto err_wait;
	}

	pr->pid = child_pid;

	return &pr->h;
err_wait:
	env_wait(child_pid, 0, NULL);
err:
	close(wait_sock);
	xfree(pr);
	return ERR_PTR(-1);
}

static ct_process_t vz_enter_cb(ct_handler_t h, ct_process_desc_t p, int (*cb)(void *), void *arg)
{
	pr_err("Enter with callback is not supported\n");
	return ERR_PTR(-1);
}

static const struct container_ops vz_ct_ops = {
	.spawn_cb		= vz_spawn_cb,
	.spawn_execve		= vz_spawn_execve,
	.enter_cb		= vz_enter_cb,
	.enter_execve		= vz_enter_execve,
	.kill			= vz_ct_kill,
	.wait			= vz_ct_wait,
	.destroy		= vz_ct_destroy,
	.detach			= vz_ct_destroy,
	.set_nsmask		= vz_set_nsmask,
	.add_controller		= local_add_controller,
	.config_controller	= local_config_controller,
	.read_controller	= local_read_controller,
	.fs_set_root		= local_fs_set_root,
	.fs_set_private		= local_fs_set_private,
	.fs_add_mount		= local_add_mount,
	.fs_add_bind_mount	= local_add_bind_mount,
	.fs_del_bind_mount	= local_del_bind_mount,
	.fs_add_devnode		= NULL,
	.get_state		= vz_get_state,
	.set_option		= vz_set_option,
	.set_console_fd		= vz_set_console_fd,
	.net_add		= vz_net_add,
	.net_del		= local_net_del,
	.net_route_add		= local_net_route_add,
	.uname			= vz_uname,
};

const struct container_ops *get_vz_ct_ops(void)
{
	return &vz_ct_ops;
}

ct_handler_t vz_ct_create(char *name)
{
	struct container *ct;

	ct = xzalloc(sizeof(*ct));
	if (ct) {
		ct_handler_init(&ct->h);
		local_process_init(&ct->p);
		ct->h.ops = get_vz_ct_ops();
		ct->state = CT_STOPPED;
		ct->name = xstrdup(name);
		ct->tty_fd = -1;
		INIT_LIST_HEAD(&ct->cgroups);
		INIT_LIST_HEAD(&ct->cg_configs);
		INIT_LIST_HEAD(&ct->ct_nets);
		INIT_LIST_HEAD(&ct->ct_net_routes);
		INIT_LIST_HEAD(&ct->fs_mnts);
		INIT_LIST_HEAD(&ct->fs_devnodes);
		INIT_LIST_HEAD(&ct->uid_map);
		INIT_LIST_HEAD(&ct->gid_map);

		return &ct->h;
	}

	return NULL;

}
