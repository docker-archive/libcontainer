#ifndef __UAPI_LIBCT_H__
#define __UAPI_LIBCT_H__

#include <sys/types.h>
#include <stdint.h>
#include "libct-errors.h"

/*
 * Session management
 */

struct libct_session;
typedef struct libct_session *libct_session_t;

extern void *libct_err_to_handle(long err);
extern long libct_handle_to_err(void *handle);
extern int libct_handle_is_err(void *handle);

extern libct_session_t libct_session_open(char *url);
extern libct_session_t libct_session_open_local(void);
extern void libct_session_close(libct_session_t s);

/*
 * Basic container management
 */

struct ct_handler;
typedef struct ct_handler *ct_handler_t;

struct ct_process_desc;
typedef struct ct_process_desc *ct_process_desc_t;

struct ct_process;
typedef struct ct_process *ct_process_t;

enum ct_state {
	CT_ERROR = -1,
	CT_STOPPED,
	CT_RUNNING,
	CT_PAUSED,
};

extern ct_handler_t libct_container_create(libct_session_t ses, char *name);
extern ct_handler_t libct_container_open(libct_session_t ses, char *name);
extern void libct_container_close(ct_handler_t ct);

enum ct_state libct_container_state(ct_handler_t ct);
extern ct_process_t libct_container_load(ct_handler_t ct, pid_t pid);
extern ct_process_t libct_container_spawn_cb(ct_handler_t ct, ct_process_desc_t pr, int (*ct_fn)(void *), void *arg);
extern ct_process_t libct_container_spawn_execv(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv);
extern ct_process_t libct_container_spawn_execve(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv, char **env);
extern ct_process_t libct_container_enter_cb(ct_handler_t ct, ct_process_desc_t p, int (*ct_fn)(void *), void *arg);
extern ct_process_t libct_container_enter_execv(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv);
extern ct_process_t libct_container_enter_execve(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv, char **env);
extern int libct_container_kill(ct_handler_t ct);
extern int libct_container_wait(ct_handler_t ct);
extern void libct_container_destroy(ct_handler_t ct);

/*
 * CT namespaces and cgroups management
 */

extern int libct_container_set_nsmask(ct_handler_t ct, unsigned long ns_mask);
extern int libct_container_set_nspath(ct_handler_t ct, int ns, char *path);
extern int libct_container_set_sysctl(ct_handler_t ct, char *name, char *val);

enum ct_controller {
	CTL_BLKIO,
	CTL_CPU,
	CTL_CPUACCT,
	CTL_CPUSET,
	CTL_DEVICES,
	CTL_FREEZER,
	CTL_HUGETLB,
	CTL_MEMORY,
	CTL_NETCLS,
	CT_NR_CONTROLLERS
};

extern int libct_controller_add(ct_handler_t ct, enum ct_controller ctype);
extern int libct_controller_configure(ct_handler_t ct, enum ct_controller ctype, char *param, char *value);
extern int libct_controller_read(ct_handler_t ct, enum ct_controller ctype, char *param, void *buf, size_t len);

extern int libct_container_uname(ct_handler_t ct, char *host, char *domain);

extern int libct_container_pause(ct_handler_t ct);
extern int libct_container_resume(ct_handler_t ct);

/*
 * FS configuration
 */

extern int libct_fs_set_root(ct_handler_t ct, char *root_path);

enum ct_fs_type {
	CT_FS_NONE,	/* user may prepare himself */
	CT_FS_SUBDIR,	/* just a directory in existing tree */
};

extern int libct_fs_set_private(ct_handler_t ct, enum ct_fs_type type, void *arg);

#define CT_FS_RDONLY		0x0001
#define CT_FS_PRIVATE		0x0002
#define CT_FS_BIND		0x0004
#define CT_FS_NOEXEC		0x0008
#define CT_FS_NOSUID		0x0010
#define CT_FS_NODEV		0x0020
#define CT_FS_STRICTATIME	0x0040
#define CT_FS_REC		0x0080

struct libct_cmd {
	struct libct_cmd *next;

	char *path;
	char **argv;
	char **envp;
	char *dir;
};

extern int libct_fs_add_bind_mount(ct_handler_t ct, char *source, char *destination, int flags);
extern int libct_fs_del_bind_mount(ct_handler_t ct, char *destination);
extern int libct_fs_add_mount(ct_handler_t ct, char *src, char *dst,
					int flags, char *fstype, char *data);
extern int libct_fs_add_mount_with_actions(ct_handler_t ct, char *src, char *dst,
					int flags, char *fstype, char *data,
					struct libct_cmd *pre, struct libct_cmd *post);
/*
 * Networking configuration
 */

enum ct_net_type {
	CT_NET_NONE,	/* no configured networking */
	CT_NET_HOSTNIC,	/* assign nic from host */
	CT_NET_VETH,	/* assign veth pair */
};

struct ct_net_veth_arg {
	char *host_name;
	char *ct_name;
	/* FIXME -- macs */
};

struct ct_net;
typedef struct ct_net *ct_net_t;

extern ct_net_t libct_net_add(ct_handler_t ct, enum ct_net_type ntype, void *arg);
extern int libct_net_del(ct_handler_t ct, enum ct_net_type ntype, void *arg);
extern int libct_net_dev_set_mac_addr(ct_net_t n, char *addr);
extern int libct_net_dev_set_master(ct_net_t n, char *master);
extern ct_net_t libct_net_dev_get_peer(ct_net_t n);
extern int libct_net_dev_add_ip_addr(ct_net_t n, char *addr);
extern int libct_net_dev_set_mtu(ct_net_t n, int mtu);

struct ct_net_route;
typedef struct ct_net_route *ct_net_route_t;

extern ct_net_route_t libct_net_route_add(ct_handler_t ct);
extern int libct_net_route_set_src(ct_net_route_t r, char *addr);
extern int libct_net_route_set_dst(ct_net_route_t r, char *addr);
extern int libct_net_route_set_dev(ct_net_route_t r, char *dev);

struct ct_net_route_nh;
typedef struct ct_net_route_nh *ct_net_route_nh_t;

extern ct_net_route_nh_t libct_net_route_add_nh(ct_net_route_t r);
extern int libct_net_route_nh_set_gw(ct_net_route_nh_t nh, char *addr);
extern int libct_net_route_nh_set_dev(ct_net_route_nh_t nh, char *dev);

extern int libct_userns_add_uid_map(ct_handler_t ct, unsigned int first,
				unsigned lower_first, unsigned int count);
extern int libct_userns_add_gid_map(ct_handler_t ct, unsigned int first,
				unsigned lower_first, unsigned int count);

/*
 * Options
 */

/* Mount proc when PID _and_ mount namespaces are used together */
#define LIBCT_OPT_AUTO_PROC_MOUNT			1
/*
 * Bind mount CT's cgroup inside CT to let it create subgroups 
 * Argument: path where to mount it. NULL results in libct default
 */
#define LIBCT_OPT_CGROUP_SUBMOUNT			2
/*
 * Make it possible to libct_container_kill(). This is always
 * so when nsmask includes PIDNS, but if not this option will
 * help.
 */
#define LIBCT_OPT_KILLABLE				3
/*
 * Don't create a session for an initial process in CT
 */
#define LIBCT_OPT_NOSETSID				4
/*
 * Tell systemd about CT
 */
#define LIBCT_OPT_SYSTEMD				5

extern int libct_container_set_option(ct_handler_t ct, int opt, void *args);

extern int libct_container_set_console_fd(ct_handler_t ct, int tty_fd);

extern int libct_fs_add_devnode(ct_handler_t ct, char *path, int mode, int major, int minor);

extern ct_process_desc_t libct_process_desc_create(libct_session_t ses);
extern ct_process_desc_t libct_process_desc_copy(ct_process_desc_t p);
extern void libct_process_desc_destroy(ct_process_desc_t p);
extern int libct_process_desc_setuid(ct_process_desc_t p, unsigned int uid);
extern int libct_process_desc_setgid(ct_process_desc_t p, unsigned int uid);
extern int libct_process_desc_set_user(ct_process_desc_t p, char *user);
extern int libct_process_desc_setgroupts(ct_process_desc_t p, unsigned int size, unsigned int groups[]);
extern int libct_process_desc_set_rlimit(ct_process_desc_t p, int resource, uint64_t soft, uint64_t hard);
extern int libct_process_desc_set_lsm_label(ct_process_desc_t p, char *label);

#define CAPS_BSET	0x1
#define CAPS_ALLCAPS	0x2
#define CAPS_ALL	(CAPS_BSET | CAPS_ALLCAPS)
extern int libct_process_desc_set_caps(ct_process_desc_t ct, unsigned long mask, unsigned int apply_to);

extern int libct_process_desc_set_pdeathsig(ct_process_desc_t ct, int sig);

#define LIBCT_CONSOLE_FD -2
extern int libct_process_desc_set_fds(ct_process_desc_t p, int *fds, int n);

extern int libct_process_desc_set_env(ct_process_desc_t p, char **env, int envn);

extern int libct_process_wait(ct_process_t p, int *status);
extern void libct_process_destroy(ct_process_t p);
extern int libct_process_get_pid(ct_process_t p);

struct libct_processes {
	int nproc;
	int array[];
};

extern struct libct_processes *libct_container_processes(ct_handler_t h);

static inline int libct_processes_get(struct libct_processes *p, int i)
{
	return p->array[i];
}

void libct_processes_free(struct libct_processes *p);

#endif /* __UAPI_LIBCT_H__ */
