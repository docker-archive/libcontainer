#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <mntent.h>
#include <limits.h>
#include <errno.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/mount.h>

#include "uapi/libct.h"

#include "list.h"
#include "bug.h"
#include "ct.h"
#include "cgroups.h"
#include "xmalloc.h"
#include "systemd.h"
#include "util.h"
#include "linux-kernel.h"
#include "err.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

/*
 * Private controllers for libct internal needs
 */
enum {
	CTL_SERVICE = CT_NR_CONTROLLERS,
	CT_NR_CONTROLLERS_ALL
};

#define LIBCT_CTL_NAME	".libct"
#define LIBCT_CTL_PATH	DEFAULT_CGROUPS_PATH"/"LIBCT_CTL_NAME

struct cg_desc cg_descs[CT_NR_CONTROLLERS_ALL] = {
	[CTL_BLKIO]	= { .name = "blkio", },
	[CTL_CPU]	= { .name = "cpu", },
	[CTL_CPUACCT]	= { .name = "cpuacct", },
	[CTL_CPUSET]	= { .name = "cpuset", },
	[CTL_DEVICES]	= { .name = "devices", },
	[CTL_FREEZER]	= { .name = "freezer", },
	[CTL_HUGETLB]	= { .name = "hugetlb", },
	[CTL_MEMORY]	= { .name = "memory", },
	[CTL_NETCLS]	= { .name = "net_cls", },
	[CTL_SERVICE]	= { .name = LIBCT_CTL_NAME, },
};

int cgroup_add_mount(struct mntent *me)
{
	int i, found = -1;

	for (i = 0; i < CT_NR_CONTROLLERS; i++) {
		if (cg_descs[i].mounted_at)
			continue;

		if (hasmntopt(me, cg_descs[i].name)) {
			if (found == -1) {
				found = i;
				cg_descs[i].mounted_at = xstrdup(me->mnt_dir);
				if (!cg_descs[i].mounted_at)
					return -1;
			} else {
				cg_descs[i].merged = &cg_descs[found];
				cg_descs[i].mounted_at = cg_descs[found].mounted_at;
			}
		}
	}

	if (found == -1 && hasmntopt(me, "name=libct")) {
		i = CTL_SERVICE;
		cg_descs[i].mounted_at = xstrdup(me->mnt_dir);
		if (!cg_descs[i].mounted_at)
			return -1;
	}

	/* FIXME -- add custom cgroups' mount points if found == -1 */
	return 0;
}

int cgroups_create_service(void)
{
	if (cg_descs[CTL_SERVICE].mounted_at)
		return 0;

	mkdir(LIBCT_CTL_PATH, 0600);
	if (mount("cgroup", LIBCT_CTL_PATH, "cgroup",
				MS_MGC_VAL, "none,name=libct") < 0) {
		pr_perror("Unable to mount the libct subsystem");
		return -LCTERR_CGCREATE;
	}

	cg_descs[CTL_SERVICE].mounted_at = LIBCT_CTL_PATH;
	return 0;
}

static inline char *cgroup_get_path(int type, char *buf, int blen)
{
	int lp;
	lp = snprintf(buf, blen, "%s", cg_descs[type].mounted_at);
	return buf + lp;
}

static inline char *cgroup_get_ct_path(struct container *ct, enum ct_controller ctype, char *buf, int blen)
{
	char *slice = "system.slice", *t;
	int off;

	if (ct->slice)
		slice = ct->slice;

	t = cgroup_get_path(ctype, buf, blen);
	if (ct->flags & CT_SYSTEMD)
		off = snprintf(t, blen - (t - buf), "/%s/%s-%s.scope", slice, slice, ct->name);
	else
		off = snprintf(t, blen - (t - buf), "/%s", ct->name);

	return t + off;
}

int libct_controller_add(ct_handler_t ct, enum ct_controller ctype)
{
	if (ctype >= CT_NR_CONTROLLERS)
		return -LCTERR_INVARG;

	return ct->ops->add_controller(ct, ctype);
}

static int add_controller(struct container *ct, int ctype)
{
	struct controller *ctl;

	if (ct->cgroups_mask & cbit(ctype))
		return 0;

	ctl = xmalloc(sizeof(*ctl));
	if (!ctl)
		return -1;

	ctl->ctype = ctype;
	list_add_tail(&ctl->ct_l, &ct->cgroups);
	ct->cgroups_mask |= cbit(ctype);
	return 0;
}

int add_service_controller(struct container *ct)
{
	return add_controller(ct, CTL_SERVICE);
}

int local_add_controller(ct_handler_t h, enum ct_controller ctype)
{
	struct container *ct = cth2ct(h);

	if (ct->state != CT_STOPPED)
		return -LCTERR_BADCTSTATE;

	return add_controller(ct, ctype);
}

static void cg_config_free(struct cg_config *cg)
{
	if (cg) {
		xfree(cg->param);
		xfree(cg->value);
		xfree(cg);
	}
}

static struct cg_config *cg_config_alloc(enum ct_controller ctype, char *param, char *value)
{
	struct cg_config *cg = xmalloc(sizeof(*cg));

	BUG_ON(!param || !value);

	if (cg) {
		INIT_LIST_HEAD(&cg->l);
		cg->ctype = ctype;
		cg->param = xstrdup(param);
		cg->value = xstrdup(value);
		if (!cg->param || !cg->value) {
			cg_config_free(cg);
			cg = NULL;
		}
	}

	return cg;
}

int local_read_controller(ct_handler_t h, enum ct_controller ctype,
		char *param, void *buf, size_t len)
{
	struct container *ct = cth2ct(h);
	char path[PATH_MAX], *t;
	int fd, ret;

	if (ct->state == CT_STOPPED)
		return -LCTERR_BADCTSTATE;

	t = cgroup_get_ct_path(ct, ctype, path, sizeof(path));
	snprintf(t, sizeof(path) - (t - path), "/%s", param);

	ret = fd = open(path, O_RDONLY);
	if (fd >= 0) {
		ret = read(fd, buf, len);
		close(fd);
	}

	return ret;
}

int config_controller(struct container *ct, enum ct_controller ctype,
		char *param, char *value)
{
	char path[PATH_MAX], *t;
	int fd, ret;

	t = cgroup_get_ct_path(ct, ctype, path, sizeof(path));
	snprintf(t, sizeof(path) - (t - path), "/%s", param);

	ret = fd = open(path, O_WRONLY);
	if (fd >= 0) {
		ret = 0;
		if (write(fd, value, strlen(value)) < 0)
			ret = -1;
		close(fd);
	}

	return ret;
}

int local_config_controller(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value)
{
	struct container *ct = cth2ct(h);

	if (!(ct->cgroups_mask & cbit(ctype)))
		return -LCTERR_NOTFOUND;

	if (ct->state != CT_RUNNING) {
		struct cg_config *cfg;

		/*
		 * Postpone cgroups configuration
		 */

		list_for_each_entry(cfg, &ct->cg_configs, l) {
			char *new;
			if (cfg->ctype != ctype || strcmp(cfg->param, param))
				continue;

			new = xstrdup(value);
			if (!new)
				return -1;
			xfree(cfg->value);
			cfg->value = new;
			return 0;
		}

		cfg = cg_config_alloc(ctype, param, value);
		if (!cfg)
			return -1;
		list_add_tail(&cfg->l, &ct->cg_configs);
		return 0;
	}

	return config_controller(ct, ctype, param, value) ? -LCTERR_CGCONFIG : 0;
}

int cgroup_create_one(struct container *ct, struct controller *ctl)
{
	char path[PATH_MAX];

	cgroup_get_ct_path(ct, ctl->ctype, path, sizeof(path));

	if (mkdir(path, 0600) && errno != EEXIST) {
		pr_perror("Unable to create %s", path);
		return -errno;
	}

	return 0;
}

int cgroups_create(struct container *ct)
{
	struct controller *ctl;
	struct cg_config *cfg;
	int ret = 0;

	list_for_each_entry(ctl, &ct->cgroups, ct_l) {
		ret = cgroup_create_one(ct, ctl);
		if (ret)
			return -LCTERR_CGCREATE;
	}

	list_for_each_entry(cfg, &ct->cg_configs, l) {
		ret = config_controller(ct, cfg->ctype, cfg->param, cfg->value);
		if (ret)
			return -LCTERR_CGCONFIG;
	}

	return 0;
}

static int cgroup_attach_one(struct container *ct, struct controller *ctl, char *pid)
{
	return config_controller(ct, ctl->ctype, "tasks", pid) ? -LCTERR_CGATTACH : 0;
}

int cgroups_attach(struct container *ct, pid_t pid)
{
	char spid[12];
	struct controller *ctl;
	int ret = 0;

	if (ct->flags & CT_SYSTEMD && ct->p.pid == pid) {
		if (systemd_start_unit(ct, pid))
			return -1;
	}

	snprintf(spid, sizeof(spid), "%d", pid);
	list_for_each_entry(ctl, &ct->cgroups, ct_l) {
		ret = cgroup_attach_one(ct, ctl, spid);
		if (ret)
			break;
	}

	return ret;
}

static void destroy_controller(struct container *ct, struct controller *ctl)
{
	char path[PATH_MAX];

	/*
	 * Remove the directory with cgroup. It may fail, but what
	 * to do in that case? XXX
	 */
	cgroup_get_ct_path(ct, ctl->ctype, path, sizeof(path));
	rmdir(path);
}

void cgroups_destroy(struct container *ct)
{
	struct controller *ctl;

	list_for_each_entry(ctl, &ct->cgroups, ct_l)
		destroy_controller(ct, ctl);
}

void cgroups_free(struct container *ct)
{
	struct controller *ctl, *n;
	struct cg_config *cfg, *cn;

	list_for_each_entry_safe(ctl, n, &ct->cgroups, ct_l) {
		list_del(&ctl->ct_l);
		xfree(ctl);
	}

	list_for_each_entry_safe(cfg, cn, &ct->cg_configs, l) {
		list_del(&cfg->l);
		cg_config_free(cfg);
	}
}

/*
 * Bind mount container's controller root dir into @to
 */
static int re_mount_controller(struct container *ct, struct controller *ctl, char *to)
{
	char path[PATH_MAX], *t;

	if (mkdir(to, 0600)) {
		pr_perror("Unable to create %s", to);
		return -1;
	}

	t = cgroup_get_path(ctl->ctype, path, sizeof(path));
	snprintf(t, sizeof(path) - (t - path), "/%s", ct->name);

	if (do_mount(path, to, CT_FS_BIND, NULL, NULL)) {
		rmdir(to);
		return -1;
	}

	return 0;
}

static int re_mount_cg(struct container *ct)
{
	char tpath[PATH_MAX];
	struct controller *ctl;
	int l;

	if (!ct->root_path)
		return -1; /* FIXME -- implement */

	l = snprintf(tpath, sizeof(tpath), "%s/%s", ct->root_path, ct->cgroup_sub);
	if (mount("none", tpath, "tmpfs", 0, NULL))
		goto err;

	list_for_each_entry(ctl, &ct->cgroups, ct_l) {
		if (ctl->ctype >= CT_NR_CONTROLLERS)
			continue;

		snprintf(tpath + l, sizeof(tpath) - l,
			 "/%s", cg_descs[ctl->ctype].name);
		if (re_mount_controller(ct, ctl, tpath))
			goto err_ctl;
	}

	return 0;

err_ctl:
	tpath[l] = '\0';
	umount2(tpath, MNT_DETACH);
err:
	return -1;
}

int try_mount_cg(struct container *ct)
{
	/* Not requested by user */
	if (!ct->cgroup_sub)
		return 0;
	/* Can't have cgroup submount in shared FS */
	if (!fs_private(ct))
		return -1;

	return re_mount_cg(ct);
}

int libct_controller_configure(ct_handler_t ct, enum ct_controller ctype,
		char *param, char *value)
{
	if (!param || !value)
		return -LCTERR_INVARG;

	return ct->ops->config_controller(ct, ctype, param, value);
}

int libct_controller_read(ct_handler_t ct, enum ct_controller ctype,
		char *param, void *buf, size_t size)
{
	if (!param)
		return -LCTERR_INVARG;

	return ct->ops->read_controller(ct, ctype, param, buf, size);
}

struct libct_processes *local_controller_tasks(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	char path[PATH_MAX], *p, spid[16];
	struct libct_processes *procs = NULL;
	int size;
	struct controller *ctl;
	FILE *f;

	ctl = list_first_entry(&ct->cgroups, struct controller, ct_l);
	if (&ctl->ct_l == &ct->cgroups)
		return ERR_PTR(-LCTERR_INVARG);

	p = cgroup_get_path(ctl->ctype, path, sizeof(path));
	snprintf(p, sizeof(path) - (p - path), "/%s/%s", ct->name, "tasks");

	f = fopen(path, "r");
	if (!f)
		return ERR_PTR(-1);

	procs = xmalloc(sizeof(struct libct_processes));
	if (!procs)
		goto err;
	size = 0;
	procs->nproc = 0;

	while (fgets(spid, sizeof(spid), f)) {
		int pid;

		pid = atoi(spid);

		if (procs->nproc + 1 < size) {
			struct libct_processes *p;
			size = (size + 1) * 2;
			p = xrealloc(procs, sizeof(*procs) + size * sizeof(procs->array[0]));
			if (p == NULL)
				goto err;
			procs = p;
		}
		procs->array[procs->nproc] = pid;
		procs->nproc++;
	}

	fclose(f);

	return procs;

err:
	xfree(procs);
	fclose(f);
	return ERR_PTR(-1);
}

int service_ctl_killall(struct container *ct)
{
	char path[PATH_MAX], *p, spid[16];
	FILE *f;
	bool has_tasks;

	p = cgroup_get_ct_path(ct, CTL_SERVICE, path, sizeof(path));
	snprintf(p, sizeof(path) - (p - path), "/%s", "tasks");

try_again:
	f = fopen(path, "r");
	if (!f)
		return -1;

	has_tasks = false;
	while (fgets(spid, sizeof(spid), f)) {
		int pid;

		has_tasks = true;
		pid = atoi(spid);
		if (kill(pid, SIGKILL))
			goto err;
	}

	fclose(f);
	if (has_tasks)
		/* they might have fork()-ed while we read the file */
		goto try_again;

	return 0;

err:
	fclose(f);
	return -1;
}

int cgroup_freezer_set_state(struct container *ct, bool freeze)
{
	char path[PATH_MAX], *p, buf[10];
	char *state;
	int ret, fd;

	state = freeze ? "FROZEN\n" : "THAWED\n";

	p = cgroup_get_ct_path(ct, CTL_FREEZER, path, sizeof(path));
	snprintf(p, sizeof(path) - (p - path), "/freezer.state");

	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}

	if (write(fd, state, 6) != 6) {
		pr_perror("Unable to write '%s' in %s", state, path);
		goto err;
	}

	while (1) {
		struct timespec to = {0, 1000000};
		if (lseek(fd, 0, SEEK_SET) < 0) {
			pr_perror("lseek");
			goto err;
		}

		ret = read(fd, buf, sizeof(buf) - 1);
		if (ret < 0) {
			pr_perror("Unable to read from %s", path);
			goto err;
		};
		buf[ret] = 0;
		if (strcmp(buf, state) == 0)
			break;
		nanosleep(&to, NULL);
	}

	return 0;
err:
	close(fd);
	return -1;
}

