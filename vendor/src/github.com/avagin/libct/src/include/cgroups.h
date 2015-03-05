#ifndef __LIBCT_CGROUP_H__
#define __LIBCT_CGROUP_H__

#include <stdbool.h>

#include "uapi/libct.h"

#include "list.h"

#define cbit(ctype)	(1 << ctype)

struct container;
struct mntent;

struct controller {
	struct list_head	ct_l;	/* links into container->cgroups */
	enum ct_controller	ctype;
};

struct cg_desc {
	char			*name;
	char			*mounted_at;
	struct cg_desc		*merged;
};

int cgroup_add_mount(struct mntent *);

/*
 * Postponed cgroups configuration
 */

struct cg_config {
	enum ct_controller	ctype;
	char			*param;
	char			*value;
	struct list_head	l;
};

extern struct cg_desc cg_descs[];

extern int cgroup_create_one(struct container *ct, struct controller *ctl);
extern int cgroups_create(struct container *ct);
extern int cgroups_attach(struct container *ct, pid_t pid);
extern void cgroups_destroy(struct container *ct);
extern void cgroups_free(struct container *ct);

extern int local_add_controller(ct_handler_t h, enum ct_controller ctype);
extern int local_config_controller(ct_handler_t h, enum ct_controller ctype, char *param, char *value);
extern int local_read_controller(ct_handler_t h, enum ct_controller ctype, char *param, void *buf, size_t len);
extern int config_controller(struct container *ct, enum ct_controller ctype, char *param, char *value);

extern int try_mount_cg(struct container *ct);

extern int cgroups_create_service(void);
extern int add_service_controller(struct container *ct);
extern int service_ctl_killall(struct container *ct);

extern struct libct_processes *local_controller_tasks(ct_handler_t h);

extern int cgroup_freezer_set_state(struct container *ct, bool freeze);

#define DEFAULT_CGROUPS_PATH	"/sys/fs/cgroup"

#endif /* __LIBCT_CGROUP_H__ */
