#ifndef __LIBCT_PROCESS_H__
#define __LIBCT_PROCESS_H__

#include <stdint.h>
#include <sys/resource.h>

#include "uapi/libct.h"

#include "compiler.h"

struct process_ops {
	int (*wait)(ct_process_t p, int *status);
	void (*destroy)(ct_process_t p);
	int (*get_pid)(ct_process_t p);
};

struct ct_process {
	const struct process_ops *ops;
};

struct process {
	struct ct_process	h;
	pid_t			pid;
	int			status;
};

struct process_desc_ops {
	int (*setuid)(ct_process_desc_t p, unsigned int uid);
	int (*setgid)(ct_process_desc_t p, unsigned int gid);
	int (*setgroups)(ct_process_desc_t p, unsigned int size, unsigned int *groups);
	int (*set_user)(ct_process_desc_t p, char *user);
	int (*set_caps)(ct_process_desc_t h, unsigned long mask, unsigned int apply_to);
	int (*set_pdeathsig)(ct_process_desc_t h, int sig);
	int (*set_lsm_label)(ct_process_desc_t h, char *label);
	int (*set_fds)(ct_process_desc_t h, int *fds, int fdn);
	int (*set_env)(ct_process_desc_t h, char **env, int envn);
	int (*set_rlimit)(ct_process_desc_t h, int resource, uint64_t soft, uint64_t hard);
	ct_process_desc_t (*copy)(ct_process_desc_t h);
	void (*destroy)(ct_process_desc_t p);
};

struct ct_process_desc {
	const struct process_desc_ops *ops;
};

struct process_desc {
	struct ct_process_desc       h;
	unsigned int		uid;
	unsigned int		gid;
	unsigned int		ngroups;
	unsigned int		*groups;
	char			*user;

	unsigned int		cap_mask;
	uint64_t		cap_bset;
	uint64_t		cap_caps;

	int			pdeathsig;

	int			lsm_on_exec;
	char			*lsm_label;

	int			*fds;
	int			fdn;
	char			**env;
	int			envn;

	struct rlimit		rlimit[RLIM_NLIMITS];
};

static inline struct process_desc *prh2pr(ct_process_desc_t h)
{
	return container_of(h, struct process_desc, h);
}

static inline struct process *ph2p(ct_process_t h)
{
	return container_of(h, struct process, h);
}

extern void local_process_desc_init(struct process_desc *p);
extern struct process_desc *local_process_copy(struct process_desc *p);

extern void local_process_init(struct process *p);

#endif //__LIBCT_PROCESS_H__
