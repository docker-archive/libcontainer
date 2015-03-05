#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "process.h"
#include "xmalloc.h"

static int local_desc_setuid(ct_process_desc_t h, unsigned uid)
{
	struct process_desc *p = prh2pr(h);

	p->uid = uid;

	return 0;
}

static int local_desc_setgid(ct_process_desc_t h, unsigned gid)
{
	struct process_desc *p = prh2pr(h);

	p->gid = gid;

	return 0;
}

static int local_desc_set_user(ct_process_desc_t h, char *user)
{
	struct process_desc *p = prh2pr(h);

	p->user = xstrdup(user);
	if (p->user == NULL)
		return -1;

	return 0;
}

static int local_desc_setgroups(ct_process_desc_t h, unsigned int ngroups, unsigned int *groups)
{
	struct process_desc *p = prh2pr(h);
	unsigned int *g = NULL;

	if (ngroups) {
		g = xmalloc(ngroups * (sizeof(*groups)));
		if (g == NULL)
			return -1;
		memcpy(g, groups, ngroups * (sizeof(*groups)));
	}

	p->groups = g;
	p->ngroups = ngroups;

	return 0;
}

static int local_desc_set_caps(ct_process_desc_t h, unsigned long mask, unsigned int apply_to)
{
	struct process_desc *p = prh2pr(h);

	if (apply_to & CAPS_BSET) {
		p->cap_mask |= CAPS_BSET;
		p->cap_bset = mask;
	}

	if (apply_to & CAPS_ALLCAPS) {
		p->cap_mask |= CAPS_ALLCAPS;
		p->cap_caps = mask;
	}

	return 0;
}

static int local_desc_set_pdeathsig(ct_process_desc_t h, int sig)
{
	struct process_desc *p = prh2pr(h);

	p->pdeathsig = sig;

	return 0;
}

static void local_desc_destroy_env(struct process_desc *p)
{
	int i;

	for (i = 0; i < p->envn; i++)
		xfree(p->env[i]);
	xfree(p->env);
	p->env = NULL;
	p->envn = 0;
}

static int local_desc_set_env(ct_process_desc_t h, char **env, int n)
{
	struct process_desc *p = prh2pr(h);
	int i;

	if (p->env)
		return -LCTERR_INVARG;

	p->env = xzalloc(n * sizeof(char *));
	if (p == NULL)
		return -1;

	p->envn = n;
	for (i = 0; i < n; i++) {
		p->env[i] = xstrdup(env[i]);
		if (p->env[i] == NULL) {
			local_desc_destroy_env(p);
			return -1;
		}
	}

	return 0;
}

static void local_desc_destroy(ct_process_desc_t h)
{
	struct process_desc *p = prh2pr(h);

	local_desc_destroy_env(p);
	xfree(p->lsm_label);
	xfree(p->groups);
	xfree(p->user);
	xfree(p->fds);
	xfree(p);
}

ct_process_desc_t local_desc_copy(ct_process_desc_t h)
{
	struct process_desc *p = prh2pr(h);
	struct process_desc *c;

	c = xmalloc(sizeof(struct process_desc));
	if (c == NULL)
		return NULL;

	memcpy(c, p, sizeof(struct process_desc));
	c->groups = NULL;
	c->lsm_label = NULL;
	c->fds = NULL;

	if (p->ngroups) {
		c->groups = xmalloc(p->ngroups * sizeof(c->groups[0]));
		if (c->groups == NULL)
			goto err;
		memcpy(c->groups, p->groups, p->ngroups * sizeof(c->groups[0]));
	}

	if (p->fds) {
		/* reserve space for wait_pipe */
		c->fds = xmalloc((p->fdn + 1) * sizeof(c->fds[0]));
		if (c->fds == NULL)
			goto err;
		memcpy(c->fds, p->fds, p->fdn * sizeof(c->fds[0]));
	}

	if (p->lsm_label) {
		c->lsm_label = xstrdup(p->lsm_label);
		if (c->lsm_label == NULL)
			goto err;
	}

	return &c->h;
err:
	local_desc_destroy(&c->h);
	return NULL;
}

int local_desc_set_lsm_label(ct_process_desc_t h, char *label)
{
	struct process_desc *p = prh2pr(h);
	char *l;

	l = xstrdup(label);
	if (l == NULL)
		return -1;

	p->lsm_label = l;
	return 0;
}

int local_desc_set_fds(ct_process_desc_t h, int *fds, int fdn)
{
	struct process_desc *p = prh2pr(h);
	int *t = NULL;

	if (fds) {
		/* reserve space for wait_pipe */
		t = xmalloc(sizeof(int) * (fdn + 1));
		if (t == NULL)
			return -1;

		memcpy(t, fds, sizeof(int) * fdn);
	}

	xfree(p->fds);
	p->fds = t;
	p->fdn = fdn;

	return 0;
}

int local_desc_set_rlimit(ct_process_desc_t h, int resource, uint64_t soft, uint64_t hard)
{
	struct process_desc *p = prh2pr(h);

	if (resource >= RLIM_NLIMITS)
		return -1;

	p->rlimit[resource].rlim_cur = soft;
	p->rlimit[resource].rlim_max = hard;

	return 0;
}

static const struct process_desc_ops local_process_desc_ops = {
	.copy		= local_desc_copy,
	.destroy	= local_desc_destroy,
	.setuid		= local_desc_setuid,
	.setgid		= local_desc_setgid,
	.set_user	= local_desc_set_user,
	.setgroups	= local_desc_setgroups,
	.set_caps	= local_desc_set_caps,
	.set_pdeathsig	= local_desc_set_pdeathsig,
	.set_lsm_label	= local_desc_set_lsm_label,
	.set_fds	= local_desc_set_fds,
	.set_env	= local_desc_set_env,
	.set_rlimit	= local_desc_set_rlimit,
};

void local_process_desc_init(struct process_desc *p)
{
	int i;

	p->h.ops	= &local_process_desc_ops;
	p->uid		= 0;
	p->gid		= 0;
	p->cap_caps	= 0;
	p->cap_bset	= 0;
	p->cap_mask	= 0;
	p->pdeathsig	= 0;
	p->groups	= NULL;
	p->ngroups	= 0;
	p->lsm_label	= NULL;
	p->fds		= NULL;
	p->fdn		= 0;
	p->env		= NULL;
	p->envn		= 0;

	for (i = 0; i < RLIM_NLIMITS; i++) {
		/*
		 * Here is an invalid pair of values, which
		 * means that this type of limits isn't set.
		 */
		p->rlimit[i].rlim_cur = RLIM_INFINITY;
		p->rlimit[i].rlim_max = 0;
	}
}

static int local_process_get_pid(ct_process_t h)
{
	struct process *p = ph2p(h);
	return p->pid;
}

static int local_process_wait(ct_process_t h, int *status)
{
	struct process *p = ph2p(h);
	int s = -1;

	if (p->pid < 0)
		return -LCTERR_BADCTSTATE;

	if (waitpid(p->pid, &s, 0) == -1 && errno != ECHILD) {
		pr_perror("Unable to wait %d\n", p->pid);
		return -1;
	}
	p->pid = -1;
	p->status = s;
	if (status)
		*status = s;

	return 0;
}

static void local_process_destroy(ct_process_t h)
{
	struct process *p = ph2p(h);

	xfree(p);
}

static const struct process_ops local_process_ops = {
	.wait		= local_process_wait,
	.destroy	= local_process_destroy,
	.get_pid	= local_process_get_pid,
};

void local_process_init(struct process *p)
{
	p->h.ops	= &local_process_ops;
	p->pid		= -1;
}
