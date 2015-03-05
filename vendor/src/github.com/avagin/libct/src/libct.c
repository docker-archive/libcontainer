#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "uapi/libct.h"

#include "linux-kernel.h"
#include "xmalloc.h"
#include "process.h"
#include "libct.h"
#include "list.h"
#include "err.h"
#include "ct.h"

void *libct_err_to_handle(long err)
{
	return ERR_PTR(err);
}

long libct_handle_to_err(void *h)
{
	return PTR_ERR(h);
}

int libct_handle_is_err(void *h)
{
	return IS_ERR(h);
}

void ct_handler_init(ct_handler_t h)
{
	h->ops = NULL;
	INIT_LIST_HEAD(&h->s_lh);
}

int libct_init_local(void)
{
	static bool done = false;

	if (done)
		return 0;

	if (linux_get_ns_mask())
		return -1;

	if (linux_get_cgroup_mounts())
		return -1;

	done = true;
	return 0;
}

enum ct_state libct_container_state(ct_handler_t h)
{
	return h->ops->get_state(h);
}

ct_process_t libct_container_load(ct_handler_t ct, pid_t pid)
{
	/* This one is optional -- only local ops support */
	if (!ct->ops->load)
		return ERR_PTR(-LCTERR_OPNOTSUPP);

	return ct->ops->load(ct, pid);
}

ct_process_t libct_container_spawn_cb(ct_handler_t ct, ct_process_desc_t pr, int (*cb)(void *), void *arg)
{
	/* This one is optional -- only local ops support */
	if (!ct->ops->spawn_cb)
		return ERR_PTR(-LCTERR_OPNOTSUPP);

	return ct->ops->spawn_cb(ct, pr, cb, arg);
}

ct_process_t libct_container_spawn_execv(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv)
{
	return libct_container_spawn_execve(ct, pr, path, argv, NULL);
}

ct_process_t libct_container_spawn_execve(ct_handler_t ct, ct_process_desc_t pr, char *path, char **argv, char **env)
{
	return ct->ops->spawn_execve(ct, pr, path, argv, env);
}

ct_process_t libct_container_enter_cb(ct_handler_t ct, ct_process_desc_t p, int (*cb)(void *), void *arg)
{
	if (!ct->ops->enter_cb)
		return ERR_PTR(-LCTERR_OPNOTSUPP);

	return ct->ops->enter_cb(ct, p, cb, arg);
}

ct_process_t libct_container_enter_execv(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv)
{
	return libct_container_enter_execve(ct, p, path, argv, NULL);
}

ct_process_t libct_container_enter_execve(ct_handler_t ct, ct_process_desc_t p, char *path, char **argv, char **env)
{
	return ct->ops->enter_execve(ct, p, path, argv, env);
}


int libct_container_kill(ct_handler_t ct)
{
	return ct->ops->kill(ct);
}

int libct_container_wait(ct_handler_t ct)
{
	return ct->ops->wait(ct);
}

void libct_container_destroy(ct_handler_t ct)
{
	list_del_init(&ct->s_lh);
	ct->ops->destroy(ct);
}

void libct_container_close(ct_handler_t ct)
{
	list_del_init(&ct->s_lh);
	ct->ops->detach(ct);
}

int libct_container_set_nsmask(ct_handler_t ct, unsigned long nsmask)
{
	return ct->ops->set_nsmask(ct, nsmask);
}

int libct_container_set_nspath(ct_handler_t ct, int ns, char *path)
{
	return ct->ops->set_nspath(ct, ns, path);
}

int libct_container_set_sysctl(ct_handler_t ct, char *name, char *val)
{
	return ct->ops->set_sysctl(ct, name, val);
}

int libct_container_set_option(ct_handler_t ct, int opt, void *args)
{
	return ct->ops->set_option(ct, opt, args);
}

int libct_container_set_console_fd(ct_handler_t ct, int tty_fd)
{
	return ct->ops->set_console_fd(ct, tty_fd);
}

int libct_container_uname(ct_handler_t ct, char *host, char *domain)
{
	return ct->ops->uname(ct, host, domain);
}

int libct_container_pause(ct_handler_t ct)
{
	return ct->ops->pause(ct);
}

int libct_container_resume(ct_handler_t ct)
{
	return ct->ops->resume(ct);
}

libct_session_t libct_session_open(char *how)
{
	if (!how || !strcmp(how, "local"))
		return libct_session_open_local();

	return libct_err_to_handle(-LCTERR_INVARG);
}

int libct_userns_add_uid_map(ct_handler_t ct, unsigned int first,
			unsigned int lower_first, unsigned int count)
{
	return ct->ops->add_uid_map(ct, first, lower_first, count);
}

int libct_userns_add_gid_map(ct_handler_t ct, unsigned int first,
			unsigned int lower_first, unsigned int count)
{
	return ct->ops->add_gid_map(ct, first, lower_first, count);
}

int libct_process_desc_set_caps(ct_process_desc_t p, unsigned long mask, unsigned int apply_to)
{
	if (!apply_to || (apply_to & ~CAPS_ALL))
		return -LCTERR_INVARG;

	return p->ops->set_caps(p, mask, apply_to);
}

int libct_process_desc_set_pdeathsig(ct_process_desc_t p, int sig)
{
	return p->ops->set_pdeathsig(p, sig);
}

int libct_process_desc_setuid(ct_process_desc_t p, unsigned int uid)
{
	return p->ops->setuid(p, uid);
}

int libct_process_desc_setgid(ct_process_desc_t p, unsigned int gid)
{
	return p->ops->setgid(p, gid);
}

int libct_process_desc_set_user(ct_process_desc_t p, char *user)
{
	return p->ops->set_user(p, user);
}

int libct_process_desc_set_rlimit(ct_process_desc_t p, int resource, uint64_t soft, uint64_t hard)
{
	return p->ops->set_rlimit(p, resource, soft, hard);
}

int libct_process_desc_setgroups(ct_process_desc_t p, unsigned int size, unsigned int groups[])
{
	return p->ops->setgroups(p, size, groups);
}

ct_process_desc_t libct_process_desc_copy(ct_process_desc_t p)
{
	return p->ops->copy(p);
}

void libct_process_desc_destroy(ct_process_desc_t p)
{
	return p->ops->destroy(p);
}

int libct_process_desc_set_lsm_label(ct_process_desc_t p, char *label)
{
	return p->ops->set_lsm_label(p, label);
}

int libct_process_desc_set_fds(ct_process_desc_t p, int *fds, int n)
{
	return p->ops->set_fds(p, fds, n);
}

int libct_process_desc_set_env(ct_process_desc_t p, char **env, int envn)
{
	return p->ops->set_env(p, env, envn);
}

int libct_process_wait(ct_process_t p, int *status)
{
	return p->ops->wait(p, status);
}

void libct_process_destroy(ct_process_t p)
{
	return p->ops->destroy(p);
}

int libct_process_get_pid(ct_process_t p)
{
	return p->ops->get_pid(p);
}

struct libct_processes *libct_container_processes(ct_handler_t ct) {
	return ct->ops->get_processes(ct);
}

void libct_processes_free(struct libct_processes *p)
{
	xfree(p);
}
