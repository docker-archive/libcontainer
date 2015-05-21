#include <unistd.h>

#include "uapi/libct.h"

#include "session.h"
#include "process.h"
#include "xmalloc.h"
#include "libct.h"
#include "ct.h"
#include "vz.h"

static void close_local_session(libct_session_t s)
{
	struct local_session *l = s2ls(s);
	xfree(l);
}

static ct_handler_t create_local_ct(libct_session_t s, char *name)
{
	ct_handler_t ct;

	ct = ct_create(name);
	if (!ct)
		return libct_err_to_handle(-1);

	return ct;
}

static ct_process_desc_t local_process_create_desc(libct_session_t s)
{
	struct process_desc *p;

	p = xmalloc(sizeof(*p));
	if (p == NULL)
		return libct_err_to_handle(-1);

	local_process_desc_init(p);

	return &p->h;
}

static void update_local_ct_state(libct_session_t s, pid_t pid)
{
	ct_handler_t h;

	list_for_each_entry(h, &s->s_cts, s_lh) {
		struct container *ct = cth2ct(h);
		if (ct->p.pid != pid)
			continue;

		h->ops->wait(h);
	}
}

static const struct backend_ops local_session_ops = {
	.type = BACKEND_LOCAL,
	.create_ct = create_local_ct,
	.create_process_desc = local_process_create_desc,
	.close = close_local_session,
	.update_ct_state = update_local_ct_state,
};


static void close_vz_session(libct_session_t s)
{
	struct local_session *l = s2ls(s);
	xfree(l);
	vzctl_close();
}

static ct_handler_t create_vz_ct(libct_session_t s, char *name)
{
	ct_handler_t ct = NULL;
	if (vzctl_open() == -1)
		return libct_err_to_handle(-1);

	ct = vz_ct_create(name);
	if (!ct)
		return libct_err_to_handle(-1);

	return ct;
}

static void update_vz_ct_state(libct_session_t s, pid_t pid)
{
	/* TODO: implement afterwards */
}


static const struct backend_ops vz_session_ops = {
	.type = BACKEND_VZ,
	.create_ct = create_vz_ct,
	.create_process_desc = local_process_create_desc,
	.close = close_vz_session,
	.update_ct_state = update_vz_ct_state,
};

libct_session_t libct_session_open_local(void)
{
	struct local_session *s;

	if (libct_init_local())
		return libct_err_to_handle(-1);

	s = xmalloc(sizeof(*s));
	if (s) {
		INIT_LIST_HEAD(&s->s.s_cts);
		if (!access("/proc/vz", F_OK))
			s->s.ops = &vz_session_ops;
		else
			s->s.ops = &local_session_ops;
		return &s->s;
	}

	return libct_err_to_handle(-1);
}

static inline ct_handler_t new_ct(libct_session_t ses, ct_handler_t cth)
{
	if (!libct_handle_is_err(cth) && list_empty(&cth->s_lh))
		list_add_tail(&cth->s_lh, &ses->s_cts);

	return cth;
}

ct_handler_t libct_container_create(libct_session_t ses, char *name)
{
	ct_handler_t cth;

	if (!name)
		return libct_err_to_handle(-LCTERR_INVARG);

	cth = ses->ops->create_ct(ses, name);
	return new_ct(ses, cth);
}

ct_handler_t libct_container_open(libct_session_t ses, char *name)
{
	ct_handler_t cth;

	if (!name)
		return libct_err_to_handle(-LCTERR_INVARG);

	if (!ses->ops->open_ct)
		return libct_err_to_handle(-1);

	/*
	 * FIXME -- there can exist multiple handlers, need
	 * to invalidate them all on container destruction.
	 */

	cth = ses->ops->open_ct(ses, name);
	return new_ct(ses, cth);
}

ct_process_desc_t libct_process_desc_create(libct_session_t ses)
{
	return ses->ops->create_process_desc(ses);
}

void libct_session_close(libct_session_t s)
{
	ct_handler_t cth, n;

	list_for_each_entry_safe(cth, n, &s->s_cts, s_lh)
		libct_container_close(cth);

	s->ops->close(s);
}
