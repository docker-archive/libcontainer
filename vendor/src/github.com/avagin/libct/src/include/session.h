#ifndef __LIBCT_SESSION_H__
#define __LIBCT_SESSION_H__

#include "uapi/libct.h"

#include "list.h"
#include "ct.h"

enum {
	BACKEND_NONE,
	BACKEND_LOCAL,
	BACKEND_UNIX,
	BACKEND_VZ,
};

struct backend_ops {
	int type;
	ct_handler_t (*create_ct)(libct_session_t s, char *name);
	ct_handler_t (*open_ct)(libct_session_t s, char *name);
	void	     (*update_ct_state)(libct_session_t s, pid_t pid);
	ct_process_desc_t (*create_process_desc)(libct_session_t s);
	void (*close)(libct_session_t s);
};

struct libct_session {
	const struct backend_ops *ops;
	struct list_head s_cts;
};

struct local_session {
	struct libct_session s;
};

static inline struct local_session *s2ls(libct_session_t s)
{
	return container_of(s, struct local_session, s);
}

extern void local_session_add(libct_session_t, struct container *ct);

#endif /* __LIBCT_SESSION_H__ */
