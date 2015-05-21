#ifndef __LIBCT_NAMESPACES_H__
#define __LIBCT_NAMESPACES_H__

struct ns_desc {
	char *name;
	unsigned long cflag;
};

extern struct ns_desc *namespaces[];
extern struct ns_desc pid_ns;
extern struct ns_desc net_ns;

extern int switch_ns(int pid, struct ns_desc *d, int *old_ns);
extern void restore_ns(int ns_fd, struct ns_desc *d);

#endif /* __LIBCT_NAMESPACES_H__ */
