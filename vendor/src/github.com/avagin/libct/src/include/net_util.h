#ifndef __LIBCT_NET_UTILS_H__
#define __LIBCT_NET_UTILS_H__

#include "net.h"

struct ct_net_host_nic {
	struct ct_net n;
	char *name;
};

struct ct_net_veth {
	struct ct_net n;
	struct ct_net peer;
};

extern void ct_net_init(ct_net_t n, const struct ct_net_ops *ops);
extern void ct_net_clean(ct_net_t n);

extern int net_dev_set_mtu(ct_net_t n, int mtu);
extern int net_dev_set_mac_addr(ct_net_t n, char *addr);
extern int net_dev_set_master(ct_net_t n, char *master);
extern int net_dev_add_ip_addr(ct_net_t n, char *addr);
extern void veth_stop(struct container *ct, struct ct_net *n);
extern int veth_match(struct ct_net *n, void *arg);
extern void veth_free(struct ct_net_veth *vn);
extern struct ct_net_veth *cn2vn(struct ct_net *n);

extern struct nl_sock *net_sock_open();
extern void net_sock_close(struct nl_sock *sk);
extern struct nl_cache *net_get_link_cache(struct nl_sock *sk);
extern int net_link_apply(char *name, ct_net_t n);
extern int net_add_ip_addrs(struct nl_sock *sk, ct_net_t n);
#endif /* __LIBCT_NET_UTILS_H__ */
