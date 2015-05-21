#include <stdlib.h>
#include <netinet/ether.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include "net_util.h"
#include "xmalloc.h"
#include "util.h"

/*
 * Generic Linux networking management
 */

struct nl_sock *net_sock_open()
{
	struct nl_sock *sk;
	int err;

	sk = nl_socket_alloc();
	if (sk == NULL)
		return NULL;

	if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
		nl_socket_free(sk);
		pr_err("Unable to connect socket: %s", nl_geterror(err));
		return NULL;
	}

	return sk;
}

void net_sock_close(struct nl_sock *sk)
{
	if (sk == NULL)
		return;

	nl_close(sk);
	nl_socket_free(sk);

	return;
}

struct nl_cache *net_get_link_cache(struct nl_sock *sk)
{
	struct nl_cache *cache;
	int err;

	err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
	if (err) {
		pr_err("Unable to alloc link cache: %s", nl_geterror(err));
		return NULL;
	}

	return cache;
}

static int __net_add_ip_addr(struct nl_sock *sk, ct_net_t n, char *saddr)
{
	struct rtnl_addr *addr;
	struct nl_addr *l;
	int err, ret = -1;

	err = nl_addr_parse(saddr, AF_UNSPEC, &l);
	if (err) {
		pr_err("Unable to parse address: %s\n", nl_geterror(err));
		return -1;
	}

	addr = rtnl_addr_alloc();
	if (addr == NULL)
		goto err;

	rtnl_addr_set_local(addr, l);
	rtnl_addr_set_ifindex(addr, n->ifidx);
	err = rtnl_addr_add(sk, addr, 0);
	if (err) {
		pr_err("Unable to add %s: %s\n", saddr, nl_geterror(err));
		goto err;
	}

	ret = 0;
err:
	nl_addr_put(l);
	rtnl_addr_put(addr);
	return ret;
}

int net_link_apply(char *name, ct_net_t n)
{
	struct rtnl_link *link = NULL, *orig = NULL;
	struct nl_cache *cache = NULL;
	struct nl_sock *sk;
	int err = -1;

	sk = net_sock_open();
	if (sk == NULL)
		return -1;

	cache = net_get_link_cache(sk);
	if (sk == NULL)
		goto free;

	orig = rtnl_link_get_by_name(cache, name);
	if (orig == NULL)
		goto free;

	link = rtnl_link_alloc();
	if (link == NULL)
		goto free;

	rtnl_link_set_name(link, n->name);

	if (n->addr) {
		struct nl_addr* addr;

		addr = nl_addr_build(AF_LLC, ether_aton(n->addr), ETH_ALEN);
		if (addr == NULL)
			goto free;
		rtnl_link_set_addr(link, addr);
	}

	if (n->master) {
		int idx;

		idx = rtnl_link_name2i(cache, n->master);
		if (idx == 0)
			goto free;

		rtnl_link_set_master(link, idx);
	}

	rtnl_link_set_flags(link, IFF_UP);

	err = rtnl_link_change(sk, orig, link, 0);
	if (err) {
		pr_err("Unable to change link %s: %s", n->name, nl_geterror(err));
		goto free;
	}

	err = -1;
	if (nl_cache_refill(sk, cache))
		goto free;

	n->ifidx = rtnl_link_name2i(cache, n->name);
	if ( n->ifidx == 0)
		goto free;

	if (net_add_ip_addrs(sk, n))
		goto free;
	err = 0;
free:
	rtnl_link_put(link);
	rtnl_link_put(orig);
	nl_cache_put(cache);
	net_sock_close(sk);
	return err;
}


int net_add_ip_addrs(struct nl_sock *sk, ct_net_t n)
{
	struct ct_net_ip_addr *addr;

	list_for_each_entry(addr, &n->ip_addrs, l) {
		if (__net_add_ip_addr(sk, n, addr->addr))
			goto err;
	}

	return 0;
err:
	// FIXME rollback
	return -1;
}


void ct_net_init(ct_net_t n, const struct ct_net_ops *ops)
{
	INIT_LIST_HEAD(&n->ip_addrs);
	n->name = NULL;
	n->ops = ops;
}

void ct_net_clean(ct_net_t n)
{
	struct ct_net_ip_addr *addr, *t;

	xfree(n->name);
	xfree(n->addr);
	xfree(n->master);

	list_for_each_entry_safe(addr, t, &n->ip_addrs, l) {
		xfree(addr->addr);
		xfree(addr);
	}
}

int net_dev_set_mtu(ct_net_t n, int mtu)
{
	n->mtu = mtu;

	return 0;
}

int net_dev_set_mac_addr(ct_net_t n, char *addr)
{
	return set_string(&n->addr, addr);
}

int net_dev_set_master(ct_net_t n, char *master)
{
	return set_string(&n->master, master);
}

int net_dev_add_ip_addr(ct_net_t n, char *addr)
{
	struct ct_net_ip_addr *a;

	a = xzalloc(sizeof(*a));
	if (a == NULL)
		return -1;

	a->addr = xstrdup(addr);
	if (a->addr == NULL) {
		xfree(a);
		return -1;
	}

	list_add(&a->l, &n->ip_addrs);

	return 0;
}

void veth_stop(struct container *ct, struct ct_net *n)
{
	/* TODO: Ask Pavel about veth stop algo
	 * FIXME -- don't destroy veth here, keep it across
	 * container's restarts. This needs checks in the
	 * veth_pair_create() for existance.
	 */
}

int veth_match(struct ct_net *n, void *arg)
{
	struct ct_net_veth *vn = cn2vn(n);
	struct ct_net_veth_arg *va = arg;

	/* Matching hostname should be enough */
	return !strcmp(vn->peer.name, va->host_name);
}

void veth_free(struct ct_net_veth *vn)
{
	ct_net_clean(&vn->n);
	ct_net_clean(&vn->peer);
	xfree(vn);
}
