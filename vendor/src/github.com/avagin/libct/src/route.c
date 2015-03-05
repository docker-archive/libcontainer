#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include "uapi/libct.h"

#include "namespaces.h"
#include "xmalloc.h"
#include "util.h"
#include "list.h"
#include "err.h"
#include "net.h"
#include "ct.h"
#include "net_util.h"

void net_route_nh_free(ct_net_route_nh_t nh)
{
	if (nh == NULL)
		return;

	xfree(nh->gateway);
	xfree(nh->dev);
	xfree(nh);
}

void net_route_free(struct ct_net_route *r)
{
	ct_net_route_nh_t nh, t;

	if (r == NULL)
		return;

	list_for_each_entry_safe(nh, t, &r->nhs, l)
		net_route_nh_free(nh);

	xfree(r->dst);
	xfree(r->src);
	xfree(r->dev);
	xfree(r);
}


int net_route_nh_add(struct rtnl_route *route, struct ct_net_route_nh *n, struct nl_cache *cache)
{
	struct rtnl_nexthop *nh;
	int err;

	nh = rtnl_route_nh_alloc();
	if (nh == NULL)
		return -1;

	if (n->dev) {
		int idx;

		idx = rtnl_link_name2i(cache, n->dev);
		if (idx == 0)
			goto free;

		rtnl_route_nh_set_ifindex(nh, idx);
	}

	if (n->gateway) {
		struct nl_addr *addr;

		err = nl_addr_parse(n->gateway, AF_UNSPEC, &addr);
		if (err) {
			pr_err("Unable to parse %s: %s", n->gateway, nl_geterror(err));
			goto free;
		}

		rtnl_route_nh_set_gateway(nh, addr);
		nl_addr_put(addr);
	}

	rtnl_route_add_nexthop(route, nh);
	return 0;
free:
	rtnl_route_nh_free(nh);
	return -1;
}

int net_route_add(struct nl_sock *sk, struct nl_cache *cache, struct ct_net_route *r)
{
	struct ct_net_route_nh *n;
	struct rtnl_route *route;
	struct nl_addr *addr;
	int err, ret = -1;

	route = rtnl_route_alloc();
	if (route == NULL)
		return -1;

	if (r->src) {
		err = nl_addr_parse(r->src, AF_UNSPEC, &addr);
		if (err) {
			pr_err("Unable to parse %s: %s", r->src, nl_geterror(err));
			goto out;
		}
		err = rtnl_route_set_src(route, addr);
		nl_addr_put(addr);
		if (err) {
			pr_err("Unable to set %s: %s", r->src, nl_geterror(err));
			goto out;
		}
	}

	if (r->dst) {
		err = nl_addr_parse(r->dst, AF_UNSPEC, &addr);
		if (err) {
			pr_err("Unable to parse %s: %s", r->dst, nl_geterror(err));
			goto out;
		}
		err = rtnl_route_set_dst(route, addr);
		nl_addr_put(addr);
		if (err) {
			pr_err("Unable to set %s: %s", r->dst, nl_geterror(err));
			goto out;
		}
	}

	list_for_each_entry(n, &r->nhs, l)
		if (net_route_nh_add(route, n, cache))
			goto out;

	if (r->dev) {
		int idx;

		idx = rtnl_link_name2i(cache, r->dev);
		if (idx == 0)
			goto out;

		rtnl_route_set_iif(route, idx);
	}

	err = rtnl_route_add(sk, route, NLM_F_EXCL);
	if (err) {
		pr_err("Unable to add route: %s\n", nl_geterror(err));
		goto out;
	}

	ret = 0;
out:
	rtnl_route_put(route);

	return ret;
}

int net_route_setup(struct container *ct)
{
	struct ct_net_route *r;
	int rst, ret = -1;
	struct nl_sock *sk;
	struct nl_cache *cache;

	if (list_empty(&ct->ct_net_routes))
		return 0;

	if (switch_ns(ct->p.pid, &net_ns, &rst))
		return -1;

	sk = net_sock_open();
	restore_ns(rst, &net_ns);
	if (sk == NULL)
		return -1;

	cache = net_get_link_cache(sk);
	if (cache == NULL)
		goto out;

	list_for_each_entry(r, &ct->ct_net_routes, l) {
		ret = net_route_add(sk, cache, r);
		if (ret)
			goto out;
	}

	ret = 0;
out:
	nl_cache_put(cache);
	net_sock_close(sk);

	return ret;
}

void net_route_release(struct container *ct)
{
	struct ct_net_route *r, *t;
	list_for_each_entry_safe(r, t, &ct->ct_net_routes, l)
		net_route_free(r);
}

ct_net_route_t local_net_route_add(ct_handler_t h)
{
	struct container *ct = cth2ct(h);
	struct ct_net_route *r;

	r = xzalloc(sizeof(*r));
	if (r == NULL)
		return NULL;

	INIT_LIST_HEAD(&r->nhs);

	list_add(&r->l, &ct->ct_net_routes);

	return r;
}

ct_net_route_t libct_net_route_add(ct_handler_t ct)
{
	return ct->ops->net_route_add(ct);
}

int libct_net_route_set_src(ct_net_route_t r, char *addr)
{
	return set_string(&r->src, addr);
}

int libct_net_route_set_dst(ct_net_route_t r, char *addr)
{
	return set_string(&r->dst, addr);
}

int libct_net_route_set_dev(ct_net_route_t r, char *dev)
{
	return set_string(&r->dev, dev);
}

ct_net_route_nh_t libct_net_route_add_nh(ct_net_route_t r)
{
	ct_net_route_nh_t nh;

	nh = xzalloc(sizeof(*nh));
	if (nh == NULL)
		return NULL;

	list_add(&nh->l, &r->nhs);

	return nh;
}

int libct_net_route_nh_set_gw(ct_net_route_nh_t nh, char *addr)
{
	return set_string(&nh->gateway, addr);
}

int libct_net_route_nh_set_dev(ct_net_route_nh_t nh, char *dev)
{
	return set_string(&nh->dev, dev);
}
