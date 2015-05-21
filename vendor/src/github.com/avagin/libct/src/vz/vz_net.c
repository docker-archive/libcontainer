#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ether.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include "vzctl_veth.h"
#include "vz_net.h"
#include "vz.h"
#include "log.h"
#include "xmalloc.h"
#include "net_util.h"
#include "util.h"
#include "ct.h"

#define ETH_ALEN 6

static int gen_hwaddr(unsigned char *buf, int size)
{
	int res = -1;
	int fd = -1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return errno;

	res = read(fd, buf, size);
	if (res < 0) {
		int _errno = errno;
		close(fd);
		return _errno;
	}

	close(fd);
	if (res != size)
		return EINVAL;

	/* use locally administrated address */
	buf[0] = 0xfe;

	return 0;
}

static int vz_veth_ioctl(int op_type, struct container *ct, struct ct_net *n, const char *pair0, const char *pair1)
{
	struct vzctl_ve_hwaddr veth;
	int ret = -1;
	unsigned int veid = 0;
	if (ct) {
		ret = parse_uint(ct->name, &veid);
		if (ret) {
			pr_err("Unable to parse container's ID");
			return -1;
		}
	} else {
		veid = 0;
	}

	veth.op = op_type;
	veth.veid = veid;
	veth.addrlen = ETH_ALEN;
	veth.addrlen_ve = ETH_ALEN;

	ret = gen_hwaddr(veth.dev_addr, ETH_ALEN);
	if (ret) {
		pr_err("Failed to gen_hwaddr: err=%d", ret);
		return -1;
	}
	if (n->addr) {
		sscanf(n->addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &veth.dev_addr_ve[0],
			&veth.dev_addr_ve[1], &veth.dev_addr_ve[2], &veth.dev_addr_ve[3],
			&veth.dev_addr_ve[4], &veth.dev_addr_ve[5]);

	} else  {
		ret = gen_hwaddr(veth.dev_addr_ve, ETH_ALEN);
		if (ret) {
			pr_err("Failed to gen_hwaddr: err=%d", ret);
			return -1;
		}
	}
	memcpy(veth.dev_name, pair0, sizeof(veth.dev_name));
	memcpy(veth.dev_name_ve, pair1, sizeof(veth.dev_name_ve));

	ret = ioctl(get_vzctlfd(), VETHCTL_VE_HWADDR, &veth);
	if (ret) {
		if (errno == ENOTTY) {
			pr_err("veth feature is"
					" not supported by the kernel");
		} else {
			pr_err("Unable to perform operation %d on veth device"
					" pair %s %s err=%d",
					op_type, pair0, pair1, errno);
			pr_perror("Error");
		}
		return -1;
	}
	return 0;
}

static struct ct_net *vz_veth_create(void *arg, struct ct_net_ops const *ops)
{
	struct ct_net_veth_arg *va = arg;
	struct ct_net_veth *vn = NULL;

	if (!arg || !va->host_name || !va->ct_name)
		return NULL;

	vn = xzalloc(sizeof(*vn));
	if (!vn)
		return NULL;

	ct_net_init(&vn->n, ops);
	ct_net_init(&vn->peer, ops);

	vn->peer.name = xstrdup(va->host_name);
	vn->n.name = xstrdup(va->ct_name);
	if (!vn->peer.name || !vn->n.name) {
		xfree(vn->peer.name);
		xfree(vn->n.name);
		veth_free(vn);
		return NULL;
	}

	return &vn->n;

	return NULL;
}

static int vz_veth_start(struct container *ct, struct ct_net *n)
{
	struct ct_net_veth *vn = NULL;
	int ret = -1;

	if (!n)
		return -LCTERR_BADARG;
	vn = cn2vn(n);

	ret = vz_veth_ioctl(VE_ETH_ADD, ct, n, vn->peer.name, vn->n.name);
	if (ret)
		return ret;
	ret = vz_veth_ioctl(VE_ETH_ALLOW_MAC_CHANGE, ct, n, vn->peer.name, vn->n.name);
	return ret;
}

static void vz_veth_destroy(struct ct_net *n)
{
	struct ct_net_veth *vn = NULL;
	if (!n)
		return;
	vn = cn2vn(n);
	/* TODO: Ask Pavel: should we explicitly remove veth */
	/*vz_veth_ioctl(VE_ETH_DEL, NULL, vn->n.name, vn->peer.name);*/
	veth_free(vn);
}

static const struct ct_net_ops vz_veth_nic_ops = {
	.create		= vz_veth_create,
	.destroy	= vz_veth_destroy,
	.start		= vz_veth_start,
	.stop		= veth_stop,
	.match		= veth_match,
	.set_mac_addr	= net_dev_set_mac_addr,
	.set_master	= net_dev_set_master,
	.add_ip_addr	= net_dev_add_ip_addr,
	.set_mtu	= net_dev_set_mtu,
};

const struct ct_net_ops *vz_net_get_ops(enum ct_net_type ntype)
{
	switch (ntype) {
	case CT_NET_VETH:
		return &vz_veth_nic_ops;
	default:
		return NULL;
	}
}

ct_net_t vz_net_add(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	return __local_net_add(h, ntype, arg, vz_net_get_ops);
}

struct ct_net_veth *cn2vn(struct ct_net *n)
{
	return container_of(n, struct ct_net_veth, n);
}
