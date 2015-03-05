#include <stdio.h>
#include <stdlib.h>
#include <libct.h>
#include <unistd.h>
#include <linux/sched.h>

#include "test.h"

#define VETH_HOST_NAME	"hveth0"
#define VETH_CT_NAME	"cveth0"

#define FS_ROOT		"root"
int main(int argc, char *argv[])
{
	libct_session_t s;
	ct_handler_t ct;
	ct_net_t nd;
	ct_process_desc_t pd;
	ct_process_t p;
	struct ct_net_veth_arg va = {
		.host_name = VETH_HOST_NAME,
		.ct_name = VETH_CT_NAME
	};
	char *ip_a[] = { "ip", "link", "show", NULL};

	s = libct_session_open_local();

	ct = libct_container_create(s, "1337");
	pd = libct_process_desc_create(s);
	libct_fs_set_root(ct, FS_ROOT);
	libct_container_set_nsmask(ct,
			CLONE_NEWNS |
			CLONE_NEWUTS |
			CLONE_NEWIPC |
			CLONE_NEWNET |
			CLONE_NEWPID);

	nd = libct_net_add(ct, CT_NET_VETH, &va);
	if (libct_handle_is_err(nd))
		return tst_err("Can't add hostnic");

	if (libct_net_dev_set_mac_addr(nd, "00:11:22:33:44:55"))
		return tst_err("Can't set mac");

	p = libct_container_spawn_execv(ct, pd, "/sbin/ip", ip_a);
	if (libct_handle_is_err(p))
		goto err;

	libct_container_wait(ct);
	libct_container_destroy(ct);

	libct_session_close(s);

	return pass("All is ok");;
err:
	return fail("Something wrong");
}
