/*
 *  include/linux/vzctl_veth.h
 *
 *  Copyright (C) 2006  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _VZCTL_VETH_H
#define _VZCTL_VETH_H

#include <linux/types.h>
#include <linux/ioctl.h>

#ifndef __ENVID_T_DEFINED__
typedef unsigned envid_t;
#define __ENVID_T_DEFINED__
#endif

struct vzctl_ve_hwaddr {
	envid_t veid;
	int op;
#define VE_ETH_ADD			1
#define VE_ETH_DEL			2
#define VE_ETH_ALLOW_MAC_CHANGE		3
#define VE_ETH_DENY_MAC_CHANGE		4
	unsigned char	dev_addr[6];
	int addrlen;
	char		dev_name[16];
	unsigned char	dev_addr_ve[6];
	int addrlen_ve;
	char		dev_name_ve[16];
};

#define VETHCTLTYPE '['

#define VETHCTL_VE_HWADDR	_IOW(VETHCTLTYPE, 3,			\
					struct vzctl_ve_hwaddr)

#endif
