/*
 *  include/linux/vzcalluser.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _LINUX_VZCALLUSER_H
#define _LINUX_VZCALLUSER_H

#include <linux/ioctl.h>
#include "types.h"
#include "vziptable_defs.h"

#ifndef __ENVID_T_DEFINED__
typedef unsigned envid_t;
#define __ENVID_T_DEFINED__
#endif

#ifndef __KERNEL__
#define __user
#endif

/*
 * VE management ioctls
 */

struct vzctl_old_env_create {
	envid_t veid;
	unsigned flags;
#define VE_CREATE 	1	/* Create VE, VE_ENTER added automatically */
#define VE_EXCLUSIVE	2	/* Fail if exists */
#define VE_ENTER	4	/* Enter existing VE */
#define VE_TEST		8	/* Test if VE exists */
#define VE_LOCK		16	/* Do not allow entering created VE */
#define VE_SKIPLOCK	32	/* Allow entering embrion VE */
	__u32 addr;
};

struct vzctl_mark_env_to_down {
	envid_t veid;
};

struct vzctl_setdevperms {
	envid_t veid;
	unsigned type;
#define VE_USE_MAJOR	010	/* Test MAJOR supplied in rule */
#define VE_USE_MINOR	030	/* Test MINOR supplied in rule */
#define VE_USE_MASK	030	/* Testing mask, VE_USE_MAJOR|VE_USE_MINOR */
	unsigned dev;
	unsigned mask;
};

struct vzctl_ve_netdev {
	envid_t veid;
	int op;
#define VE_NETDEV_ADD  1
#define VE_NETDEV_DEL  2
	char __user *dev_name;
};

struct vzctl_ve_configure {
	unsigned int veid;
	unsigned int key;
#define VE_CONFIGURE_OS_RELEASE		2
#define VE_CONFIGURE_CREATE_PROC_LINK	4
#define VE_CONFIGURE_OPEN_TTY		5
#define VE_CONFIGURE_MOUNT_OPTIONS	7
	unsigned int val;
	unsigned int size;
	char data[0];
};

struct vzctl_ve_meminfo {
	envid_t veid;
	unsigned long val;
};

struct vzctl_env_create_cid {
	envid_t veid;
	unsigned flags;
	__u32 class_id;
};

struct vzctl_env_create {
	envid_t veid;
	unsigned flags;
	__u32 class_id;
};

struct env_create_param {
	__u64 iptables_mask;
};

#define VZCTL_ENV_CREATE_DATA_MINLEN	sizeof(struct env_create_param)

struct env_create_param2 {
	__u64 iptables_mask;
	__u64 feature_mask;
	__u32 total_vcpus;	/* 0 - don't care, same as in host */
};

struct env_create_param3 {
	__u64 iptables_mask;
	__u64 feature_mask;
	__u32 total_vcpus;
	__u32 pad;
	__u64 known_features;
};

#define VE_FEATURE_SYSFS	(1ULL << 0)
#define VE_FEATURE_NFS		(1ULL << 1)
#define VE_FEATURE_DEF_PERMS	(1ULL << 2)
#define VE_FEATURE_SIT          (1ULL << 3)
#define VE_FEATURE_IPIP         (1ULL << 4)
#define VE_FEATURE_PPP		(1ULL << 5)
#define VE_FEATURE_IPGRE	(1ULL << 6)
#define VE_FEATURE_BRIDGE	(1ULL << 7)
#define VE_FEATURE_NFSD		(1ULL << 8)

#define VE_FEATURES_OLD		(VE_FEATURE_SYSFS)
#define VE_FEATURES_DEF		(VE_FEATURE_SYSFS | \
				 VE_FEATURE_DEF_PERMS)

typedef struct env_create_param3 env_create_param_t;
#define VZCTL_ENV_CREATE_DATA_MAXLEN	sizeof(env_create_param_t)

struct vzctl_env_create_data {
	envid_t veid;
	unsigned flags;
	__u32 class_id;
	env_create_param_t __user *data;
	int datalen;
};

struct vz_load_avg {
	int val_int;
	int val_frac;
};

struct vz_cpu_stat {
	unsigned long user_jif;
	unsigned long nice_jif;
	unsigned long system_jif; 
	unsigned long uptime_jif;
	__u64 idle_clk;
	__u64 strv_clk;
	__u64 uptime_clk;
	struct vz_load_avg avenrun[3];	/* loadavg data */
};

struct vzctl_cpustatctl {
	envid_t veid;
	struct vz_cpu_stat __user *cpustat;
};

#define VZCTLTYPE '.'
#define VZCTL_OLD_ENV_CREATE	_IOW(VZCTLTYPE, 0,			\
					struct vzctl_old_env_create)
#define VZCTL_MARK_ENV_TO_DOWN	_IOW(VZCTLTYPE, 1,			\
					struct vzctl_mark_env_to_down)
#define VZCTL_SETDEVPERMS	_IOW(VZCTLTYPE, 2,			\
					struct vzctl_setdevperms)
#define VZCTL_ENV_CREATE_CID	_IOW(VZCTLTYPE, 4,			\
					struct vzctl_env_create_cid)
#define VZCTL_ENV_CREATE	_IOW(VZCTLTYPE, 5,			\
					struct vzctl_env_create)
#define VZCTL_GET_CPU_STAT	_IOW(VZCTLTYPE, 6,			\
					struct vzctl_cpustatctl)
#define VZCTL_ENV_CREATE_DATA	_IOW(VZCTLTYPE, 10,			\
					struct vzctl_env_create_data)
#define VZCTL_VE_NETDEV		_IOW(VZCTLTYPE, 11,			\
					struct vzctl_ve_netdev)
#define VZCTL_VE_MEMINFO	_IOW(VZCTLTYPE, 13,                     \
					struct vzctl_ve_meminfo)
#define VZCTL_VE_CONFIGURE	_IOW(VZCTLTYPE, 15,			\
					struct vzctl_ve_configure)

#ifdef __KERNEL__
#ifdef CONFIG_COMPAT
#include <linux/compat.h>

struct compat_vzctl_ve_netdev {
	envid_t veid;
	int op;
	compat_uptr_t dev_name;
};

struct compat_vzctl_ve_meminfo {
	envid_t veid;
	compat_ulong_t val;
};

struct compat_vzctl_env_create_data {
	envid_t veid;
	unsigned flags;
	__u32 class_id;
	compat_uptr_t data;
	int datalen;
};

#define VZCTL_COMPAT_ENV_CREATE_DATA _IOW(VZCTLTYPE, 10,		\
					struct compat_vzctl_env_create_data)
#define VZCTL_COMPAT_VE_NETDEV	_IOW(VZCTLTYPE, 11,			\
					struct compat_vzctl_ve_netdev)
#define VZCTL_COMPAT_VE_MEMINFO	_IOW(VZCTLTYPE, 13,                     \
					struct compat_vzctl_ve_meminfo)
#endif
#endif

#endif
