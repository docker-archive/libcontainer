#ifndef __LINUX_VZLIST_H__
#define __LINUX_VZLIST_H__

#include <linux/types.h>
#include <linux/ioctl.h>

#ifndef __KERNEL__
#include <stdint.h>
#endif

#ifndef __ENVID_T_DEFINED__
typedef unsigned envid_t;
#define __ENVID_T_DEFINED__
#endif

struct vzlist_vepidctl {
	envid_t		veid;
	unsigned int	num;
	pid_t 		*pid;
};

#define VZLISTTYPE 'x'
#define VZCTL_GET_VEPIDS	_IOR(VZLISTTYPE, 2, struct vzlist_vepidctl)

#endif /* __LINUX_VZLIST_H__ */
