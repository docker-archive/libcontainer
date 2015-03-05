#ifndef __LIBCT_SYSTEMD_H__
#define __LIBCT_SYSTEMD_H__

struct container;
int systemd_start_unit(struct container *ct, int pid);
int systemd_add_pid(struct container *ct, int pid);

#endif //__LIBCT_SYSTEMD_H__
