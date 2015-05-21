#ifndef __LIBCT_VZ_H__
#define __LIBCT_VZ_H__

#include "uapi/libct.h"

struct container_ops;

ct_handler_t vz_ct_create(char *name);
const struct container_ops *get_vz_ct_ops(void);
int vzctl_open(void);
void vzctl_close(void);
int get_vzctlfd(void);

#endif
