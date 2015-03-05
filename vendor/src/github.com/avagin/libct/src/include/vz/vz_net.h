#ifndef __LIBCT_VZ_NET_H__
#define __LIBCT_VZ_NET_H__

#include "net.h"

extern const struct ct_net_ops *vz_net_get_ops(enum ct_net_type);
extern ct_net_t vz_net_add(ct_handler_t h, enum ct_net_type ntype, void *arg);

#endif /* __LIBCT_VZ_NET_H__ */
