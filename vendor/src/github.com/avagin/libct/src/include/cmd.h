#ifndef __LIBCT_CMD_H__
#define __LIBCT_CMD_H__

#include "uapi/libct.h"

extern void free_cmd(struct libct_cmd *cmd);
extern struct libct_cmd * alloc_cmd(struct libct_cmd *cmd);
extern int exec_cmd(struct libct_cmd *cmd);

#endif /* __LIBCT_CMD_H__ */
