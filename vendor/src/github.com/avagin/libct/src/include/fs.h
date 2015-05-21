#ifndef __LIBCT_FS_H__
#define __LIBCT_FS_H__

#include "uapi/libct.h"

struct container;

struct ct_fs_ops {
	int (*mount)(char *root, void *fs_priv);
	void (*umount)(char *root, void *fs_priv);
	void *(*get)(void *fs_priv);
	void (*put)(void *fs_priv);
};

extern const struct ct_fs_ops *fstype_get_ops(enum ct_fs_type type);
extern int local_fs_set_root(ct_handler_t h, char *root);
extern int local_fs_set_private(ct_handler_t ct, enum ct_fs_type type, void *priv);
extern int local_add_bind_mount(ct_handler_t ct, char *src, char *dst, int flags);
extern int local_del_bind_mount(ct_handler_t ct, char *dst);
extern int local_add_mount(ct_handler_t h, char *src, char *dst, int flags, char *fstype, char *data,
				struct libct_cmd *premount, struct libct_cmd *postdump);

extern int fs_mount(struct container *ct);
extern int fs_mount_ext(struct container *ct);
extern void fs_umount(struct container *ct);
extern void fs_umount_ext(struct container *ct);
extern void fs_free(struct container *ct);

extern int local_add_devnode(ct_handler_t h, char *path, int mode, int maj, int minor);

extern int fs_create_devnodes(struct container *ct);
extern void fs_free_devnodes(struct container *ct);

#endif /* __LIBCT_FS_H__ */
