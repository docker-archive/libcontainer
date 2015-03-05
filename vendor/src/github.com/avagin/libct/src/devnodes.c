#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "list.h"
#include "uapi/libct.h"
#include "xmalloc.h"
#include "ct.h"

struct fs_devnode {
	struct list_head l;

	char *path;
	mode_t mode;
	dev_t dev;
};

int local_add_devnode(ct_handler_t h, char *path, int mode, int major, int minor)
{
	struct container *ct = cth2ct(h);
	struct fs_devnode *dev;

	if (ct->state != CT_STOPPED)
		/* FIXME -- implement */
		return -LCTERR_BADCTSTATE;

	dev = xmalloc(sizeof(*dev));
	if (dev == NULL)
		return -1;

	dev->path = xstrdup(path);
	if (dev->path == NULL) {
		xfree(dev);
		return -1;
	}
	dev->mode = mode;
	dev->dev = makedev(major, minor);
	list_add_tail(&dev->l, &ct->fs_devnodes);

	return 0;
}

int libct_fs_add_devnode(ct_handler_t ct, char *path, int mode, int major, int minor)
{

	if (!path)
		return -LCTERR_INVARG;

	return ct->ops->fs_add_devnode(ct, path, mode, major, minor);
}

int fs_create_devnodes(struct container *ct)
{
	struct fs_devnode *d;

	list_for_each_entry(d, &ct->fs_devnodes, l) {
		unlink(d->path);
		if (mknod(d->path, d->mode, d->dev) == -1) {
			pr_perror("Unable to create device");
			return -1;
		}
	}

	return 0;
}

void fs_free_devnodes(struct container *ct)
{
	struct fs_devnode *d, *dn;

	list_for_each_entry_safe(d, dn, &ct->fs_mnts, l) {
		list_del(&d->l);
		xfree(d->path);
		xfree(d);
	}
}
