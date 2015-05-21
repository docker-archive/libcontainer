#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>

#include <sys/prctl.h>

#include <linux/capability.h>

#include "uapi/libct.h"

#include "linux-kernel.h"
#include "security.h"
#include "xmalloc.h"
#include "list.h"
#include "log.h"
#include "ct.h"

static int apply_bset(uint64_t mask)
{
	int i, last_cap;

	last_cap = linux_get_last_capability();
	if (last_cap < 0)
		return -1;

	for (i = 0; i <= last_cap; i++) {
		if (mask & (1ULL << i))
			continue;

		if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) == -1)
			return -1;
	}

	return 0;
}

extern int capget(cap_user_header_t header, const cap_user_data_t data);
extern int capset(cap_user_header_t header, const cap_user_data_t data);

static int apply_all_caps(uint64_t mask)
{
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct data[2]; /* as of .._VERSION_3 */

	memset(&header, 0, sizeof(header));
	capget(&header, data);
	switch (header.version) {
		case _LINUX_CAPABILITY_VERSION_1:
		case _LINUX_CAPABILITY_VERSION_2:
		case _LINUX_CAPABILITY_VERSION_3:
			break;
		default:
			return -1;
	}

	header.pid = 0;

	data[0].effective = mask;
	data[0].permitted = mask;
	data[0].inheritable = mask;

	mask >>= 32;
	data[1].effective = mask;
	data[1].permitted = mask;
	data[1].inheritable = mask;

	return capset(&header, data);
}

static int __add_group(gid_t gid, gid_t **groups, int *ngroups)
{
	int n;
	gid_t *g;

	n = *ngroups + 1;
	if (*groups == NULL)
		g = xmalloc(n * sizeof(gid_t));
	else
		g = xrealloc(*groups, n * sizeof(gid_t));
	if (g == NULL)
		return -1;

	g[n - 1] = gid;
	*groups = g;
	*ngroups = n;
	return 0;
}

static int libct_getgroups(char *user, gid_t **__groups)
{
	char *name = NULL, *passwd = NULL, *users = NULL;
	char buff[4096], *str;
	int ngroups = 0;
	gid_t *groups = NULL;
	FILE *f;

	f = fopen("/etc/group", "r");
	if (f == NULL) {
		return -1;
	}

	while ((str = fgets(buff, sizeof(buff), f))) {
		gid_t gid;
		int off, len, ret;

		name = NULL;
		passwd = NULL;
		users = NULL;

		ret = sscanf(str, "%m[^:]:%m[^:]:%u:%ms", &name, &passwd, &gid, &users);
		if (ret < 3) {
			pr_err("Unable to parse: %s -> %d\n", str, ret);
			goto err;
		}
		if (ret < 4)
			continue;

		len = strlen(users);
		off = 0;
		while (off < len) {
			char *c;
			c = strchr(users + off, ',');
			if (c != NULL)
				*c = 0;

			if (strcmp(users + off, user) == 0) {
				if (__add_group(gid, &groups, &ngroups))
					goto err;
				break;
			}

			if (c != NULL) {
				*c = ',';
				off = c - users;
			} else
				off = len;
		}
		xfree(name);
		xfree(passwd);
		xfree(users);
	}

	*__groups = groups;
	return ngroups;
err:
	xfree(name);
	xfree(passwd);
	xfree(users);
	fclose(f);
	return -1;
}

static int libct_getpwnam(char *user, char *buf, size_t buflen, struct passwd *result)
{
	FILE *f;
	char buff[4096], *str;

	f = fopen("/etc/passwd", "r");
	if (f == NULL) {
		return -1;
	}

	while ((str = fgets(buff, sizeof(buff), f))) {
		char *name = NULL, *passwd = NULL, *gecos = NULL, *home = NULL, *shell = NULL;
		char suid[11];
		unsigned int uid, gid;
		int ret;
		off_t off;

		/* name:password:UID:GID:GECOS:directory:shell */
		/* root:x:0:0:root:/root:/bin/sh */
		errno = 0;
		ret = sscanf(str, "%m[^:]:%m[^:]:%u:%u:%m[^:]:%m[^:]:%m[^:]", &name, &passwd, &uid, &gid, &gecos, &home, &shell);
		if (ret != 7) {
			pr_perror("Unable to parse: %s -> %d\n", str, ret);
			xfree(name);
			xfree(passwd);
			xfree(gecos);
			xfree(home);
			xfree(shell);
			goto err;
		}
		snprintf(suid, sizeof(suid), "%d", uid);

		if (strcmp(user, name) && strcmp(suid, user))
			continue;

		off = 0;
		result->pw_name = buf + off;
		off += strlen(name) + 1;
		result->pw_passwd = buf + off;
		off += strlen(passwd) + 1;
		result->pw_uid = uid;
		result->pw_gid = gid;
		result->pw_gecos = buf + off;
		off += strlen(gecos) + 1;
		result->pw_dir = buf + off;
		off += strlen(home) + 1;
		result->pw_shell = buf + off;
		off += strlen(shell) + 1;

		strcpy(result->pw_name, name);
		strcpy(result->pw_passwd, passwd);
		strcpy(result->pw_gecos, gecos);
		strcpy(result->pw_dir, home);
		strcpy(result->pw_shell, shell);
		xfree(name);
		xfree(passwd);
		xfree(gecos);
		xfree(home);
		xfree(shell);
		return 0;
	}

err:
	fclose(f);
	return -1;
}

int apply_creds(struct process_desc *p)
{
	if (p->user) {
		char buf[4096];
		struct passwd e;
		gid_t *groups = NULL;
		int ngroups;

		if (libct_getpwnam(p->user, buf, sizeof(buf), &e))
			return -1;

		p->uid = e.pw_uid;
		p->gid = e.pw_gid;

		ngroups = libct_getgroups(e.pw_name, &groups);
		if (ngroups < 0)
			return ngroups;
		if (p->groups == NULL) {
			p->groups = groups;
			p->ngroups = ngroups;
		} else {
			gid_t *_groups;
			_groups = xrealloc(p->groups, p->ngroups + ngroups);
			if (_groups == NULL)
				return -1;
			p->groups = _groups;
			memcpy(p->groups + p->ngroups, groups, sizeof(gid_t) * ngroups);
			p->ngroups += ngroups;
			xfree(groups);
		}

		setenv("HOME", e.pw_dir, 0);
	}

	if (setgroups(p->ngroups, p->groups))
		return -1;

	if (p->cap_mask & CAPS_BSET)
		if (apply_bset(p->cap_bset) < 0)
			return -1;

	if (prctl(PR_SET_KEEPCAPS, 1))
		pr_perror("Unable to set PR_SET_KEEPCAPS\n");
	if (setgid(p->gid) || setuid(p->uid))
		return -1;
	if (prctl(PR_SET_KEEPCAPS, 0)) {
		pr_perror("Unable to clear PR_SET_KEEPCAPS\n");
		return -1;
	}

	if (p->cap_mask & CAPS_ALLCAPS)
		if (apply_all_caps(p->cap_caps) < 0)
			return -1;

	return 0;
}
