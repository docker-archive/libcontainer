#ifndef __LIBCT_ERRORS_H__
#define __LIBCT_ERRORS_H__
/*
 * This file contains error codes, that can be returned from various
 * library calls in negative form.
 */

/* Codes bellow 1000 are reserved for generic Linux error codes */

/* Generic */
#define LCTERR_BADCTSTATE	1002	/* Bad container state */
#define LCTERR_BADTYPE		1003	/* Bad type requested */
#define LCTERR_BADARG		1004	/* Bad argument for request */
#define LCTERR_NONS		1005	/* Required namespace is not available */
#define LCTERR_NOTFOUND		1006	/* Requested object not found */
#define LCTERR_INVARG		1007	/* Invalid API call argument */
#define LCTERR_OPNOTSUPP	1008	/* Operation not supported */

/* FS-specific */
#define LCTERR_CANTMOUNT	1010	/* Can't mount something */

/* CGroups-specifig */
#define LCTERR_CGCREATE		1021	/* Can't create cgroup */
#define LCTERR_CGCONFIG		1022	/* Can't configure cgroup */
#define	LCTERR_CGATTACH		1023	/* Can't attach to cgroup */

/* RPC-specific ones */
#define LCTERR_BADCTRID		1042	/* Bad container remote ID given */
#define LCTERR_BADCTRNAME	1043	/* Bad name on open */
#define LCTERR_RPCUNKNOWN	1044	/* Remote problem , but err is not given */
#define LCTERR_RPCCOMM		1045	/* Error communicating via channel */

#endif /* __LIBCT_ERRORS_H__ */
