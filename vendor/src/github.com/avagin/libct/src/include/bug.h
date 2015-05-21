#ifndef __LIBCT_BUG_H__
#define __LIBCT_BUG_H__

#include <signal.h>

#include "compiler.h"
#include "log.h"

#ifndef BUG_ON_HANDLER

# define __raise() raise(SIGABRT)

# define BUG_ON_HANDLER(condition)							\
	do {										\
		if ((condition)) {							\
			pr_err("BUG at %s:%d\n", __FILE__, __LINE__);			\
			__raise();							\
			*(volatile unsigned long *)NULL = 0xdead0000 + __LINE__;	\
		}									\
	} while (0)

#endif /* BUG_ON_HANDLER */

#define BUG_ON(condition)	BUG_ON_HANDLER((condition))
#define BUG()			BUG_ON(true)

#endif /* __LIBCT_BUG_H__ */
