/*
 * Warning: this header is used in log plugin as well,
 * modify carefully.
 */

#ifndef __LIBCT_LOG_H__
#define __LIBCT_LOG_H__

#include <stdio.h>
#include <stdbool.h>

#include "uapi/libct-log-levels.h"

#ifndef LOG_PREFIX
# define LOG_PREFIX
#endif

extern void print_on_level(unsigned int loglevel, const char *format, ...);

#define pr_msg(fmt, ...)							\
	print_on_level(LOG_MSG,							\
		       fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)							\
	print_on_level(LOG_INFO,						\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)							\
	print_on_level(LOG_ERROR,						\
		       "Error (%s:%d): " LOG_PREFIX fmt,			\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_err_once(fmt, ...)							\
	do {									\
		static bool __printed;						\
		if (!__printed) {						\
			pr_err(fmt, ##__VA_ARGS__);				\
			__printed = 1;						\
		}								\
	} while (0)

#define pr_warn(fmt, ...)							\
	print_on_level(LOG_WARN,						\
		       "Warn  (%s:%d): " LOG_PREFIX fmt,			\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_warn_once(fmt, ...)							\
	do {									\
		static bool __printed;						\
		if (!__printed) {						\
			pr_warn(fmt, ##__VA_ARGS__);				\
			__printed = 1;						\
		}								\
	} while (0)

#define pr_debug(fmt, ...)							\
	print_on_level(LOG_DEBUG,						\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)							\
	pr_err(fmt ": %m\n", ##__VA_ARGS__)

#endif /* __LIBCT_LOG_H__ */
