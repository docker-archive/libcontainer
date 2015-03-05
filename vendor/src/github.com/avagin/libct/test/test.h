#ifndef __LIBCT_TEST_H__
#define __LIBCT_TEST_H__

#include <unistd.h>
#include <stdarg.h>

#include <libct-log-levels.h>

static inline void test_init()
{
	libct_log_init(STDERR_FILENO, LOG_DEBUG);
}

static inline int __tst_msg(int code, const char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	vprintf(format, vl);
	va_end(vl);
	return code;
}

#define tst_err(fmt, ...) \
	__tst_msg(2, "%s:%d: Error: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define tst_perr(fmt, ...) \
	__tst_msg(2, "%s:%d: Error: " fmt ": %m\n", __func__, __LINE__, ##__VA_ARGS__)

#define pass(fmt, ...) \
	__tst_msg(0, "%s:%d: PASS: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define fail(fmt, ...) \
	__tst_msg(1, "%s:%d: FAIL: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#endif
