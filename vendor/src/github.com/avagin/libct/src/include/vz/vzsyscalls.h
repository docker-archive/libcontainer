/*
 *  Copyright (c) 1999-2010, Parallels, Inc. All rights reserved.
 *
 */

#ifndef _VZSYSCALLS_H_
#define _VZSYSCALLS_H_

#include <sys/syscall.h>

#ifdef __ia64__
#define __NR_setluid		1506
#define __NR_setublimit		1507
#define __NR_ioprio_set		1274
#elif __x86_64__
#define __NR_setluid		501
#define __NR_setublimit		502
#define __NR_ioprio_set		251
#define __NR_setns		308
#elif __powerpc__
#define __NR_setluid		411
#define __NR_setublimit		412
#define __NR_ioprio_set		273
#elif defined(__i386__) || defined(__sparc__)
#define __NR_setluid		511
#define __NR_setublimit		512
#define __NR_setns		346
#ifdef __sparc__
#define __NR_ioprio_set		196
#else
#define __NR_ioprio_set		289
#endif
#else
#error "no syscall for this arch"
#endif

#endif
