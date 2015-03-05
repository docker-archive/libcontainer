/*
 *  Copyright (c) 1999-2010, Parallels, Inc. All rights reserved.
 *
 */

#ifndef _READELF_H_
#define _READELF_H_

enum {elf_none = 0,
      elf_32 = 1,
      elf_64 = 2};
int get_arch_from_elf(const char *file);

#endif
