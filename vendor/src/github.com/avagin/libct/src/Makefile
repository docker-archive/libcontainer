lib-so			+= libct
lib-a			+= libct

obj-y			+= libct.o
obj-y			+= session.o
obj-y			+= ct.o
obj-y			+= namespaces.o
obj-y			+= cgroups.o
obj-y			+= log.o
obj-y			+= linux_kernel.o
obj-y			+= fs.o
obj-y			+= net.o
obj-y			+= security.o
obj-y			+= util.o
obj-y			+= devnodes.o
obj-y			+= route.o
obj-y			+= process.o
obj-y			+= net_util.o
obj-y			+= cmd.o
obj-y			+= vz/vz.o
obj-y			+= vz/vz_net.o
obj-y			+= vz/readelf.o
obj-y			+= lsm/lsm.o
obj-$(CONFIG_APPARMOR)	+= lsm/apparmor.o
obj-$(CONFIG_SELINUX)	+= lsm/selinux.o
obj-y			+= lsm/nop.o
obj-y			+= systemd.o

cflags-y		+= -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= -rdynamic

.SECONDARY:

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
