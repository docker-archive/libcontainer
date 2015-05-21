COMMON_TESTS = vz_create_exec vz_net_veth vz_enter

LOCAL_TESTS =	ct_create ct_enter ct_proc ct_root ct_root_enter \
	ct_create_exec ct_cgroup_basic ct_net_host \
	ct_net_veth ct_private_subdir \
	ct_ext_mount ct_private_subdir_ns \
	ct_cgroup_sub ct_service ct_kill_nons ct_pid_enter \
	ct_userns ct_caps ct_fds ct_pause

VZ_TESTS = vz_cgroup_memory vz_cgroup_cpu vz_cgroup_blkio

TESTS = $(LOCAL_TESTS) $(VZ_TESTS) $(COMMON_TESTS)

PIGS  = file_piggy

CC = gcc
CFLAGS = -I../src/include/uapi/ -g -Wall -Werror

CFLAGS += $(DEFINES)

ifneq ("$(wildcard /proc/vz)","")
	CFLAGS += -I/usr/src/kernels/$(shell uname -r)/include/
	CFLAGS += -DVZ
endif
LIBNLDIR = ../.shipped/libnl/lib/.libs
LDFLAGS = -Wl,--no-as-needed \
	-lct -L../src/ -Wl,-rpath,'$$ORIGIN/../src' \
	-lnl-route-3 -lnl-3 -L$(LIBNLDIR) -Wl,-rpath,'$$ORIGIN/$(LIBNLDIR)' \
	-ldbus-1

COMMON_OUTS = $(COMMON_TESTS:%=%.out)
LOCAL_OUTS = $(LOCAL_TESTS:%=%.out)
VZ_OUTS = $(VZ_TESTS:%=%.out)

ifdef CONFIG_APPARMOR
LDFLAGS += -lapparmor
LOCAL_TESTS += ct_apparmor
endif

ifdef CONFIG_SELINUX
LDFLAGS += -lselinux
endif

OUTS = $(TESTS:%=%.out)
OBJS = $(TESTS:%=%.o)

all: $(PIGS) $(TESTS)

local: $(PIGS) $(LOCAL_TESTS)
common: $(PIGS) $(COMMON_TESTS)

vz: $(VZ_TESTS)

cleanouts:
	rm -f $(OUTS)

clean: cleanouts
	rm -f $(TESTS)
	rm -f $(PIGS)
	rm -f $(OBJS)
	rm -rf root

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

define gen-out
$(1): $(1).o
	$$(CC) -o $$@ $$^ $$(LDFLAGS)

$(1).out: $(1)
	./$$^ > $$@
	@ tail -n1 $$@
endef
$(foreach t, $(TESTS) $(PIGS), $(eval $(call gen-out,$(t))))

run-local: cleanouts root $(PIGS) $(LOCAL_OUTS) $(COMMON_OUTS)

run-vz: cleanouts root $(VZ_OUTS) $(COMMON_OUTS)

run: cleanouts $(PIGS) $(OUTS)

root:
	mkdir root
	curl -sSL https://github.com/jpetazzo/docker-busybox/raw/buildroot-2014.02/rootfs.tar | tar -xC root

.PHONY: all local vz clean run run-local run-vz
