// +build linux

package libcontainer

/*
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <malloc.h>

#define INVALID_SYSCALL -1

#ifndef __NR_msgctl
#define __NR_msgctl INVALID_SYSCALL
#endif

#ifndef __NR_accept
#define __NR_accept INVALID_SYSCALL
#endif

#ifndef __NR_semctl
#define __NR_semctl INVALID_SYSCALL
#endif

#ifndef __NR_getsockname
#define __NR_getsockname INVALID_SYSCALL
#endif

#ifndef __NR_accept4
#define __NR_accept4 INVALID_SYSCALL
#endif

#ifndef __NR_listen
#define __NR_listen INVALID_SYSCALL
#endif

#ifndef __NR_semget
#define __NR_semget INVALID_SYSCALL
#endif

#ifndef __NR_epoll_wait_old
#define __NR_epoll_wait_old INVALID_SYSCALL
#endif

#ifndef __NR_recvmsg
#define __NR_recvmsg INVALID_SYSCALL
#endif

#ifndef __NR_recvfrom
#define __NR_recvfrom INVALID_SYSCALL
#endif

#ifndef __NR_socket
#define __NR_socket INVALID_SYSCALL
#endif

#ifndef __NR_semtimedop
#define __NR_semtimedop INVALID_SYSCALL
#endif

#ifndef __NR_msgrcv
#define __NR_msgrcv INVALID_SYSCALL
#endif

#ifndef __NR_getpeername
#define __NR_getpeername INVALID_SYSCALL
#endif

#ifndef __NR_msgsnd
#define __NR_msgsnd INVALID_SYSCALL
#endif

#ifndef __NR_sendmsg
#define __NR_sendmsg INVALID_SYSCALL
#endif

#ifndef __NR_shmdt
#define __NR_shmdt INVALID_SYSCALL
#endif

#ifndef __NR_connect
#define __NR_connect INVALID_SYSCALL
#endif

#ifndef __NR_msgget
#define __NR_msgget INVALID_SYSCALL
#endif

#ifndef __NR_tuxcall
#define __NR_tuxcall INVALID_SYSCALL
#endif

#ifndef __NR_getsockopt
#define __NR_getsockopt INVALID_SYSCALL
#endif

#ifndef __NR_socketpair
#define __NR_socketpair INVALID_SYSCALL
#endif

#ifndef __NR_newfstatat
#define __NR_newfstatat INVALID_SYSCALL
#endif

#ifndef __NR_sendto
#define __NR_sendto INVALID_SYSCALL
#endif

#ifndef __NR_semop
#define __NR_semop INVALID_SYSCALL
#endif

#ifndef __NR_setsockopt
#define __NR_setsockopt INVALID_SYSCALL
#endif

#ifndef __NR_bind
#define __NR_bind INVALID_SYSCALL
#endif

#ifndef __NR_shutdown
#define __NR_shutdown INVALID_SYSCALL
#endif

#ifndef __NR_arch_prctl
#define __NR_arch_prctl INVALID_SYSCALL
#endif

#ifndef __NR_shmat
#define __NR_shmat INVALID_SYSCALL
#endif

#ifndef __NR_shmctl
#define __NR_shmctl INVALID_SYSCALL
#endif

#ifndef __NR_epoll_ctl_old
#define __NR_epoll_ctl_old INVALID_SYSCALL
#endif

#ifndef __NR_shmget
#define __NR_shmget INVALID_SYSCALL
#endif

#ifndef __NR_security
#define __NR_security INVALID_SYSCALL
#endif

#ifndef __NR_arm_sync_file_range
#define __NR_arm_sync_file_range INVALID_SYSCALL
#endif

#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load INVALID_SYSCALL
#endif

#ifndef __NR_syscall
#define __NR_syscall INVALID_SYSCALL
#endif

#ifndef __NR_sysmips
#define __NR_sysmips INVALID_SYSCALL
#endif

#ifndef __NR_cacheflush
#define __NR_cacheflush INVALID_SYSCALL
#endif

#ifndef __NR_oldwait4
#define __NR_oldwait4 INVALID_SYSCALL
#endif

#ifndef __NR_pciconfig_iobase
#define __NR_pciconfig_iobase INVALID_SYSCALL
#endif

#ifndef __NR_bpf
#define __NR_bpf INVALID_SYSCALL
#endif

#ifndef __NR_pciconfig_write
#define __NR_pciconfig_write INVALID_SYSCALL
#endif

#ifndef __NR_send
#define __NR_send INVALID_SYSCALL
#endif

#ifndef __NR_memfd_create
#define __NR_memfd_create INVALID_SYSCALL
#endif

#ifndef __NR_pciconfig_read
#define __NR_pciconfig_read INVALID_SYSCALL
#endif

#ifndef __NR_execveat
#define __NR_execveat INVALID_SYSCALL
#endif

#ifndef __NR_recv
#define __NR_recv INVALID_SYSCALL
#endif

#ifndef __NR_timerfd
#define __NR_timerfd INVALID_SYSCALL
#endif

#ifndef __NR_sync_file_range2
#define __NR_sync_file_range2 INVALID_SYSCALL
#endif

#ifndef __NR_cachectl
#define __NR_cachectl INVALID_SYSCALL
#endif

#ifndef __NR_arm_fadvise64_64
#define __NR_arm_fadvise64_64 INVALID_SYSCALL
#endif

#ifndef __NR_shmget
#define __NR_shmget INVALID_SYSCALL
#endif

#ifndef __NR_getrandom
#define __NR_getrandom INVALID_SYSCALL
#endif

#ifndef __NR__llseek
#define __NR__llseek INVALID_SYSCALL
#endif

#ifndef __NR__newselect
#define __NR__newselect INVALID_SYSCALL
#endif

#ifndef __NR_bdflush
#define __NR_bdflush INVALID_SYSCALL
#endif

#ifndef __NR_break
#define __NR_break INVALID_SYSCALL
#endif

#ifndef __NR_chown32
#define __NR_chown32 INVALID_SYSCALL
#endif

#ifndef __NR_fadvise64_64
#define __NR_fadvise64_64 INVALID_SYSCALL
#endif

#ifndef __NR_fchown32
#define __NR_fchown32 INVALID_SYSCALL
#endif

#ifndef __NR_fcntl64
#define __NR_fcntl64 INVALID_SYSCALL
#endif

#ifndef __NR_fstat64
#define __NR_fstat64 INVALID_SYSCALL
#endif

#ifndef __NR_fstatat64
#define __NR_fstatat64 INVALID_SYSCALL
#endif

#ifndef __NR_fstatfs64
#define __NR_fstatfs64 INVALID_SYSCALL
#endif

#ifndef __NR_ftime
#define __NR_ftime INVALID_SYSCALL
#endif

#ifndef __NR_ftruncate64
#define __NR_ftruncate64 INVALID_SYSCALL
#endif

#ifndef __NR_getegid32
#define __NR_getegid32 INVALID_SYSCALL
#endif

#ifndef __NR_geteuid32
#define __NR_geteuid32 INVALID_SYSCALL
#endif

#ifndef __NR_getgid32
#define __NR_getgid32 INVALID_SYSCALL
#endif

#ifndef __NR_getgroups32
#define __NR_getgroups32 INVALID_SYSCALL
#endif

#ifndef __NR_getresgid32
#define __NR_getresgid32 INVALID_SYSCALL
#endif

#ifndef __NR_getresuid32
#define __NR_getresuid32 INVALID_SYSCALL
#endif

#ifndef __NR_getuid32
#define __NR_getuid32 INVALID_SYSCALL
#endif

#ifndef __NR_gtty
#define __NR_gtty INVALID_SYSCALL
#endif

#ifndef __NR_idle
#define __NR_idle INVALID_SYSCALL
#endif

#ifndef __NR_ipc
#define __NR_ipc INVALID_SYSCALL
#endif

#ifndef __NR_lchown32
#define __NR_lchown32 INVALID_SYSCALL
#endif

#ifndef __NR_lock
#define __NR_lock INVALID_SYSCALL
#endif

#ifndef __NR_lstat64
#define __NR_lstat64 INVALID_SYSCALL
#endif

#ifndef __NR_mmap2
#define __NR_mmap2 INVALID_SYSCALL
#endif

#ifndef __NR_mpx
#define __NR_mpx INVALID_SYSCALL
#endif

#ifndef __NR_nice
#define __NR_nice INVALID_SYSCALL
#endif

#ifndef __NR_oldfstat
#define __NR_oldfstat INVALID_SYSCALL
#endif

#ifndef __NR_oldlstat
#define __NR_oldlstat INVALID_SYSCALL
#endif

#ifndef __NR_oldolduname
#define __NR_oldolduname INVALID_SYSCALL
#endif

#ifndef __NR_oldstat
#define __NR_oldstat INVALID_SYSCALL
#endif

#ifndef __NR_olduname
#define __NR_olduname INVALID_SYSCALL
#endif

#ifndef __NR_prof
#define __NR_prof INVALID_SYSCALL
#endif

#ifndef __NR_profil
#define __NR_profil INVALID_SYSCALL
#endif

#ifndef __NR_readdir
#define __NR_readdir INVALID_SYSCALL
#endif

#ifndef __NR_renameat2
#define __NR_renameat2 INVALID_SYSCALL
#endif

#ifndef __NR_sched_getattr
#define __NR_sched_getattr INVALID_SYSCALL
#endif

#ifndef __NR_sched_setattr
#define __NR_sched_setattr INVALID_SYSCALL
#endif

#ifndef __NR_seccomp
#define __NR_seccomp INVALID_SYSCALL
#endif

#ifndef __NR_sendfile64
#define __NR_sendfile64 INVALID_SYSCALL
#endif

#ifndef __NR_setfsgid32
#define __NR_setfsgid32 INVALID_SYSCALL
#endif

#ifndef __NR_setfsuid32
#define __NR_setfsuid32 INVALID_SYSCALL
#endif

#ifndef __NR_setgid32
#define __NR_setgid32 INVALID_SYSCALL
#endif

#ifndef __NR_setgroups32
#define __NR_setgroups32 INVALID_SYSCALL
#endif

#ifndef __NR_setregid32
#define __NR_setregid32 INVALID_SYSCALL
#endif

#ifndef __NR_setresgid32
#define __NR_setresgid32 INVALID_SYSCALL
#endif

#ifndef __NR_setresuid32
#define __NR_setresuid32 INVALID_SYSCALL
#endif

#ifndef __NR_setreuid32
#define __NR_setreuid32 INVALID_SYSCALL
#endif

#ifndef __NR_setuid32
#define __NR_setuid32 INVALID_SYSCALL
#endif

#ifndef __NR_sgetmask
#define __NR_sgetmask INVALID_SYSCALL
#endif

#ifndef __NR_sigaction
#define __NR_sigaction INVALID_SYSCALL
#endif

#ifndef __NR_signal
#define __NR_signal INVALID_SYSCALL
#endif

#ifndef __NR_sigpending
#define __NR_sigpending INVALID_SYSCALL
#endif

#ifndef __NR_sigprocmask
#define __NR_sigprocmask INVALID_SYSCALL
#endif

#ifndef __NR_sigreturn
#define __NR_sigreturn INVALID_SYSCALL
#endif

#ifndef __NR_sigsuspend
#define __NR_sigsuspend INVALID_SYSCALL
#endif

#ifndef __NR_socketcall
#define __NR_socketcall INVALID_SYSCALL
#endif

#ifndef __NR_ssetmask
#define __NR_ssetmask INVALID_SYSCALL
#endif

#ifndef __NR_stat64
#define __NR_stat64 INVALID_SYSCALL
#endif

#ifndef __NR_statfs64
#define __NR_statfs64 INVALID_SYSCALL
#endif

#ifndef __NR_stime
#define __NR_stime INVALID_SYSCALL
#endif

#ifndef __NR_stty
#define __NR_stty INVALID_SYSCALL
#endif

#ifndef __NR_truncate64
#define __NR_truncate64 INVALID_SYSCALL
#endif

#ifndef __NR_ugetrlimit
#define __NR_ugetrlimit INVALID_SYSCALL
#endif

#ifndef __NR_ulimit
#define __NR_ulimit INVALID_SYSCALL
#endif

#ifndef __NR_umount
#define __NR_umount INVALID_SYSCALL
#endif

#ifndef __NR_vm86
#define __NR_vm86 INVALID_SYSCALL
#endif

#ifndef __NR_vm86old
#define __NR_vm86old INVALID_SYSCALL
#endif

#ifndef __NR_waitpid
#define __NR_waitpid INVALID_SYSCALL
#endif

#ifndef __NR_accept
#define __NR_accept INVALID_SYSCALL
#endif

#ifndef __NR_accept4
#define __NR_accept4 INVALID_SYSCALL
#endif

#ifndef __NR_arch_prctl
#define __NR_arch_prctl INVALID_SYSCALL
#endif

#ifndef __NR_bind
#define __NR_bind INVALID_SYSCALL
#endif

#ifndef __NR_connect
#define __NR_connect INVALID_SYSCALL
#endif

#ifndef __NR_epoll_ctl_old
#define __NR_epoll_ctl_old INVALID_SYSCALL
#endif

#ifndef __NR_epoll_wait_old
#define __NR_epoll_wait_old INVALID_SYSCALL
#endif

#ifndef __NR_getpeername
#define __NR_getpeername INVALID_SYSCALL
#endif

#ifndef __NR_getsockname
#define __NR_getsockname INVALID_SYSCALL
#endif

#ifndef __NR_getsockopt
#define __NR_getsockopt INVALID_SYSCALL
#endif

#ifndef __NR_listen
#define __NR_listen INVALID_SYSCALL
#endif

#ifndef __NR_msgctl
#define __NR_msgctl INVALID_SYSCALL
#endif

#ifndef __NR_msgget
#define __NR_msgget INVALID_SYSCALL
#endif

#ifndef __NR_msgrcv
#define __NR_msgrcv INVALID_SYSCALL
#endif

#ifndef __NR_msgsnd
#define __NR_msgsnd INVALID_SYSCALL
#endif

#ifndef __NR_newfstatat
#define __NR_newfstatat INVALID_SYSCALL
#endif

#ifndef __NR_recvfrom
#define __NR_recvfrom INVALID_SYSCALL
#endif

#ifndef __NR_recvmsg
#define __NR_recvmsg INVALID_SYSCALL
#endif

#ifndef __NR_security
#define __NR_security INVALID_SYSCALL
#endif

#ifndef __NR_semctl
#define __NR_semctl INVALID_SYSCALL
#endif

#ifndef __NR_semget
#define __NR_semget INVALID_SYSCALL
#endif

#ifndef __NR_semop
#define __NR_semop INVALID_SYSCALL
#endif

#ifndef __NR_semtimedop
#define __NR_semtimedop INVALID_SYSCALL
#endif

#ifndef __NR_sendmsg
#define __NR_sendmsg INVALID_SYSCALL
#endif

#ifndef __NR_sendto
#define __NR_sendto INVALID_SYSCALL
#endif

#ifndef __NR_setsockopt
#define __NR_setsockopt INVALID_SYSCALL
#endif

#ifndef __NR_shmat
#define __NR_shmat INVALID_SYSCALL
#endif

#ifndef __NR_shmctl
#define __NR_shmctl INVALID_SYSCALL
#endif

#ifndef __NR_shmdt
#define __NR_shmdt INVALID_SYSCALL
#endif

#ifndef __NR_shmget
#define __NR_shmget INVALID_SYSCALL
#endif

#ifndef __NR_shutdown
#define __NR_shutdown INVALID_SYSCALL
#endif

#ifndef __NR_socket
#define __NR_socket INVALID_SYSCALL
#endif

#ifndef __NR_socketpair
#define __NR_socketpair INVALID_SYSCALL
#endif

#ifndef __NR_tuxcall
#define __NR_tuxcall INVALID_SYSCALL
#endif

struct scmp_map {
    int syscall;
    int action;
};

static int scmp_filter(struct scmp_map **syscall_filter, int num)
{
        struct sock_filter *sec_filter = malloc(sizeof(struct sock_filter) * (num * 2 + 3));
    if (sec_filter) {
                struct sock_filter scmp_head[] = {
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
            };
            memcpy(sec_filter, scmp_head, sizeof(scmp_head));

            int i = 0;
                int fil_index = 0;
            for ( ; i < num; i++)
            {
                    if (INVALID_SYSCALL == (*syscall_filter)[i].syscall) {
                                continue;
                        }

                struct sock_filter node[] = {
                    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (*syscall_filter)[i].syscall, 0, 1),
                    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
                };
                memcpy(&sec_filter[1 + fil_index * 2], node, sizeof(node));
                        fil_index++;
            }
            struct sock_filter scmp_end[] = {
                BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
                BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
            };
            memcpy(&sec_filter[1 + fil_index * 2], scmp_end, sizeof(scmp_end));

            struct sock_fprog prog = {
                .len = (unsigned short)(fil_index * 2 + 3),
                .filter = sec_filter,
            };

            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                        || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
                    perror("prctl error");
                        free(sec_filter);
                    return 1;
                }
            free(sec_filter);
    }
    return 0;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

type Action struct {
	syscall int
	action  int
	args    string
}

type ScmpCtx struct {
	CallMap map[string]Action
}

var SyscallMap = map[string]int{
	"_llseek":                C.__NR__llseek,
	"_newselect":             C.__NR__newselect,
	"_sysctl":                C.__NR__sysctl,
	"accept":                 C.__NR_accept,
	"accept4":                C.__NR_accept4,
	"access":                 C.__NR_access,
	"acct":                   C.__NR_acct,
	"add_key":                C.__NR_add_key,
	"adjtimex":               C.__NR_adjtimex,
	"afs_syscall":            C.__NR_afs_syscall,
	"alarm":                  C.__NR_alarm,
	"arch_prctl":             C.__NR_arch_prctl,
	"bdflush":                C.__NR_bdflush,
	"bind":                   C.__NR_bind,
	"break":                  C.__NR_break,
	"brk":                    C.__NR_brk,
	"capget":                 C.__NR_capget,
	"capset":                 C.__NR_capset,
	"chdir":                  C.__NR_chdir,
	"chmod":                  C.__NR_chmod,
	"chown":                  C.__NR_chown,
	"chown32":                C.__NR_chown32,
	"chroot":                 C.__NR_chroot,
	"clock_adjtime":          C.__NR_clock_adjtime,
	"clock_getres":           C.__NR_clock_getres,
	"clock_gettime":          C.__NR_clock_gettime,
	"clock_nanosleep":        C.__NR_clock_nanosleep,
	"clock_settime":          C.__NR_clock_settime,
	"clone":                  C.__NR_clone,
	"close":                  C.__NR_close,
	"connect":                C.__NR_connect,
	"creat":                  C.__NR_creat,
	"create_module":          C.__NR_create_module,
	"delete_module":          C.__NR_delete_module,
	"dup":                    C.__NR_dup,
	"dup2":                   C.__NR_dup2,
	"dup3":                   C.__NR_dup3,
	"epoll_create":           C.__NR_epoll_create,
	"epoll_create1":          C.__NR_epoll_create1,
	"epoll_ctl":              C.__NR_epoll_ctl,
	"epoll_ctl_old":          C.__NR_epoll_ctl_old,
	"epoll_pwait":            C.__NR_epoll_pwait,
	"epoll_wait":             C.__NR_epoll_wait,
	"epoll_wait_old":         C.__NR_epoll_wait_old,
	"eventfd":                C.__NR_eventfd,
	"eventfd2":               C.__NR_eventfd2,
	"execve":                 C.__NR_execve,
	"exit":                   C.__NR_exit,
	"exit_group":             C.__NR_exit_group,
	"faccessat":              C.__NR_faccessat,
	"fadvise64":              C.__NR_fadvise64,
	"fadvise64_64":           C.__NR_fadvise64_64,
	"fallocate":              C.__NR_fallocate,
	"fanotify_init":          C.__NR_fanotify_init,
	"fanotify_mark":          C.__NR_fanotify_mark,
	"fchdir":                 C.__NR_fchdir,
	"fchmod":                 C.__NR_fchmod,
	"fchmodat":               C.__NR_fchmodat,
	"fchown":                 C.__NR_fchown,
	"fchown32":               C.__NR_fchown32,
	"fchownat":               C.__NR_fchownat,
	"fcntl":                  C.__NR_fcntl,
	"fcntl64":                C.__NR_fcntl64,
	"fdatasync":              C.__NR_fdatasync,
	"fgetxattr":              C.__NR_fgetxattr,
	"finit_module":           C.__NR_finit_module,
	"flistxattr":             C.__NR_flistxattr,
	"flock":                  C.__NR_flock,
	"fork":                   C.__NR_fork,
	"fremovexattr":           C.__NR_fremovexattr,
	"fsetxattr":              C.__NR_fsetxattr,
	"fstat":                  C.__NR_fstat,
	"fstat64":                C.__NR_fstat64,
	"fstatat64":              C.__NR_fstatat64,
	"fstatfs":                C.__NR_fstatfs,
	"fstatfs64":              C.__NR_fstatfs64,
	"fsync":                  C.__NR_fsync,
	"ftime":                  C.__NR_ftime,
	"ftruncate":              C.__NR_ftruncate,
	"ftruncate64":            C.__NR_ftruncate64,
	"futex":                  C.__NR_futex,
	"futimesat":              C.__NR_futimesat,
	"get_kernel_syms":        C.__NR_get_kernel_syms,
	"get_mempolicy":          C.__NR_get_mempolicy,
	"get_robust_list":        C.__NR_get_robust_list,
	"get_thread_area":        C.__NR_get_thread_area,
	"getcpu":                 C.__NR_getcpu,
	"getcwd":                 C.__NR_getcwd,
	"getdents":               C.__NR_getdents,
	"getdents64":             C.__NR_getdents64,
	"getegid":                C.__NR_getegid,
	"getegid32":              C.__NR_getegid32,
	"geteuid":                C.__NR_geteuid,
	"geteuid32":              C.__NR_geteuid32,
	"getgid":                 C.__NR_getgid,
	"getgid32":               C.__NR_getgid32,
	"getgroups":              C.__NR_getgroups,
	"getgroups32":            C.__NR_getgroups32,
	"getitimer":              C.__NR_getitimer,
	"getpeername":            C.__NR_getpeername,
	"getpgid":                C.__NR_getpgid,
	"getpgrp":                C.__NR_getpgrp,
	"getpid":                 C.__NR_getpid,
	"getpmsg":                C.__NR_getpmsg,
	"getppid":                C.__NR_getppid,
	"getpriority":            C.__NR_getpriority,
	"getresgid":              C.__NR_getresgid,
	"getresgid32":            C.__NR_getresgid32,
	"getresuid":              C.__NR_getresuid,
	"getresuid32":            C.__NR_getresuid32,
	"getrlimit":              C.__NR_getrlimit,
	"getrusage":              C.__NR_getrusage,
	"getsid":                 C.__NR_getsid,
	"getsockname":            C.__NR_getsockname,
	"getsockopt":             C.__NR_getsockopt,
	"gettid":                 C.__NR_gettid,
	"gettimeofday":           C.__NR_gettimeofday,
	"getuid":                 C.__NR_getuid,
	"getuid32":               C.__NR_getuid32,
	"getxattr":               C.__NR_getxattr,
	"gtty":                   C.__NR_gtty,
	"idle":                   C.__NR_idle,
	"init_module":            C.__NR_init_module,
	"inotify_add_watch":      C.__NR_inotify_add_watch,
	"inotify_init":           C.__NR_inotify_init,
	"inotify_init1":          C.__NR_inotify_init1,
	"inotify_rm_watch":       C.__NR_inotify_rm_watch,
	"io_cancel":              C.__NR_io_cancel,
	"io_destroy":             C.__NR_io_destroy,
	"io_getevents":           C.__NR_io_getevents,
	"io_setup":               C.__NR_io_setup,
	"io_submit":              C.__NR_io_submit,
	"ioctl":                  C.__NR_ioctl,
	"ioperm":                 C.__NR_ioperm,
	"iopl":                   C.__NR_iopl,
	"ioprio_get":             C.__NR_ioprio_get,
	"ioprio_set":             C.__NR_ioprio_set,
	"ipc":                    C.__NR_ipc,
	"kcmp":                   C.__NR_kcmp,
	"kexec_load":             C.__NR_kexec_load,
	"keyctl":                 C.__NR_keyctl,
	"kill":                   C.__NR_kill,
	"lchown":                 C.__NR_lchown,
	"lchown32":               C.__NR_lchown32,
	"lgetxattr":              C.__NR_lgetxattr,
	"link":                   C.__NR_link,
	"linkat":                 C.__NR_linkat,
	"listen":                 C.__NR_listen,
	"listxattr":              C.__NR_listxattr,
	"llistxattr":             C.__NR_llistxattr,
	"lock":                   C.__NR_lock,
	"lookup_dcookie":         C.__NR_lookup_dcookie,
	"lremovexattr":           C.__NR_lremovexattr,
	"lseek":                  C.__NR_lseek,
	"lsetxattr":              C.__NR_lsetxattr,
	"lstat":                  C.__NR_lstat,
	"lstat64":                C.__NR_lstat64,
	"madvise":                C.__NR_madvise,
	"mbind":                  C.__NR_mbind,
	"migrate_pages":          C.__NR_migrate_pages,
	"mincore":                C.__NR_mincore,
	"mkdir":                  C.__NR_mkdir,
	"mkdirat":                C.__NR_mkdirat,
	"mknod":                  C.__NR_mknod,
	"mknodat":                C.__NR_mknodat,
	"mlock":                  C.__NR_mlock,
	"mlockall":               C.__NR_mlockall,
	"mmap":                   C.__NR_mmap,
	"mmap2":                  C.__NR_mmap2,
	"modify_ldt":             C.__NR_modify_ldt,
	"mount":                  C.__NR_mount,
	"move_pages":             C.__NR_move_pages,
	"mprotect":               C.__NR_mprotect,
	"mpx":                    C.__NR_mpx,
	"mq_getsetattr":          C.__NR_mq_getsetattr,
	"mq_notify":              C.__NR_mq_notify,
	"mq_open":                C.__NR_mq_open,
	"mq_timedreceive":        C.__NR_mq_timedreceive,
	"mq_timedsend":           C.__NR_mq_timedsend,
	"mq_unlink":              C.__NR_mq_unlink,
	"mremap":                 C.__NR_mremap,
	"msgctl":                 C.__NR_msgctl,
	"msgget":                 C.__NR_msgget,
	"msgrcv":                 C.__NR_msgrcv,
	"msgsnd":                 C.__NR_msgsnd,
	"msync":                  C.__NR_msync,
	"munlock":                C.__NR_munlock,
	"munlockall":             C.__NR_munlockall,
	"munmap":                 C.__NR_munmap,
	"name_to_handle_at":      C.__NR_name_to_handle_at,
	"nanosleep":              C.__NR_nanosleep,
	"newfstatat":             C.__NR_newfstatat,
	"nfsservctl":             C.__NR_nfsservctl,
	"nice":                   C.__NR_nice,
	"oldfstat":               C.__NR_oldfstat,
	"oldlstat":               C.__NR_oldlstat,
	"oldolduname":            C.__NR_oldolduname,
	"oldstat":                C.__NR_oldstat,
	"olduname":               C.__NR_olduname,
	"open":                   C.__NR_open,
	"open_by_handle_at":      C.__NR_open_by_handle_at,
	"openat":                 C.__NR_openat,
	"pause":                  C.__NR_pause,
	"perf_event_open":        C.__NR_perf_event_open,
	"personality":            C.__NR_personality,
	"pipe":                   C.__NR_pipe,
	"pipe2":                  C.__NR_pipe2,
	"pivot_root":             C.__NR_pivot_root,
	"poll":                   C.__NR_poll,
	"ppoll":                  C.__NR_ppoll,
	"prctl":                  C.__NR_prctl,
	"pread64":                C.__NR_pread64,
	"preadv":                 C.__NR_preadv,
	"prlimit64":              C.__NR_prlimit64,
	"process_vm_readv":       C.__NR_process_vm_readv,
	"process_vm_writev":      C.__NR_process_vm_writev,
	"prof":                   C.__NR_prof,
	"profil":                 C.__NR_profil,
	"pselect6":               C.__NR_pselect6,
	"ptrace":                 C.__NR_ptrace,
	"putpmsg":                C.__NR_putpmsg,
	"pwrite64":               C.__NR_pwrite64,
	"pwritev":                C.__NR_pwritev,
	"query_module":           C.__NR_query_module,
	"quotactl":               C.__NR_quotactl,
	"read":                   C.__NR_read,
	"readahead":              C.__NR_readahead,
	"readdir":                C.__NR_readdir,
	"readlink":               C.__NR_readlink,
	"readlinkat":             C.__NR_readlinkat,
	"readv":                  C.__NR_readv,
	"reboot":                 C.__NR_reboot,
	"recvfrom":               C.__NR_recvfrom,
	"recvmmsg":               C.__NR_recvmmsg,
	"recvmsg":                C.__NR_recvmsg,
	"remap_file_pages":       C.__NR_remap_file_pages,
	"removexattr":            C.__NR_removexattr,
	"rename":                 C.__NR_rename,
	"renameat":               C.__NR_renameat,
	"renameat2":              C.__NR_renameat2,
	"request_key":            C.__NR_request_key,
	"restart_syscall":        C.__NR_restart_syscall,
	"rmdir":                  C.__NR_rmdir,
	"rt_sigaction":           C.__NR_rt_sigaction,
	"rt_sigpending":          C.__NR_rt_sigpending,
	"rt_sigprocmask":         C.__NR_rt_sigprocmask,
	"rt_sigqueueinfo":        C.__NR_rt_sigqueueinfo,
	"rt_sigreturn":           C.__NR_rt_sigreturn,
	"rt_sigsuspend":          C.__NR_rt_sigsuspend,
	"rt_sigtimedwait":        C.__NR_rt_sigtimedwait,
	"rt_tgsigqueueinfo":      C.__NR_rt_tgsigqueueinfo,
	"sched_get_priority_max": C.__NR_sched_get_priority_max,
	"sched_get_priority_min": C.__NR_sched_get_priority_min,
	"sched_getaffinity":      C.__NR_sched_getaffinity,
	"sched_getattr":          C.__NR_sched_getattr,
	"sched_getparam":         C.__NR_sched_getparam,
	"sched_getscheduler":     C.__NR_sched_getscheduler,
	"sched_rr_get_interval":  C.__NR_sched_rr_get_interval,
	"sched_setaffinity":      C.__NR_sched_setaffinity,
	"sched_setattr":          C.__NR_sched_setattr,
	"sched_setparam":         C.__NR_sched_setparam,
	"sched_setscheduler":     C.__NR_sched_setscheduler,
	"sched_yield":            C.__NR_sched_yield,
	"seccomp":                C.__NR_seccomp,
	"security":               C.__NR_security,
	"select":                 C.__NR_select,
	"semctl":                 C.__NR_semctl,
	"semget":                 C.__NR_semget,
	"semop":                  C.__NR_semop,
	"semtimedop":             C.__NR_semtimedop,
	"sendfile":               C.__NR_sendfile,
	"sendfile64":             C.__NR_sendfile64,
	"sendmmsg":               C.__NR_sendmmsg,
	"sendmsg":                C.__NR_sendmsg,
	"sendto":                 C.__NR_sendto,
	"set_mempolicy":          C.__NR_set_mempolicy,
	"set_robust_list":        C.__NR_set_robust_list,
	"set_thread_area":        C.__NR_set_thread_area,
	"set_tid_address":        C.__NR_set_tid_address,
	"setdomainname":          C.__NR_setdomainname,
	"setfsgid":               C.__NR_setfsgid,
	"setfsgid32":             C.__NR_setfsgid32,
	"setfsuid":               C.__NR_setfsuid,
	"setfsuid32":             C.__NR_setfsuid32,
	"setgid":                 C.__NR_setgid,
	"setgid32":               C.__NR_setgid32,
	"setgroups":              C.__NR_setgroups,
	"setgroups32":            C.__NR_setgroups32,
	"sethostname":            C.__NR_sethostname,
	"setitimer":              C.__NR_setitimer,
	"setns":                  C.__NR_setns,
	"setpgid":                C.__NR_setpgid,
	"setpriority":            C.__NR_setpriority,
	"setregid":               C.__NR_setregid,
	"setregid32":             C.__NR_setregid32,
	"setresgid":              C.__NR_setresgid,
	"setresgid32":            C.__NR_setresgid32,
	"setresuid":              C.__NR_setresuid,
	"setresuid32":            C.__NR_setresuid32,
	"setreuid":               C.__NR_setreuid,
	"setreuid32":             C.__NR_setreuid32,
	"setrlimit":              C.__NR_setrlimit,
	"setsid":                 C.__NR_setsid,
	"setsockopt":             C.__NR_setsockopt,
	"settimeofday":           C.__NR_settimeofday,
	"setuid":                 C.__NR_setuid,
	"setuid32":               C.__NR_setuid32,
	"setxattr":               C.__NR_setxattr,
	"sgetmask":               C.__NR_sgetmask,
	"shmat":                  C.__NR_shmat,
	"shmctl":                 C.__NR_shmctl,
	"shmdt":                  C.__NR_shmdt,
	"shmget":                 C.__NR_shmget,
	"shutdown":               C.__NR_shutdown,
	"sigaction":              C.__NR_sigaction,
	"sigaltstack":            C.__NR_sigaltstack,
	"signal":                 C.__NR_signal,
	"signalfd":               C.__NR_signalfd,
	"signalfd4":              C.__NR_signalfd4,
	"sigpending":             C.__NR_sigpending,
	"sigprocmask":            C.__NR_sigprocmask,
	"sigreturn":              C.__NR_sigreturn,
	"sigsuspend":             C.__NR_sigsuspend,
	"socket":                 C.__NR_socket,
	"socketcall":             C.__NR_socketcall,
	"socketpair":             C.__NR_socketpair,
	"splice":                 C.__NR_splice,
	"ssetmask":               C.__NR_ssetmask,
	"stat":                   C.__NR_stat,
	"stat64":                 C.__NR_stat64,
	"statfs":                 C.__NR_statfs,
	"statfs64":               C.__NR_statfs64,
	"stime":                  C.__NR_stime,
	"stty":                   C.__NR_stty,
	"swapoff":                C.__NR_swapoff,
	"swapon":                 C.__NR_swapon,
	"symlink":                C.__NR_symlink,
	"symlinkat":              C.__NR_symlinkat,
	"sync":                   C.__NR_sync,
	"sync_file_range":        C.__NR_sync_file_range,
	"syncfs":                 C.__NR_syncfs,
	"sysfs":                  C.__NR_sysfs,
	"sysinfo":                C.__NR_sysinfo,
	"syslog":                 C.__NR_syslog,
	"tee":                    C.__NR_tee,
	"tgkill":                 C.__NR_tgkill,
	"time":                   C.__NR_time,
	"timer_create":           C.__NR_timer_create,
	"timer_delete":           C.__NR_timer_delete,
	"timer_getoverrun":       C.__NR_timer_getoverrun,
	"timer_gettime":          C.__NR_timer_gettime,
	"timer_settime":          C.__NR_timer_settime,
	"timerfd_create":         C.__NR_timerfd_create,
	"timerfd_gettime":        C.__NR_timerfd_gettime,
	"timerfd_settime":        C.__NR_timerfd_settime,
	"times":                  C.__NR_times,
	"tkill":                  C.__NR_tkill,
	"truncate":               C.__NR_truncate,
	"truncate64":             C.__NR_truncate64,
	"tuxcall":                C.__NR_tuxcall,
	"ugetrlimit":             C.__NR_ugetrlimit,
	"ulimit":                 C.__NR_ulimit,
	"umask":                  C.__NR_umask,
	"umount":                 C.__NR_umount,
	"umount2":                C.__NR_umount2,
	"uname":                  C.__NR_uname,
	"unlink":                 C.__NR_unlink,
	"unlinkat":               C.__NR_unlinkat,
	"unshare":                C.__NR_unshare,
	"uselib":                 C.__NR_uselib,
	"ustat":                  C.__NR_ustat,
	"utime":                  C.__NR_utime,
	"utimensat":              C.__NR_utimensat,
	"utimes":                 C.__NR_utimes,
	"vfork":                  C.__NR_vfork,
	"vhangup":                C.__NR_vhangup,
	"vm86":                   C.__NR_vm86,
	"vm86old":                C.__NR_vm86old,
	"vmsplice":               C.__NR_vmsplice,
	"vserver":                C.__NR_vserver,
	"wait4":                  C.__NR_wait4,
	"waitid":                 C.__NR_waitid,
	"waitpid":                C.__NR_waitpid,
	"write":                  C.__NR_write,
	"writev":                 C.__NR_writev,
}

var SyscallMapMin = map[string]int{
	"write":        C.__NR_write,
	"rt_sigreturn": C.__NR_rt_sigreturn,
	"exit_group":   C.__NR_exit_group,
	"futex":        C.__NR_futex,
}

var scmpActAllow = 0

func ScmpInit(action int) (*ScmpCtx, error) {
	ctx := ScmpCtx{CallMap: make(map[string]Action)}
	return &ctx, nil
}

func ScmpAdd(ctx *ScmpCtx, call string, action int) error {
	_, exists := ctx.CallMap[call]
	if exists {
		return errors.New("syscall exist")
	}
	sysCall, sysExists := SyscallMap[call]
	if sysExists {
		ctx.CallMap[call] = Action{sysCall, action, ""}
	}

	return errors.New("syscall not surport")
}

func ScmpDel(ctx *ScmpCtx, call string) error {
	_, exists := ctx.CallMap[call]
	if exists {
		delete(ctx.CallMap, call)
		return nil
	}

	return errors.New("syscall not exist")
}

func ScmpLoad(ctx *ScmpCtx) error {
	for key := range SyscallMapMin {
		ScmpAdd(ctx, key, scmpActAllow)
	}

	num := len(ctx.CallMap)
	filter := make([]C.struct_scmp_map, num)

	index := 0
	for _, value := range ctx.CallMap {
		filter[index].syscall = C.int(value.syscall)
		filter[index].action = C.int(value.action)
		index++
	}

	res := C.scmp_filter((**C.struct_scmp_map)(unsafe.Pointer(&filter)), C.int(num))
	if 0 != res {
		return errors.New("SeccompLoad error")
	}
	return nil
}

func finalizeSeccomp(config *initConfig) error {
	scmpCtx, _ := ScmpInit(scmpActAllow)
	for _, call := range config.Config.SysCalls {
		ScmpAdd(scmpCtx, call, scmpActAllow)
	}
	if len(config.Config.SysCalls) == len(scmpCtx.CallMap) {
		return nil
	}
	return ScmpLoad(scmpCtx)
}
