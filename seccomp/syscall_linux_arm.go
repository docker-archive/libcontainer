// +build linux
// +build arm

package seccomp

import (
    "syscall"
)

const (
	SECCOMP_RET_KILL       = 0x00000000
	SECCOMP_RET_TRAP       = 0x00030000
	SECCOMP_RET_ALLOW      = 0x7fff0000
	SECCOMP_MODE_FILTER    = 0x2
	PR_SET_NO_NEW_PRIVS    = 0x26
)

var SyscallMap = map[string] uint32 {
    "OABI_SYSCALL_BASE":        syscall.SYS_OABI_SYSCALL_BASE,
    "SYSCALL_BASE":             syscall.SYS_SYSCALL_BASE,
    "RESTART_SYSCALL":          syscall.SYS_RESTART_SYSCALL,
    "EXIT":                     syscall.SYS_EXIT,
    "FORK":                     syscall.SYS_FORK,
    "READ":                     syscall.SYS_READ,
    "WRITE":                    syscall.SYS_WRITE,
    "OPEN":                     syscall.SYS_OPEN,
    "CLOSE":                    syscall.SYS_CLOSE,
    "CREAT":                    syscall.SYS_CREAT,
    "LINK":                     syscall.SYS_LINK,
    "UNLINK":                   syscall.SYS_UNLINK,
    "EXECVE":                   syscall.SYS_EXECVE,
    "CHDIR":                    syscall.SYS_CHDIR,
    "TIME":                     syscall.SYS_TIME,
    "MKNOD":                    syscall.SYS_MKNOD,
    "CHMOD":                    syscall.SYS_CHMOD,
    "LCHOWN":                   syscall.SYS_LCHOWN,
    "LSEEK":                    syscall.SYS_LSEEK,
    "GETPID":                   syscall.SYS_GETPID,
    "MOUNT":                    syscall.SYS_MOUNT,
    "UMOUNT":                   syscall.SYS_UMOUNT,
    "SETUID":                   syscall.SYS_SETUID,
    "GETUID":                   syscall.SYS_GETUID,
    "STIME":                    syscall.SYS_STIME,
    "PTRACE":                   syscall.SYS_PTRACE,
    "ALARM":                    syscall.SYS_ALARM,
    "PAUSE":                    syscall.SYS_PAUSE,
    "UTIME":                    syscall.SYS_UTIME,
    "ACCESS":                   syscall.SYS_ACCESS,
    "NICE":                     syscall.SYS_NICE,
    "SYNC":                     syscall.SYS_SYNC,
    "KILL":                     syscall.SYS_KILL,
    "RENAME":                   syscall.SYS_RENAME,
    "MKDIR":                    syscall.SYS_MKDIR,
    "RMDIR":                    syscall.SYS_RMDIR,
    "DUP":                      syscall.SYS_DUP,
    "PIPE":                     syscall.SYS_PIPE,
    "TIMES":                    syscall.SYS_TIMES,
    "BRK":                      syscall.SYS_BRK,
    "SETGID":                   syscall.SYS_SETGID,
    "GETGID":                   syscall.SYS_GETGID,
    "GETEUID":                  syscall.SYS_GETEUID,
    "GETEGID":                  syscall.SYS_GETEGID,
    "ACCT":                     syscall.SYS_ACCT,
    "UMOUNT2":                  syscall.SYS_UMOUNT2,
    "IOCTL":                    syscall.SYS_IOCTL,
    "FCNTL":                    syscall.SYS_FCNTL,
    "SETPGID":                  syscall.SYS_SETPGID,
    "UMASK":                    syscall.SYS_UMASK,
    "CHROOT":                   syscall.SYS_CHROOT,
    "USTAT":                    syscall.SYS_USTAT,
    "DUP2":                     syscall.SYS_DUP2,
    "GETPPID":                  syscall.SYS_GETPPID,
    "GETPGRP":                  syscall.SYS_GETPGRP,
    "SETSID":                   syscall.SYS_SETSID,
    "SIGACTION":                syscall.SYS_SIGACTION,
    "SETREUID":                 syscall.SYS_SETREUID,
    "SETREGID":                 syscall.SYS_SETREGID,
    "SIGSUSPEND":               syscall.SYS_SIGSUSPEND,
    "SIGPENDING":               syscall.SYS_SIGPENDING,
    "SETHOSTNAME":              syscall.SYS_SETHOSTNAME,
    "SETRLIMIT":                syscall.SYS_SETRLIMIT,
    "GETRLIMIT":                syscall.SYS_GETRLIMIT,
    "GETRUSAGE":                syscall.SYS_GETRUSAGE,
    "GETTIMEOFDAY":             syscall.SYS_GETTIMEOFDAY,
    "SETTIMEOFDAY":             syscall.SYS_SETTIMEOFDAY,
    "GETGROUPS":                syscall.SYS_GETGROUPS,
    "SETGROUPS":                syscall.SYS_SETGROUPS,
    "SELECT":                   syscall.SYS_SELECT,
    "SYMLINK":                  syscall.SYS_SYMLINK,
    "READLINK":                 syscall.SYS_READLINK,
    "USELIB":                   syscall.SYS_USELIB,
    "SWAPON":                   syscall.SYS_SWAPON,
    "REBOOT":                   syscall.SYS_REBOOT,
    "READDIR":                  syscall.SYS_READDIR,
    "MMAP":                     syscall.SYS_MMAP,
    "MUNMAP":                   syscall.SYS_MUNMAP,
    "TRUNCATE":                 syscall.SYS_TRUNCATE,
    "FTRUNCATE":                syscall.SYS_FTRUNCATE,
    "FCHMOD":                   syscall.SYS_FCHMOD,
    "FCHOWN":                   syscall.SYS_FCHOWN,
    "GETPRIORITY":              syscall.SYS_GETPRIORITY,
    "SETPRIORITY":              syscall.SYS_SETPRIORITY,
    "STATFS":                   syscall.SYS_STATFS,
    "FSTATFS":                  syscall.SYS_FSTATFS,
    "SOCKETCALL":               syscall.SYS_SOCKETCALL,
    "SYSLOG":                   syscall.SYS_SYSLOG,
    "SETITIMER":                syscall.SYS_SETITIMER,
    "GETITIMER":                syscall.SYS_GETITIMER,
    "STAT":                     syscall.SYS_STAT,
    "LSTAT":                    syscall.SYS_LSTAT,
    "FSTAT":                    syscall.SYS_FSTAT,
    "VHANGUP":                  syscall.SYS_VHANGUP,
    "SYSCALL":                  syscall.SYS_SYSCALL,
    "WAIT4":                    syscall.SYS_WAIT4,
    "SWAPOFF":                  syscall.SYS_SWAPOFF,
    "SYSINFO":                  syscall.SYS_SYSINFO,
    "IPC":                      syscall.SYS_IPC,
    "FSYNC":                    syscall.SYS_FSYNC,
    "SIGRETURN":                syscall.SYS_SIGRETURN,
    "CLONE":                    syscall.SYS_CLONE,
    "SETDOMAINNAME":            syscall.SYS_SETDOMAINNAME,
    "UNAME":                    syscall.SYS_UNAME,
    "ADJTIMEX":                 syscall.SYS_ADJTIMEX,
    "MPROTECT":                 syscall.SYS_MPROTECT,
    "SIGPROCMASK":              syscall.SYS_SIGPROCMASK,
    "INIT_MODULE":              syscall.SYS_INIT_MODULE,
    "DELETE_MODULE":            syscall.SYS_DELETE_MODULE,
    "QUOTACTL":                 syscall.SYS_QUOTACTL,
    "GETPGID":                  syscall.SYS_GETPGID,
    "FCHDIR":                   syscall.SYS_FCHDIR,
    "BDFLUSH":                  syscall.SYS_BDFLUSH,
    "SYSFS":                    syscall.SYS_SYSFS,
    "PERSONALITY":              syscall.SYS_PERSONALITY,
    "SETFSUID":                 syscall.SYS_SETFSUID,
    "SETFSGID":                 syscall.SYS_SETFSGID,
    "_LLSEEK":                  syscall.SYS__LLSEEK,
    "GETDENTS":                 syscall.SYS_GETDENTS,
    "_NEWSELECT":               syscall.SYS__NEWSELECT,
    "FLOCK":                    syscall.SYS_FLOCK,
    "MSYNC":                    syscall.SYS_MSYNC,
    "READV":                    syscall.SYS_READV,
    "WRITEV":                   syscall.SYS_WRITEV,
    "GETSID":                   syscall.SYS_GETSID,
    "FDATASYNC":                syscall.SYS_FDATASYNC,
    "_SYSCTL":                  syscall.SYS__SYSCTL,
    "MLOCK":                    syscall.SYS_MLOCK,
    "MUNLOCK":                  syscall.SYS_MUNLOCK,
    "MLOCKALL":                 syscall.SYS_MLOCKALL,
    "MUNLOCKALL":               syscall.SYS_MUNLOCKALL,
    "SCHED_SETPARAM":           syscall.SYS_SCHED_SETPARAM,
    "SCHED_GETPARAM":           syscall.SYS_SCHED_GETPARAM,
    "SCHED_SETSCHEDULER":       syscall.SYS_SCHED_SETSCHEDULER,
    "SCHED_GETSCHEDULER":       syscall.SYS_SCHED_GETSCHEDULER,
    "SCHED_YIELD":              syscall.SYS_SCHED_YIELD,
    "SCHED_GET_PRIORITY_MAX":   syscall.SYS_SCHED_GET_PRIORITY_MAX,
    "SCHED_GET_PRIORITY_MIN":   syscall.SYS_SCHED_GET_PRIORITY_MIN,
    "SCHED_RR_GET_INTERVAL":    syscall.SYS_SCHED_RR_GET_INTERVAL,
    "NANOSLEEP":                syscall.SYS_NANOSLEEP,
    "MREMAP":                   syscall.SYS_MREMAP,
    "SETRESUID":                syscall.SYS_SETRESUID,
    "GETRESUID":                syscall.SYS_GETRESUID,
    "POLL":                     syscall.SYS_POLL,
    "NFSSERVCTL":               syscall.SYS_NFSSERVCTL,
    "SETRESGID":                syscall.SYS_SETRESGID,
    "GETRESGID":                syscall.SYS_GETRESGID,
    "PRCTL":                    syscall.SYS_PRCTL,
    "RT_SIGRETURN":             syscall.SYS_RT_SIGRETURN,
    "RT_SIGACTION":             syscall.SYS_RT_SIGACTION,
    "RT_SIGPROCMASK":           syscall.SYS_RT_SIGPROCMASK,
    "RT_SIGPENDING":            syscall.SYS_RT_SIGPENDING,
    "RT_SIGTIMEDWAIT":          syscall.SYS_RT_SIGTIMEDWAIT,
    "RT_SIGQUEUEINFO":          syscall.SYS_RT_SIGQUEUEINFO,
    "RT_SIGSUSPEND":            syscall.SYS_RT_SIGSUSPEND,
    "PREAD64":                  syscall.SYS_PREAD64,
    "PWRITE64":                 syscall.SYS_PWRITE64,
    "CHOWN":                    syscall.SYS_CHOWN,
    "GETCWD":                   syscall.SYS_GETCWD,
    "CAPGET":                   syscall.SYS_CAPGET,
    "CAPSET":                   syscall.SYS_CAPSET,
    "SIGALTSTACK":              syscall.SYS_SIGALTSTACK,
    "SENDFILE":                 syscall.SYS_SENDFILE,
    "VFORK":                    syscall.SYS_VFORK,
    "UGETRLIMIT":               syscall.SYS_UGETRLIMIT,
    "MMAP2":                    syscall.SYS_MMAP2,
    "TRUNCATE64":               syscall.SYS_TRUNCATE64,
    "FTRUNCATE64":              syscall.SYS_FTRUNCATE64,
    "STAT64":                   syscall.SYS_STAT64,
    "LSTAT64":                  syscall.SYS_LSTAT64,
    "FSTAT64":                  syscall.SYS_FSTAT64,
    "LCHOWN32":                 syscall.SYS_LCHOWN32,
    "GETUID32":                 syscall.SYS_GETUID32,
    "GETGID32":                 syscall.SYS_GETGID32,
    "GETEUID32":                syscall.SYS_GETEUID32,
    "GETEGID32":                syscall.SYS_GETEGID32,
    "SETREUID32":               syscall.SYS_SETREUID32,
    "SETREGID32":               syscall.SYS_SETREGID32,
    "GETGROUPS32":              syscall.SYS_GETGROUPS32,
    "SETGROUPS32":              syscall.SYS_SETGROUPS32,
    "FCHOWN32":                 syscall.SYS_FCHOWN32,
    "SETRESUID32":              syscall.SYS_SETRESUID32,
    "GETRESUID32":              syscall.SYS_GETRESUID32,
    "SETRESGID32":              syscall.SYS_SETRESGID32,
    "GETRESGID32":              syscall.SYS_GETRESGID32,
    "CHOWN32":                  syscall.SYS_CHOWN32,
    "SETUID32":                 syscall.SYS_SETUID32,
    "SETGID32":                 syscall.SYS_SETGID32,
    "SETFSUID32":               syscall.SYS_SETFSUID32,
    "SETFSGID32":               syscall.SYS_SETFSGID32,
    "GETDENTS64":               syscall.SYS_GETDENTS64,
    "PIVOT_ROOT":               syscall.SYS_PIVOT_ROOT,
    "MINCORE":                  syscall.SYS_MINCORE,
    "MADVISE":                  syscall.SYS_MADVISE,
    "FCNTL64":                  syscall.SYS_FCNTL64,
    "GETTID":                   syscall.SYS_GETTID,
    "READAHEAD":                syscall.SYS_READAHEAD,
    "SETXATTR":                 syscall.SYS_SETXATTR,
    "LSETXATTR":                syscall.SYS_LSETXATTR,
    "FSETXATTR":                syscall.SYS_FSETXATTR,
    "GETXATTR":                 syscall.SYS_GETXATTR,
    "LGETXATTR":                syscall.SYS_LGETXATTR,
    "FGETXATTR":                syscall.SYS_FGETXATTR,
    "LISTXATTR":                syscall.SYS_LISTXATTR,
    "LLISTXATTR":               syscall.SYS_LLISTXATTR,
    "FLISTXATTR":               syscall.SYS_FLISTXATTR,
    "REMOVEXATTR":              syscall.SYS_REMOVEXATTR,
    "LREMOVEXATTR":             syscall.SYS_LREMOVEXATTR,
    "FREMOVEXATTR":             syscall.SYS_FREMOVEXATTR,
    "TKILL":                    syscall.SYS_TKILL,
    "SENDFILE64":               syscall.SYS_SENDFILE64,
    "FUTEX":                    syscall.SYS_FUTEX,
    "SCHED_SETAFFINITY":        syscall.SYS_SCHED_SETAFFINITY,
    "SCHED_GETAFFINITY":        syscall.SYS_SCHED_GETAFFINITY,
    "IO_SETUP":                 syscall.SYS_IO_SETUP,
    "IO_DESTROY":               syscall.SYS_IO_DESTROY,
    "IO_GETEVENTS":             syscall.SYS_IO_GETEVENTS,
    "IO_SUBMIT":                syscall.SYS_IO_SUBMIT,
    "IO_CANCEL":                syscall.SYS_IO_CANCEL,
    "EXIT_GROUP":               syscall.SYS_EXIT_GROUP,
    "LOOKUP_DCOOKIE":           syscall.SYS_LOOKUP_DCOOKIE,
    "EPOLL_CREATE":             syscall.SYS_EPOLL_CREATE,
    "EPOLL_CTL":                syscall.SYS_EPOLL_CTL,
    "EPOLL_WAIT":               syscall.SYS_EPOLL_WAIT,
    "REMAP_FILE_PAGES":         syscall.SYS_REMAP_FILE_PAGES,
    "SET_TID_ADDRESS":          syscall.SYS_SET_TID_ADDRESS,
    "TIMER_CREATE":             syscall.SYS_TIMER_CREATE,
    "TIMER_SETTIME":            syscall.SYS_TIMER_SETTIME,
    "TIMER_GETTIME":            syscall.SYS_TIMER_GETTIME,
    "TIMER_GETOVERRUN":         syscall.SYS_TIMER_GETOVERRUN,
    "TIMER_DELETE":             syscall.SYS_TIMER_DELETE,
    "CLOCK_SETTIME":            syscall.SYS_CLOCK_SETTIME,
    "CLOCK_GETTIME":            syscall.SYS_CLOCK_GETTIME,
    "CLOCK_GETRES":             syscall.SYS_CLOCK_GETRES,
    "CLOCK_NANOSLEEP":          syscall.SYS_CLOCK_NANOSLEEP,
    "STATFS64":                 syscall.SYS_STATFS64,
    "FSTATFS64":                syscall.SYS_FSTATFS64,
    "TGKILL":                   syscall.SYS_TGKILL,
    "UTIMES":                   syscall.SYS_UTIMES,
    "ARM_FADVISE64_64":         syscall.SYS_ARM_FADVISE64_64,
    "PCICONFIG_IOBASE":         syscall.SYS_PCICONFIG_IOBASE,
    "PCICONFIG_READ":           syscall.SYS_PCICONFIG_READ,
    "PCICONFIG_WRITE":          syscall.SYS_PCICONFIG_WRITE,
    "MQ_OPEN":                  syscall.SYS_MQ_OPEN,
    "MQ_UNLINK":                syscall.SYS_MQ_UNLINK,
    "MQ_TIMEDSEND":             syscall.SYS_MQ_TIMEDSEND,
    "MQ_TIMEDRECEIVE":          syscall.SYS_MQ_TIMEDRECEIVE,
    "MQ_NOTIFY":                syscall.SYS_MQ_NOTIFY,
    "MQ_GETSETATTR":            syscall.SYS_MQ_GETSETATTR,
    "WAITID":                   syscall.SYS_WAITID,
    "SOCKET":                   syscall.SYS_SOCKET,
    "BIND":                     syscall.SYS_BIND,
    "CONNECT":                  syscall.SYS_CONNECT,
    "LISTEN":                   syscall.SYS_LISTEN,
    "ACCEPT":                   syscall.SYS_ACCEPT,
    "GETSOCKNAME":              syscall.SYS_GETSOCKNAME,
    "GETPEERNAME":              syscall.SYS_GETPEERNAME,
    "SOCKETPAIR":               syscall.SYS_SOCKETPAIR,
    "SEND":                     syscall.SYS_SEND,
    "SENDTO":                   syscall.SYS_SENDTO,
    "RECV":                     syscall.SYS_RECV,
    "RECVFROM":                 syscall.SYS_RECVFROM,
    "SHUTDOWN":                 syscall.SYS_SHUTDOWN,
    "SETSOCKOPT":               syscall.SYS_SETSOCKOPT,
    "GETSOCKOPT":               syscall.SYS_GETSOCKOPT,
    "SENDMSG":                  syscall.SYS_SENDMSG,
    "RECVMSG":                  syscall.SYS_RECVMSG,
    "SEMOP":                    syscall.SYS_SEMOP,
    "SEMGET":                   syscall.SYS_SEMGET,
    "SEMCTL":                   syscall.SYS_SEMCTL,
    "MSGSND":                   syscall.SYS_MSGSND,
    "MSGRCV":                   syscall.SYS_MSGRCV,
    "MSGGET":                   syscall.SYS_MSGGET,
    "MSGCTL":                   syscall.SYS_MSGCTL,
    "SHMAT":                    syscall.SYS_SHMAT,
    "SHMDT":                    syscall.SYS_SHMDT,
    "SHMGET":                   syscall.SYS_SHMGET,
    "SHMCTL":                   syscall.SYS_SHMCTL,
    "ADD_KEY":                  syscall.SYS_ADD_KEY,
    "REQUEST_KEY":              syscall.SYS_REQUEST_KEY,
    "KEYCTL":                   syscall.SYS_KEYCTL,
    "SEMTIMEDOP":               syscall.SYS_SEMTIMEDOP,
    "VSERVER":                  syscall.SYS_VSERVER,
    "IOPRIO_SET":               syscall.SYS_IOPRIO_SET,
    "IOPRIO_GET":               syscall.SYS_IOPRIO_GET,
    "INOTIFY_INIT":             syscall.SYS_INOTIFY_INIT,
    "INOTIFY_ADD_WATCH":        syscall.SYS_INOTIFY_ADD_WATCH,
    "INOTIFY_RM_WATCH":         syscall.SYS_INOTIFY_RM_WATCH,
    "MBIND":                    syscall.SYS_MBIND,
    "GET_MEMPOLICY":            syscall.SYS_GET_MEMPOLICY,
    "SET_MEMPOLICY":            syscall.SYS_SET_MEMPOLICY,
    "OPENAT":                   syscall.SYS_OPENAT,
    "MKDIRAT":                  syscall.SYS_MKDIRAT,
    "MKNODAT":                  syscall.SYS_MKNODAT,
    "FCHOWNAT":                 syscall.SYS_FCHOWNAT,
    "FUTIMESAT":                syscall.SYS_FUTIMESAT,
    "FSTATAT64":                syscall.SYS_FSTATAT64,
    "UNLINKAT":                 syscall.SYS_UNLINKAT,
    "RENAMEAT":                 syscall.SYS_RENAMEAT,
    "LINKAT":                   syscall.SYS_LINKAT,
    "SYMLINKAT":                syscall.SYS_SYMLINKAT,
    "READLINKAT":               syscall.SYS_READLINKAT,
    "FCHMODAT":                 syscall.SYS_FCHMODAT,
    "FACCESSAT":                syscall.SYS_FACCESSAT,
    "PSELECT6":                 syscall.SYS_PSELECT6,
    "PPOLL":                    syscall.SYS_PPOLL,
    "UNSHARE":                  syscall.SYS_UNSHARE,
    "SET_ROBUST_LIST":          syscall.SYS_SET_ROBUST_LIST,
    "GET_ROBUST_LIST":          syscall.SYS_GET_ROBUST_LIST,
    "SPLICE":                   syscall.SYS_SPLICE,
    "ARM_SYNC_FILE_RANGE":      syscall.SYS_ARM_SYNC_FILE_RANGE,
    "TEE":                      syscall.SYS_TEE,
    "VMSPLICE":                 syscall.SYS_VMSPLICE,
    "MOVE_PAGES":               syscall.SYS_MOVE_PAGES,
    "GETCPU":                   syscall.SYS_GETCPU,
    "EPOLL_PWAIT":              syscall.SYS_EPOLL_PWAIT,
    "KEXEC_LOAD":               syscall.SYS_KEXEC_LOAD,
    "UTIMENSAT":                syscall.SYS_UTIMENSAT,
    "SIGNALFD":                 syscall.SYS_SIGNALFD,
    "TIMERFD_CREATE":           syscall.SYS_TIMERFD_CREATE,
    "EVENTFD":                  syscall.SYS_EVENTFD,
    "FALLOCATE":                syscall.SYS_FALLOCATE,
    "TIMERFD_SETTIME":          syscall.SYS_TIMERFD_SETTIME,
    "TIMERFD_GETTIME":          syscall.SYS_TIMERFD_GETTIME,
    "SIGNALFD4":                syscall.SYS_SIGNALFD4,
    "EVENTFD2":                 syscall.SYS_EVENTFD2,
    "EPOLL_CREATE1":            syscall.SYS_EPOLL_CREATE1,
    "DUP3":                     syscall.SYS_DUP3,
    "PIPE2":                    syscall.SYS_PIPE2,
    "INOTIFY_INIT1":            syscall.SYS_INOTIFY_INIT1,
    "PREADV":                   syscall.SYS_PREADV,
    "PWRITEV":                  syscall.SYS_PWRITEV,
    "RT_TGSIGQUEUEINFO":        syscall.SYS_RT_TGSIGQUEUEINFO,
    "PERF_EVENT_OPEN":          syscall.SYS_PERF_EVENT_OPEN,
    "RECVMMSG":                 syscall.SYS_RECVMMSG,
    "ACCEPT4":                  syscall.SYS_ACCEPT4,
    "FANOTIFY_INIT":            syscall.SYS_FANOTIFY_INIT,
    "FANOTIFY_MARK":            syscall.SYS_FANOTIFY_MARK,
    "PRLIMIT64":                syscall.SYS_PRLIMIT64,
    "NAME_TO_HANDLE_AT":        syscall.SYS_NAME_TO_HANDLE_AT,
    "OPEN_BY_HANDLE_AT":        syscall.SYS_OPEN_BY_HANDLE_AT,
    "CLOCK_ADJTIME":            syscall.SYS_CLOCK_ADJTIME,
    "SYNCFS":                   syscall.SYS_SYNCFS,
    "SENDMMSG":                 syscall.SYS_SENDMMSG,
    "SETNS":                    syscall.SYS_SETNS,
    "PROCESS_VM_READV":         syscall.SYS_PROCESS_VM_READV,
    "PROCESS_VM_WRITEV":        syscall.SYS_PROCESS_VM_WRITEV,
}

var SyscallMapMin = map[string]int{
    "WRITE":                        syscall.SYS_WRITE,
    "RT_SIGRETURN":                 syscall.SYS_RT_SIGRETURN,
    "EXIT_GROUP":                   syscall.SYS_EXIT_GROUP,
    "FUTEX":                        syscall.SYS_FUTEX,
}
