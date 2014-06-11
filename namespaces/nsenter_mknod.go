package namespaces

/*
#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <sched.h>

// This function enters the namespace of the process and calls mknod(2) to create a new device node.
// This should be safe to call from Go because it does not manipulate any threads, file descriptors etc.

int nsenter_mknod(char *mount_ns_file, char *mknod_file, unsigned long long mode, unsigned int major, unsigned int minor) {

        if (mount_ns_file == NULL || mknod_file == NULL) {
                fprintf(stderr, "nsenter_mknod: Incorrect argument.");
                return 1;
        }

        int child = fork();
        if (child == 0) {

                int fd = open(mount_ns_file, O_RDONLY);
                if (fd == -1) {
                        fprintf(stderr, "nsenter_mknod: Failed to open ns file \"%s\" with error: \"%s\"\n", mount_ns_file, strerror(errno));
                        return 1;
                }

                // Set the namespace.
                if (setns(fd, 0) == -1) {
                        fprintf(stderr, "nsenter_mknod: Failed to setns for \"%s\" with error: \"%s\"\n", mount_ns_file, strerror(errno));
                        return 1;
                }
                close(fd);

                // Clear the umask because we have all the permission bits in the mode.  Not worried about saving the old
                // umask because we just exit below anyway.
                umask(0);

                if (mknod(mknod_file, mode, makedev(major, minor)) == -1) {
                        fprintf(stderr, "nsenter_mknod: Failed to mknod \"%s\" with error: \"%s\"\n", mknod_file, strerror(errno));
                        return 1;
                }
		exit(0);
	} else {
		// Parent, wait for the child.
		int status = 0;

		if (waitpid(child, &status, 0) == -1) {
			fprintf(stderr, "nsenter: Failed to waitpid with error: \"%s\"\n", strerror(errno));
			exit(1);
		}
	}

	return 0;
}

*/
import "C"
import "fmt"
import "unsafe"

func NsEnterMknod(mount_file string, mknod_file string, mode uint64, major uint, minor uint) error {
	// cgo docs aren't clear if you can do the free in C so I'm doing it here like they show.
	mount_file_c := C.CString(mount_file)
	mknod_file_c := C.CString(mknod_file)
	err := C.nsenter_mknod(mount_file_c, mknod_file_c, C.ulonglong(mode), C.uint(major), C.uint(minor))
	C.free(unsafe.Pointer(mount_file_c))
	C.free(unsafe.Pointer(mknod_file_c))

	if err > 0 {
		return fmt.Errorf("Error creating node in container (check stderr)")
	}

	return nil
}
