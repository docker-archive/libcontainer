// +build cgo
//
// formated with indent -linux nsenter.c

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

static const kBufSize = 4096;

int get_args(int fd, int *argc, char ***argv)
{
	// Read the whole commandline.
	ssize_t contents_size = 0;
	ssize_t contents_offset = 0;
	char *contents = NULL, *tmp;
	ssize_t bytes_read = 0;
	int idx = *argc;
	do {
		contents_size += kBufSize;
		tmp = (char *)realloc(contents, contents_size);
		if (!tmp) {
			goto on_error;	
		}

		contents = tmp;
		bytes_read = read(fd, contents + contents_offset, contents_size - contents_offset);
		if (bytes_read < 0) {
			goto on_error;
		}

		contents_offset += bytes_read;
	} while (bytes_read > 0);
	close(fd);

	// Parse the commandline into an argv.
	// /proc/self/cmdline or argfile should be \0 delimited.

	ssize_t i;
	for (i = 0; i < contents_offset; i++) {
		if (contents[i] == '\0') {
			(*argc)++;
		}
	}
	tmp = (char *)realloc(*argv, sizeof(char *) * ((*argc) + 1));
	if (!tmp) {
		goto on_error;
	}
	*argv = (char **)tmp;

	for (; idx < (*argc); idx++) {
		(*argv)[idx] = contents;
		contents += strlen(contents) + 1;
	}
	(*argv)[*argc] = NULL;
	return 0;

on_error:
	fprintf(stderr, "nsenter: Failed reading commandline with error: \"%s\"\n", strerror(errno));
	if (contents) {
		free(contents);
	}
	return -1;
}

// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#define _GNU_SOURCE
#include <sched.h>
#include "syscall.h"
#ifdef SYS_setns
int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif
#endif

void print_usage()
{
	fprintf(stderr,
			"Usage: <binary> nsenter --nspid <pid> --config <pipe_fd> --containerjson <container_json> -- cmd1 arg1 arg2...\n");
}

void nsenter()
{
	int argc = 0;
	char **argv = NULL;
	int fd;

	fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd < 0)
		exit(1);

	if (get_args(fd, &argc, &argv)) {
		close(fd);
		exit(1);
	}
	close(fd);

	// Ignore if this is not for us.
	if (argc < 6 || strcmp(argv[1], "nsenter") != 0) {
		return;
	}

	static const struct option longopts[] = {
		{ "nspid",         required_argument, NULL, 'n' },
		{ "containerjson", required_argument, NULL, 'c' },
		{ "console",       required_argument, NULL, 't' },
		{ "config",        required_argument, NULL, 'F' },
		{ NULL,            0,                 NULL,  0  }
	};

	int c;
	pid_t init_pid = -1;
	char *init_pid_str = NULL;
	char *container_json = NULL;
	char *console = NULL;
	char *argend = NULL;

	opterr = 0;
	while ((c = getopt_long_only(argc, argv, ":n:s:c:F:", longopts, NULL)) != -1) {
		switch (c) {
		case 'n':
			init_pid_str = optarg;
			break;
		case 'c':
			container_json = optarg;
			break;
		case 't':
			console = optarg;
			break;
		case 'F':
			// Append any additional args.
			fd = strtol(optarg, &argend, 10);
			if (fd == LONG_MIN || fd == LONG_MAX ||
				argend == optarg || *argend != '\0') {
				fprintf(stderr, "nsenter: Invalid config file\n");
				exit(1);
			}
			break;
		case ':':
			fprintf(stderr,
					"nsenter: Required argument missing for option '-%c'\n",
					(char)optopt);
			print_usage();
			exit(1);
			break;
		case '?':
		default:
			fprintf(stderr, "nsenter: Unrecongnized commandline option\n");
			print_usage();
			exit(1);
			break;
		}
	}

	if (container_json == NULL || init_pid_str == NULL) {
		print_usage();
		exit(1);
	}

	init_pid = strtol(init_pid_str, &argend, 10);
	if (init_pid == LONG_MIN || init_pid == LONG_MAX ||
		argend == init_pid_str || *argend != '\0' ||
		init_pid <= 0) {
		fprintf(stderr,
				"nsenter: Failed to parse PID from \"%s\" with error: \"%s\"\n",
				init_pid_str, strerror(errno));
		print_usage();
		exit(1);
	}

	argc -= 3;
	argv += 3;

	if (setsid() == -1) {
		fprintf(stderr, "nsenter: Failed to setsid \"%s\"\n", strerror(errno));
		exit(1);
	}

	// before we setns we need to dup the console
	int consolefd = -1;
	if (console != NULL) {
		consolefd = open(console, O_RDWR);
		if (consolefd < 0) {
			fprintf(stderr,
					"nsenter: Failed to open console %s %s\n",
					console, strerror(errno));
			exit(1);
		}
	}

	// Setns on all supported namespaces.
	char ns_dir[PATH_MAX];
	memset(ns_dir, 0, PATH_MAX);
	snprintf(ns_dir, PATH_MAX, "/proc/%d/ns/", init_pid);

	char *namespaces[] = {"ipc", "uts", "net", "pid", "mnt"};
	const int num = sizeof(namespaces) / sizeof(char *);
	int i;
	for (i = 0; i < num; i++) {
		char buf[PATH_MAX];
		memset(buf, 0, PATH_MAX);
		snprintf(buf, PATH_MAX, "%s%s", ns_dir, namespaces[i]);
		int fd = open(buf, O_RDONLY);
		if (fd == -1) {
			// Ignore nonexistent namespaces.
			if (errno == ENOENT)
				continue;

			fprintf(stderr,
					"nsenter: Failed to open ns file \"%s\" for ns \"%s\" with error: \"%s\"\n",
					buf, namespaces[i], strerror(errno));
			exit(1);
		}

		// Set the namespace.
		if (setns(fd, 0) == -1) {
			fprintf(stderr,
					"nsenter: Failed to setns for \"%s\" with error: \"%s\"\n",
					namespaces[i], strerror(errno));
			exit(1);
		}
		close(fd);
	}

	// We must fork to actually enter the PID namespace.
	int child = fork();
	if (child == 0) {
		if (consolefd != -1) {
			if (dup2(consolefd, STDIN_FILENO) != 0) {
				fprintf(stderr, "nsenter: Failed to dup 0 %s\n",
						strerror(errno));
				exit(1);
			}
			if (dup2(consolefd, STDOUT_FILENO) != STDOUT_FILENO) {
				fprintf(stderr, "nsenter: Failed to dup 1 %s\n",
						strerror(errno));
				exit(1);
			}
			if (dup2(consolefd, STDERR_FILENO) != STDERR_FILENO) {
				fprintf(stderr, "nsenter: Failed to dup 2 %s\n",
						strerror(errno));
				exit(1);
			}
		}

		// Finish executing, let the Go runtime take over.
		return;
	} else {
		// Parent, wait for the child.
		int status = 0;
		if (waitpid(child, &status, 0) == -1) {
			fprintf(stderr,
					"nsenter: Failed to waitpid with error: \"%s\"\n",
					strerror(errno));
			exit(1);
		}

		// Forward the child's exit code or re-send its death signal.
		if (WIFEXITED(status)) {
			exit(WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			kill(getpid(), WTERMSIG(status));
		}
		exit(1);
	}

	return;
}
