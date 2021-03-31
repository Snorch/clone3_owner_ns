#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "util.h"

int child(void *unused)
{
	while (1)
		sleep(1);
	return 0;
}

#define CLONE_STACK_SIZE 4096
#define __stack_aligned__ __attribute__((aligned(16)))

int main()
{
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	struct _clone_args ca = {};
	int uns_pid, pid;
	int unsfd = -1, uns_kid;
	int pidnsfd = -1;
	int exit_code = 1;
	int status;

	uns_pid = clone(child, &stack[CLONE_STACK_SIZE],
		    CLONE_NEWUSER | SIGCHLD, NULL);
	if (uns_pid == -1) {
		printf("Fail to clone child: %m\n");
		return 1;
	}

	unsfd = open_ns_fd(uns_pid, "user");
	if (unsfd == -1) {
		printf("Failed to open userns for %d\n", uns_pid);
		goto err;
	}

	if (get_ns_kid(unsfd, &uns_kid)) {
		printf("Can't get userns kid of %d\n", uns_pid);
		close_safe(&unsfd);
		goto err;
	}
	printf("First child userns %u\n", uns_kid);

	ca.flags = CLONE_NEWPID | CLONE_OWNER_NS;
	ca.userns_fd = unsfd;

	pid = clone3(&ca);
	if (pid == -1) {
		printf("Fail to clone3 child: %m\n");
		close_safe(&unsfd);
		goto err;
	} else if (pid == 0) {
		close_safe(&unsfd);
		exit(child(NULL));
	}
	close_safe(&unsfd);

	unsfd = open_ns_fd(pid, "user");
	if (unsfd == -1) {
		printf("Failed to open userns for %d\n", pid);
		goto err2;
	}

	if (get_ns_kid(unsfd, &uns_kid)) {
		printf("Can't get userns kid of %d\n", pid);
		close_safe(&unsfd);
		goto err2;
	}
	printf("Second child userns %u\n", uns_kid);
	close_safe(&unsfd);

	pidnsfd = open_ns_fd(pid, "pid");
	if (pidnsfd == -1) {
		printf("Failed to open pidns for %d\n", pid);
		goto err2;
	}

	unsfd = ioctl(pidnsfd, NS_GET_USERNS);
	if (unsfd < 0) {
		printf("Fail get pidns owner: %m\n");
		close_safe(&pidnsfd);
		goto err2;
	}
	close_safe(&pidnsfd);

	if (get_ns_kid(unsfd, &uns_kid)) {
		printf("Can't get userns kid of owner of pidns of %d\n", pid);
		close_safe(&unsfd);
		goto err2;
	}
	printf("Second child pidns owner userns %u\n", uns_kid);
	close_safe(&unsfd);

	exit_code = 0;
err2:
	kill(pid, SIGTERM);
	waitpid(pid, &status, 0);
err:
	kill(uns_pid, SIGTERM);
	waitpid(uns_pid, &status, 0);
	return exit_code;
}
