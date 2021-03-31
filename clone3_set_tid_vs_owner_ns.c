#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sys/mount.h>

#include "util.h"

struct ancestor_args {
	/* Two pipes for setup_userns communication */
	int pipefd_pid[2];
	int pipefd_done[2];
	/* Pipe to report last ancestor pid */
	int pipefd_last[2];
	int level;
};

struct message {
	int pid;
};

static int ancestor(void *args);

#define CLONE_STACK_SIZE 4096
#define __stack_aligned__ __attribute__((aligned(16)))

/*
 * Clone process with new pid and user namespace, passing "proc"-level pid over
 * pipes from child to parent, so that we can setup userns for this process
 * right.
 */
static int clone_ns_ancestor(struct ancestor_args *aa)
{
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	struct message msg = {};
	int flags = CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD;
	int status;
	int len;
	int pid;

	if (pipe(aa->pipefd_pid) == -1) {
		perror("pipe");
		return -1;
	}

	if (pipe(aa->pipefd_done) == -1) {
		perror("pipe");
		goto err_close;
	}

	/* For last ancestor we only create userns */
	if (aa->level == 1)
		flags &= ~CLONE_NEWPID;

	pid = clone(ancestor, &stack[CLONE_STACK_SIZE],
		    flags | SIGCHLD, aa);
	if (pid == -1) {
		printf("Fail to clone ancestor %d: %m\n", aa->level);
		goto err_close;
	}

	close_safe(&aa->pipefd_pid[1]);
	close_safe(&aa->pipefd_done[0]);

	len = read(aa->pipefd_pid[0], &msg, sizeof(msg));
	if (len != sizeof(msg)) {
		perror("read pid");
		goto err;
	}
	close_safe(&aa->pipefd_pid[0]);

	if (setup_userns(msg.pid))
		goto err;

	len = write(aa->pipefd_done[1], &msg, sizeof(msg));
	if (len != sizeof(msg)) {
		perror("write done");
		goto err;
	}
	close_safe(&aa->pipefd_done[1]);

	return pid;
err:
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
err_close:
	close_safe(&aa->pipefd_pid[1]);
	close_safe(&aa->pipefd_done[0]);
	close_safe(&aa->pipefd_pid[0]);
	close_safe(&aa->pipefd_done[1]);
	return -1;
}

/*
 * Send "proc"-level pid to parent, so that it can setup userns for us.
 */
static int ancestor_prepare(struct ancestor_args *aa)
{
	struct message msg = {};

	close_safe(&aa->pipefd_pid[0]);
	close_safe(&aa->pipefd_done[1]);

	msg.pid = get_proc_pid();
	if (msg.pid == -1)
		goto err;

	if (write(aa->pipefd_pid[1], &msg, sizeof(msg)) != sizeof(msg)) {
		perror("write");
		goto err;
	}
	close_safe(&aa->pipefd_pid[1]);

	if (read(aa->pipefd_done[0], &msg, sizeof(msg)) != sizeof(msg)) {
		perror("read");
		goto err;
	}
	close_safe(&aa->pipefd_done[0]);

	return 0;

err:
	close_safe(&aa->pipefd_pid[1]);
	close_safe(&aa->pipefd_done[0]);
	return -1;
}

/*
 * Recursively clone needed amount of ancestors. In last ancestor pass
 * "proc"-level pid to ns_main and hang in sleep loop.
 */
static int ancestor(void *args)
{
	struct ancestor_args *aa = (struct ancestor_args *)args;
	int status;
	int pid;

	close_safe(&aa->pipefd_last[0]);

	if (ancestor_prepare(aa)) {
		printf("Failed to prepare ancestor %d\n", aa->level);
		goto err;
	}

	aa->level--;

	if (aa->level) {
		pid = clone_ns_ancestor(aa);
		if (pid == -1) {
			printf("Failed to clone ns_ancestor %d\n", aa->level);
			goto err;
		}
		close_safe(&aa->pipefd_last[1]);
		waitpid(pid, &status, 0);
	} else {
		struct message msg = {};

		msg.pid = get_proc_pid();
		if (msg.pid == -1)
			goto err;

		if (write(aa->pipefd_last[1], &msg, sizeof(msg)) != sizeof(msg)) {
			perror("write");
			goto err;
		}

		while (1)
			sleep(1);
	}
	return 0;
err:
	close_safe(&aa->pipefd_last[1]);
	return 1;
}

#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int last_pidns_helper(int last_pid)
{
	int userns_fd = -1, userns_kid;
	pid_t set_tid[] = {1, 10, 10, 10, 10, 10};
	struct _clone_args ca = {
		.exit_signal = SIGCHLD,
		.set_tid = ptr_to_u64(set_tid),
		.set_tid_size = ARRAY_SIZE(set_tid),
		.flags = CLONE_OWNER_NS | CLONE_NEWPID,
	};
	int cpid;
	int status = 0;

	userns_fd = open_ns_fd(last_pid, "user");
	if (userns_fd == -1) {
		printf("Can't open userns_fd of %d\n", last_pid);
		return 1;
	}

	if (get_ns_kid(userns_fd, &userns_kid)) {
		printf("Can't get userns kid of %d\n", last_pid);
		close_safe(&userns_fd);
		return 1;
	}
	printf("Last ancestor userns %u\n", userns_kid);

	ca.userns_fd = userns_fd;

	cpid = clone3(&ca);
	if (cpid == -1) {
		perror("clone3");
		close_safe(&userns_fd);
		return 1;
	} else if (cpid == 0) {
		int proc_pid;
		int pidns_fd = -1;
		int ownerns_fd = -1, ownerns_kid;
		char comm[4096];

		close_safe(&userns_fd);

		proc_pid = get_proc_pid();
		if (proc_pid == -1)
			exit(1);

		pidns_fd = open_ns_fd(proc_pid, "pid");
		if (pidns_fd == -1) {
			printf("Can't open pidns_fd of %d\n", last_pid);
			exit(1);
		}

		ownerns_fd = ioctl(pidns_fd, NS_GET_USERNS);
		if (ownerns_fd < 0) {
			perror("ioctl NS_GET_USERNS");
			close_safe(&pidns_fd);
			exit(1);
		}
		close_safe(&pidns_fd);

		if (get_ns_kid(ownerns_fd, &ownerns_kid)) {
			printf("Can't get userns kid of %d\n", proc_pid);
			close_safe(&ownerns_fd);
			exit(1);
		}
		close_safe(&ownerns_fd);
		printf("New init pidns owner userns %u\n", ownerns_kid);

		if (snprintf(comm, sizeof(comm), "grep NSpid /proc/%d/status",
			     proc_pid) >= sizeof(comm)) {
			perror("snprintf comm truncated");
			return -1;
		}
		system(comm);

		exit(0);
	}
	close_safe(&userns_fd);

	if ((waitpid(cpid, &status, 0) < 0) || status) {
		printf("Child cpid has bad exit status %d: %m\n", status);
		return 1;
	}
	return 0;
}

#define NUM_ANCESTORS 5

static int ns_main(void *unused)
{
	int exit_code = 1;
	struct ancestor_args aa = {
		.pipefd_pid = {-1, -1},
		.pipefd_done = {-1, -1},
		.pipefd_last = {-1, -1},
		.level = NUM_ANCESTORS,

	};
	struct message msg = {};
	int status = 0;
	int pid;
	int last_pid = 0;
	int pidns_fd = -1;
	int helper_pid;

	if (prepare_mntns())
		return 1;

	/* Pipe to get pid in current pidns of the last ancestor */
	if (pipe(aa.pipefd_last) == -1) {
		perror("pipe");
		return 1;
	}

	pid = clone_ns_ancestor(&aa);
	if (pid == -1) {
		printf("Failed to clone ns_ancestor %d\n", aa.level);
		goto err_close;
	}
	close_safe(&aa.pipefd_last[1]);

	if (read(aa.pipefd_last[0], &msg, sizeof(msg)) != sizeof(msg)) {
		perror("read");
		goto err;
	}
	close_safe(&aa.pipefd_last[0]);
	last_pid = msg.pid;

	/*
	 * Preparation stage finished: Now we have NUM_ANCESTORS ancestors
	 * hanging, each ancestor created one more nested level of
	 * userns+pidns except last one which only has new nested userns. And
	 * last_pid is a pid of this last ancestor (e.g. 6).
	 *
	 * ┌−−−−−−−−−−−−┐  ┌−−−−−−−−−−−−┐  ┌−−−−−−−−−−−−−−┐
	 * ╎  usernses  ╎  ╎  pidnses   ╎  ╎  processes   ╎
	 * ╎            ╎  ╎            ╎  ╎              ╎
	 * ╎ ┌────────┐ ╎  ╎ ┌────────┐ ╎  ╎ ┌──────────┐ ╎
	 * ╎ │  usr_1 │ ╎─▶╎ │  pid_1 │ ╎─▶╎ │ns_main(1)│ ╎
	 * ╎ └────────┘ ╎  ╎ └────────┘ ╎  ╎ └──────────┘ ╎
	 * ╎   │        ╎  ╎   │        ╎  ╎   │          ╎
	 * ╎   ▼        ╎  ╎   ▼        ╎  ╎   ▼          ╎
	 * ╎ ┌────────┐ ╎  ╎ ┌────────┐ ╎  ╎ ┌─────────┐  ╎
	 * ╎ │  usr_2 │ ╎─▶╎ │  pid_2 │ ╎─▶╎ │  anc(2) │  ╎
	 * ╎ └────────┘ ╎  ╎ └────────┘ ╎  ╎ └─────────┘  ╎
	 * ╎   │        ╎  ╎   │        ╎  ╎   │          ╎
	 * ╎   ▼        ╎  ╎   ▼        ╎  ╎   ▼          ╎
	 * ╎ ┌────────┐ ╎  ╎ ┌────────┐ ╎  ╎ ┌─────────┐  ╎
	 * ╎ │  usr_3 │ ╎─▶╎ │  pid_3 │ ╎─▶╎ │  anc(3) │  ╎
	 * ╎ └────────┘ ╎  ╎ └────────┘ ╎  ╎ └─────────┘  ╎
	 * ╎   │        ╎  ╎   │        ╎  ╎   │          ╎
	 * ╎   ▼        ╎  ╎   ▼        ╎  ╎   ▼          ╎
	 * ╎ ┌────────┐ ╎  ╎ ┌────────┐ ╎  ╎ ┌─────────┐  ╎
	 * ╎ │  usr_4 │ ╎─▶╎ │  pid_4 │ ╎─▶╎ │  anc(4) │  ╎
	 * ╎ └────────┘ ╎  ╎ └────────┘ ╎  ╎ └─────────┘  ╎
	 * ╎   │        ╎  ╎   │        ╎  ╎   │          ╎
	 * ╎   ▼        ╎  ╎   ▼        ╎  ╎   ▼          ╎
	 * ╎ ┌────────┐ ╎  ╎ ┌────────┐ ╎  ╎ ┌─────────┐  ╎
	 * ╎ │  usr_5 │ ╎─▶╎ │  pid_5 │ ╎─▶╎ │  anc(5) │  ╎
	 * ╎ └────────┘ ╎  ╎ └────────┘ ╎  ╎ └─────────┘  ╎
	 * ╎   │        ╎  └−−−−−−−−−−−−┘  ╎   │          ╎
	 * ╎   ▼        ╎                  ╎   ▼          ╎
	 * ╎ ┌────────┐ ╎                  ╎ ┌─────────┐  ╎
	 * ╎ │  usr_6 │ ╎─────────────────▶╎ │  anc(6) │  ╎
	 * ╎ └────────┘ ╎                  ╎ └─────────┘  ╎
	 * └−−−−−−−−−−−−┘                  └−−−−−−−−−−−−−−┘
	 * 
	 * Imagine now that we want to create one more process which would be
	 * an init/reaper of one more new pidns (pid_6), like this:
	 *
	 * ┌−−−−−−−−−−−−┐  ┌−−−−−−−−−−−−┐  ┌−−−−−−−−−−−−−−┐
	 * ╎ ┌────────┐ ╎  ╎ ┌────────┐ ╎  ╎ ┌─────────┐  ╎
	 * ╎ │  usr_5 │ ╎─▶╎ │  pid_5 │ ╎─▶╎ │  anc(5) │  ╎
	 * ╎ └────────┘ ╎  ╎ └────────┘ ╎  ╎ └─────────┘  ╎
	 * ╎   │        ╎  ╎   │        ╎  ╎              ╎
	 * ╎   ▼        ╎  ╎   ▼        ╎  ╎              ╎
	 * ╎ ┌────────┐ ╎  ╎ ┌────────┐ ╎  ╎ ┌─────────┐  ╎
	 * ╎ │  usr_6 │ ╎─▶╎ │  pid_6 │ ╎─▶╎ │  init   │  ╎
	 * ╎ └────────┘ ╎  ╎ └────────┘ ╎  ╎ └─────────┘  ╎
	 * └−−−−−−−−−−−−┘  └−−−−−−−−−−−−┘  └−−−−−−−−−−−−−−┘
	 *
	 * But we also want to set proper pid numbers in each of pid_1..pid_6,
	 * e.g. {10,10,10,10,10,1}.
	 *
	 * We can't do it with clone3 with clone_args.set_tid set for all the
	 * levels without new CLONE_OWNER_NS. Because if we want new pidns
	 * pid_6 to be owned by userns usr_6 without CLONE_OWNER_NS we should
	 * be in usr_6 at the time of clone, and we would not have permissions
	 * to set tid in pidnses pid_5..pid_1 because we are in relatively
	 * unprivileged usens, relative to usr_5..usr_1.
	 *
	 * With setting /proc/sys/kernel/ns_last_pid on each pidns level we can
	 * do it. But we should also be able to do it with less racy new
	 * set_tid interface too. And with CLONE_OWNER_NS we can:
	 */

	pidns_fd = open_ns_fd(last_pid, "pid");
	if (pidns_fd == -1) {
		printf("Can't open pidns_fd of %d\n", last_pid);
		goto err;
	}

	if (setns(pidns_fd, CLONE_NEWPID)) {
		perror("setns");
		close_safe(&pidns_fd);
		goto err;
	}
	close_safe(&pidns_fd);

	helper_pid = fork();
	if (helper_pid == -1) {
		perror("fork");
		goto err;
	} else if (helper_pid == 0) {
		exit(last_pidns_helper(last_pid));
	}

	if ((waitpid(helper_pid, &status, 0) < 0) || status) {
		printf("Child helper_pid has bad exit status %d: %m\n", status);
		goto err;
	}

	exit_code = 0;
err:
	if (last_pid)
		kill(last_pid, SIGKILL);
	else
		kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
err_close:
	close_safe(&aa.pipefd_last[0]);
	close_safe(&aa.pipefd_last[1]);
	return exit_code;
}

int main()
{
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	int status = 0;
	int pid;

	pid = clone(ns_main, &stack[CLONE_STACK_SIZE],
		    CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, NULL);
	if (pid == -1) {
		perror("clone ns_main");
		return 1;
	}

	if (waitpid(pid, &status, 0) < 0 || status) {
		printf("Child ns_main has bad exit status %d: %m\n", status);
		return 1;
	}

	return 0;
}
