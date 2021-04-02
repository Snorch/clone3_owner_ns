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

/*
 * Set fd to -1 to identy closed file, thus closes the file only once.
 */
int close_safe(int *fd)
{
	int ret = 0;

	if (*fd > -1) {
		ret = close(*fd);
		if (ret)
			printf("Failed to close %d: %m\n", *fd);
		else
			*fd = -1;
	}

	return ret;
}

/*
 * Mount proc of current pidns, will use to get pids in this pidns.
 */
int prepare_mntns(void)
{
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
		perror("Failed to remount \"/\" private");
		return -1;
	}

	if (umount2("/proc", MNT_DETACH)) {
		perror("Failed to lazy umount /proc");
		return -1;
	}

	if (mount("proc", "/proc", "proc", 0, NULL)) {
		perror("Failed to mount /proc");
		return -1;
	}

	return 0;
}

/*
 * Get pid in pidns of the mounted procfs.
 */
int get_proc_pid(void)
{
	char pid_buf[16];
	int len;

	len = readlink("/proc/self", pid_buf, sizeof(pid_buf) - 1);
	if (len < 0) {
		perror("Failed to readlink /proc/self");
		return -1;
	}
	pid_buf[len] = '\0';

	return atoi(pid_buf);
}

int write_id_map(pid_t pid, char *val, char *id_map)
{
	char id_map_path[4096];
	int len;
	int fd;

	if (snprintf(id_map_path, sizeof(id_map_path), "/proc/%d/%s",
		     pid, id_map) >= sizeof(id_map_path)) {
		perror("Snprintf id_map_path truncated");
		return -1;
	}

	fd = open(id_map_path, O_WRONLY);
	if (fd < 0) {
		printf("Failed to open %s %m\n", id_map_path);
		return -1;
	}

	len = strlen(val) + 1;
	if (write(fd, val, len) != len) {
		printf("Failed to write to %s %m\n", id_map_path);
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

/*
 * Initialize new userns to be able to work in it.
 */
int setup_userns(pid_t pid)
{
	if (write_id_map(pid, "0 0 20000", "uid_map"))
		return -1;

	if (write_id_map(pid, "0 0 20000", "gid_map"))
		return -1;

	return 0;
}

/*
 * Open desired namespace of the task.
 */
int open_ns_fd(int pid, char *ns)
{
	char nsfd_path[4096];
	int nsfd;

	if (snprintf(nsfd_path, sizeof(nsfd_path), "/proc/%d/ns/%s",
		     pid, ns) >= sizeof(nsfd_path)) {
		perror("Snprintf nsfd_path truncated");
		return -1;
	}

	nsfd = open(nsfd_path, O_RDONLY);
	if (nsfd == -1) {
		printf("Failed to open %s %m\n", nsfd_path);
		return -1;
	}

	return nsfd;
}

int get_ns_kid(int nsfd, int *kid)
{
	struct stat st = {};

	if (fstat(nsfd, &st) < 0) {
		printf("Failed to fstat nsfd %d: %m\n", nsfd);
		return -1;
	}
	*kid = st.st_ino;

	return 0;
}
