#ifndef _CLONE3_UTIL_H_
#define _CLONE3_UTIL_H_

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

extern int close_safe(int *fd);
extern int prepare_mntns(void);
extern int get_proc_pid(void);
extern int write_id_map(pid_t pid, char *val, char *id_map);
extern int setup_userns(pid_t pid);
extern int open_ns_fd(int pid, char *ns);
extern int get_ns_kid(int nsfd, int *kid);

/*
 * Flag to override owner userns for newly created namespaces by clone3, to
 * some ancestor userns of current userns.
 */
#define CLONE_OWNER_NS 0x400000000ULL

struct _clone_args {
        __aligned_u64 flags;
        __aligned_u64 pidfd;
        __aligned_u64 child_tid;
        __aligned_u64 parent_tid;
        __aligned_u64 exit_signal;
        __aligned_u64 stack;
        __aligned_u64 stack_size;
        __aligned_u64 tls;
        __aligned_u64 set_tid;
        __aligned_u64 set_tid_size;
        __aligned_u64 cgroup;
        __aligned_u64 userns_fd;
};

#define SYS_clone3 435

static long clone3(struct _clone_args *cl_args)
{
        return syscall(SYS_clone3, cl_args, sizeof(struct _clone_args));
}

#define NSIO    0xb7
#define NS_GET_USERNS   _IO(NSIO, 0x1)

#define __stack_aligned__ __attribute__((aligned(16)))

#endif /* _CLONE3_UTIL_H_ */
