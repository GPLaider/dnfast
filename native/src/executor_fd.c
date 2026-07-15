#define _GNU_SOURCE

#include "dnfast_native.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

int dnfast_executor_exec_fixed(int plan_fd, uint8_t approval) {
    if (plan_fd < 0 || geteuid() != 0) return -1;
    if (plan_fd != 3 && dup3(plan_fd, 3, 0) < 0) return -1;
    int flags = fcntl(3, F_GETFD);
    if (flags < 0 || fcntl(3, F_SETFD, flags & ~FD_CLOEXEC) < 0) return -1;
    if (syscall(SYS_close_range, 4U, UINT_MAX, 0U) < 0) return -1;
    if (clearenv() != 0 || setenv("LANG", "C.UTF-8", 1) != 0) return -1;
    umask(0077);
    char *const prompt_arguments[] = { "/usr/libexec/dnfast-executor", "--plan-fd", "3", NULL };
    char *const yes_arguments[] = { "/usr/libexec/dnfast-executor", "--plan-fd", "3", "--assumeyes", NULL };
    char *const no_arguments[] = { "/usr/libexec/dnfast-executor", "--plan-fd", "3", "--assumeno", NULL };
    char *const *arguments;
    switch (approval) {
        case DNFAST_EXECUTOR_PROMPT: arguments = prompt_arguments; break;
        case DNFAST_EXECUTOR_ASSUME_YES: arguments = yes_arguments; break;
        case DNFAST_EXECUTOR_ASSUME_NO: arguments = no_arguments; break;
        default: return -1;
    }
    execve(arguments[0], arguments, environ);
    return -1;
}

int dnfast_executor_take_plan_fd(void) {
    int flags = fcntl(3, F_GETFD);
    if (flags < 0 || fcntl(3, F_SETFD, flags | FD_CLOEXEC) < 0) {
        return -1;
    }
    int duplicate = fcntl(3, F_DUPFD, 4);
    if (duplicate < 0 || fcntl(duplicate, F_SETFD, FD_CLOEXEC) < 0) {
        if (duplicate >= 0) close(duplicate);
        return -1;
    }
    return duplicate;
}
