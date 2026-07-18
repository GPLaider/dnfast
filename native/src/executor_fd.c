#define _GNU_SOURCE

#include "dnfast_native.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
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

int dnfast_executor_exec_compact(int plan_fd, int manifest_fd,
                                 const int *artifact_fds,
                                 size_t artifact_count, uint8_t approval) {
    if (plan_fd < 0 || manifest_fd < 0 || geteuid() != 0 ||
        artifact_count > 1024 || (artifact_count != 0 && artifact_fds == NULL))
        return -1;
    size_t descriptor_count = artifact_count + 2;
    int *temporary = calloc(descriptor_count, sizeof(*temporary));
    if (temporary == NULL) return -1;
    int minimum = (int)artifact_count + 5;
    for (size_t index = 0; index < descriptor_count; ++index) {
        int source = index == 0 ? plan_fd :
                     index == 1 ? manifest_fd : artifact_fds[index - 2];
        temporary[index] = fcntl(source, F_DUPFD_CLOEXEC, minimum);
        if (temporary[index] < 0) {
            for (size_t close_index = 0; close_index < index; ++close_index)
                (void)close(temporary[close_index]);
            free(temporary);
            return -1;
        }
    }
    for (size_t index = 0; index < descriptor_count; ++index) {
        int target = (int)index + 3;
        if (dup3(temporary[index], target, 0) < 0) {
            for (size_t close_index = 0; close_index < descriptor_count; ++close_index)
                (void)close(temporary[close_index]);
            free(temporary);
            return -1;
        }
        int flags = fcntl(target, F_GETFD);
        if (flags < 0 || fcntl(target, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
            for (size_t close_index = 0; close_index < descriptor_count; ++close_index)
                (void)close(temporary[close_index]);
            free(temporary);
            return -1;
        }
    }
    for (size_t index = 0; index < descriptor_count; ++index)
        (void)close(temporary[index]);
    free(temporary);
    unsigned int first_closed = (unsigned int)artifact_count + 5U;
    if (syscall(SYS_close_range, first_closed, UINT_MAX, 0U) < 0) return -1;
    if (clearenv() != 0 || setenv("LANG", "C.UTF-8", 1) != 0) return -1;
    umask(0077);
    char count[32];
    if (snprintf(count, sizeof(count), "%zu", artifact_count) <= 0) return -1;
    char *const prompt_arguments[] = {
        "/usr/libexec/dnfast-executor", "--plan-fd", "3", "--compact-fd", "4",
        "--artifact-fd-base", "5", "--artifact-count", count, NULL
    };
    char *const yes_arguments[] = {
        "/usr/libexec/dnfast-executor", "--plan-fd", "3", "--compact-fd", "4",
        "--artifact-fd-base", "5", "--artifact-count", count, "--assumeyes", NULL
    };
    char *const no_arguments[] = {
        "/usr/libexec/dnfast-executor", "--plan-fd", "3", "--compact-fd", "4",
        "--artifact-fd-base", "5", "--artifact-count", count, "--assumeno", NULL
    };
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

static int take_inherited_fd(int source, int minimum) {
    int flags = fcntl(source, F_GETFD);
    if (flags < 0 || fcntl(source, F_SETFD, flags | FD_CLOEXEC) < 0)
        return -1;
    int duplicate = fcntl(source, F_DUPFD_CLOEXEC, minimum);
    return duplicate;
}

int dnfast_executor_take_plan_fd(void) {
    return take_inherited_fd(3, 4);
}

int dnfast_executor_take_compact_fd(void) {
    return take_inherited_fd(4, 5);
}

int dnfast_executor_take_artifact_fd(size_t index) {
    if (index > 1023) return -1;
    return take_inherited_fd((int)index + 5, (int)index + 6);
}
