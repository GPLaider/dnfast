#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MAX_TRACKED = 4096 };

static pthread_mutex_t registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;
static int tracked[MAX_TRACKED];
static size_t tracked_count;

static void fork_prepare(void) {
    (void)pthread_mutex_lock(&registry_mutex);
}

static void fork_parent(void) {
    (void)pthread_mutex_unlock(&registry_mutex);
}

static void fork_child(void) {
    for (size_t index = 0; index < tracked_count; ++index) {
        (void)close(tracked[index]);
    }
    tracked_count = 0;
    (void)pthread_mutex_unlock(&registry_mutex);
}

static void register_atfork(void) {
    (void)pthread_atfork(fork_prepare, fork_parent, fork_child);
}

int dnfast_lock_acquire(const char *name, size_t length) {
    if (name == NULL || length == 0 || length > sizeof(((struct sockaddr_un *)0)->sun_path) - 1) {
        return -EINVAL;
    }
    int once_error = pthread_once(&atfork_once, register_atfork);
    if (once_error != 0) {
        return -once_error;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -errno;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(&address.sun_path[1], name, length);
    socklen_t address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + length);
    if (bind(fd, (const struct sockaddr *)&address, address_length) != 0) {
        int error = errno;
        (void)close(fd);
        return -error;
    }
    int lock_error = pthread_mutex_lock(&registry_mutex);
    if (lock_error != 0) {
        (void)close(fd);
        return -lock_error;
    }
    if (tracked_count == MAX_TRACKED) {
        (void)pthread_mutex_unlock(&registry_mutex);
        (void)close(fd);
        return -EMFILE;
    }
    tracked[tracked_count++] = fd;
    (void)pthread_mutex_unlock(&registry_mutex);
    return fd;
}

void dnfast_lock_release(int fd) {
    int found = 0;
    (void)pthread_mutex_lock(&registry_mutex);
    for (size_t index = 0; index < tracked_count; ++index) {
        if (tracked[index] == fd) {
            tracked[index] = tracked[tracked_count - 1];
            --tracked_count;
            found = 1;
            break;
        }
    }
    (void)pthread_mutex_unlock(&registry_mutex);
    if (found != 0) {
        (void)close(fd);
    }
}

int dnfast_lock_fork_probe(const char *name, size_t length) {
    int parent_fd = dnfast_lock_acquire(name, length);
    if (parent_fd < 0) {
        return parent_fd;
    }
    pid_t held_child = fork();
    if (held_child == 0) {
        int reused = open("/dev/null", O_RDONLY | O_CLOEXEC);
        dnfast_lock_release(parent_fd);
        if (reused < 0 || fcntl(reused, F_GETFD) < 0) {
            _exit(12);
        }
        (void)close(reused);
        int result = dnfast_lock_acquire(name, length);
        _exit(result == -EADDRINUSE ? 0 : 10);
    }
    int status = 0;
    if (held_child < 0 || waitpid(held_child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        dnfast_lock_release(parent_fd);
        return -ECHILD;
    }
    dnfast_lock_release(parent_fd);
    pid_t released_child = fork();
    if (released_child == 0) {
        int result = dnfast_lock_acquire(name, length);
        if (result >= 0) {
            dnfast_lock_release(result);
            _exit(0);
        }
        _exit(11);
    }
    if (released_child < 0 || waitpid(released_child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -ECHILD;
    }
    return 0;
}
