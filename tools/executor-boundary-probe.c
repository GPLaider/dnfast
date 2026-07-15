#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--plan-fd") != 0 || strcmp(argv[2], "3") != 0) return 10;
    if (environ[0] == NULL || environ[1] != NULL || strcmp(environ[0], "LANG=C.UTF-8") != 0) return 11;
    for (int fd = 0; fd <= 3; fd++) {
        if (fcntl(fd, F_GETFD) < 0) return 12;
    }
    errno = 0;
    if (fcntl(4, F_GETFD) != -1 || errno != EBADF) return 13;
    puts("executor_boundary=passed");
    return 0;
}
