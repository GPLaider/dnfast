#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_all(int fd, const char *buffer, size_t length) {
  while (length > 0) {
    ssize_t written = write(fd, buffer, length);
    if (written < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    buffer += written;
    length -= (size_t)written;
  }
  return 0;
}

static int relay_transcript(int fd) {
  char buffer[4096];
  for (;;) {
    ssize_t read_count = read(fd, buffer, sizeof(buffer));
    if (read_count == 0) return 0;
    if (read_count < 0) {
      if (errno == EINTR) continue;
      if (errno == EIO) return 0;
      return -1;
    }
    if (write_all(STDOUT_FILENO, buffer, (size_t)read_count) < 0) return -1;
  }
}

int main(int argc, char **argv) {
  int terminal;
  pid_t child;
  int status;
  int public_apply = 0;

  if (argc == 3 && argv[1][0] == '/' && argv[2][0] == '/') {
    puts("pty_args=2");
  } else if (argc == 4 && strcmp(argv[1], "--public-apply") == 0
             && argv[2][0] == '/' && argv[3][0] == '/') {
    public_apply = 1;
    puts("pty_public_apply=1");
  } else {
    fprintf(stderr, "usage: %s EXECUTOR PLAN | %s --public-apply DNFAST PLAN\n", argv[0], argv[0]);
    return 2;
  }
  fflush(stdout);
  child = forkpty(&terminal, NULL, NULL, NULL);
  if (child < 0) {
    perror("forkpty");
    return 125;
  }
  if (child == 0) {
    if (public_apply) {
      execl(argv[2], argv[2], "apply", argv[3], (char *)NULL);
      _exit(127);
    }
    int plan = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (plan < 0 || (plan != 3 && dup2(plan, 3) < 0)) _exit(126);
    if (plan != 3) close(plan);
    int flags = fcntl(3, F_GETFD);
    if (flags < 0 || fcntl(3, F_SETFD, flags & ~FD_CLOEXEC) < 0) _exit(126);
    execl(argv[1], argv[1], "--plan-fd", "3", (char *)NULL);
    _exit(127);
  }
  if (write_all(terminal, "n\n", 2) < 0 || relay_transcript(terminal) < 0) {
    perror("pty transcript");
    close(terminal);
    return 125;
  }
  close(terminal);
  if (waitpid(child, &status, 0) < 0) {
    perror("waitpid");
    return 125;
  }
  if (WIFEXITED(status)) {
    printf("pty_exit=%d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    printf("pty_signal=%d\n", WTERMSIG(status));
    return 128 + WTERMSIG(status);
  }
  fputs("pty_exit=unknown\n", stdout);
  return 125;
}
