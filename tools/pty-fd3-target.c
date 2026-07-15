#include <fcntl.h>
#include <stdio.h>

int main(void) {
  if (fcntl(3, F_GETFD) < 0) return 1;
  puts("fd3_exec=present");
  return 0;
}
