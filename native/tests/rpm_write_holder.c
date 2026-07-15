#define _GNU_SOURCE
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || rpmReadConfigFiles(NULL, NULL) != 0) return 2;
    rpmts ts = rpmtsCreate();
    if (ts == NULL || rpmtsSetRootDir(ts, "/") != 0) return 3;
    rpmtxn txn = rpmtxnBegin(ts, RPMTXN_WRITE);
    if (txn == NULL) return 4;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, "ready", 5) != 5) return 5;
    close(fd);
    sleep(40);
    rpmtxnEnd(txn);
    rpmtsFree(ts);
    return 0;
}
