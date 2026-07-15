#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <stdlib.h>
#include <unistd.h>

#ifdef DNFAST_NATIVE_REAL
FD_t dnfast_transaction_truncated_duplicate(const dnfast_transaction_item *item) {
    char path[] = "/tmp/dnfast-payload-fault.XXXXXX";
    int raw = mkstemp(path);
    if (raw < 0) return NULL;
    unlink(path);
    uint8_t buffer[64 * 1024];
    uint64_t limit = item->expected.artifact_size > 4096
        ? item->expected.artifact_size - 4096 : item->expected.artifact_size / 2;
    uint64_t offset = 0;
    while (offset < limit) {
        size_t wanted = limit - offset < sizeof(buffer)
            ? (size_t)(limit - offset) : sizeof(buffer);
        ssize_t count = pread(item->retained_fd, buffer, wanted, (off_t)offset);
        if (count <= 0 || write(raw, buffer, (size_t)count) != count) {
            close(raw);
            return NULL;
        }
        offset += (uint64_t)count;
    }
    FD_t duplicate = fdDup(raw);
    close(raw);
    return duplicate;
}
#endif
