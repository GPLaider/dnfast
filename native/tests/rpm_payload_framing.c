#define _POSIX_C_SOURCE 200809L
#include "../src/rpm_payload.c"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>

static void put32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}

static void header(int fd, off_t offset, uint32_t count, uint32_t data) {
    uint8_t intro[16] = {0x8e, 0xad, 0xe8, 1};
    put32(intro + 8, count); put32(intro + 12, data);
    assert(pwrite(fd, intro, sizeof(intro), offset) == sizeof(intro));
}

int main(void) {
    char path[] = "/tmp/dnfast-rpm-payload-XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0); unlink(path);
    header(fd, 96, 0, 0); header(fd, 112, 0, 0);
    off_t payload = 0;
    assert(payload_offset(fd, &payload) == 0 && payload == 128);
    header(fd, 96, 4000001, 0);
    assert(payload_offset(fd, &payload) != 0);
    header(fd, 96, 0, 512 * 1024 * 1024 + 1U);
    assert(payload_offset(fd, &payload) != 0);
    header(fd, 96, 4000000, 0);
    off_t main_start = 112 + (off_t)4000000 * 16;
    header(fd, main_start, 0, 0);
    assert(payload_offset(fd, &payload) == 0 && payload == main_start + 16);
    header(fd, main_start, 4000001, 0);
    assert(payload_offset(fd, &payload) != 0);
    header(fd, 96, 0, 0);
    header(fd, 112, 0, 512 * 1024 * 1024);
    assert(payload_offset(fd, &payload) == 0 && payload == 128 + (off_t)512 * 1024 * 1024);
    header(fd, 112, 0, 512 * 1024 * 1024 + 1U);
    assert(payload_offset(fd, &payload) != 0);
    close(fd);
    return 0;
}
