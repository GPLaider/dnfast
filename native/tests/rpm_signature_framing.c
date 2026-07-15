#define _POSIX_C_SOURCE 200809L
#include "../src/rpm_signature.c"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>

static void put32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}

static int file_with_header(uint32_t count, uint32_t data, int complete) {
    char path[] = "/tmp/dnfast-rpm-signature-XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0); unlink(path);
    uint8_t intro[16] = {0x8e, 0xad, 0xe8, 1};
    put32(intro + 8, count); put32(intro + 12, data);
    assert(pwrite(fd, intro, sizeof(intro), 96) == sizeof(intro));
    if (complete) assert(ftruncate(fd, 112 + (off_t)count * 16 + data) == 0);
    return fd;
}

int main(void) {
    dnfast_keyring ring = {0};
    int fd = file_with_header(4096, 1, 1);
    assert(dnfast_keyring_find_fd_signer(&ring, fd) == NULL); close(fd);
    fd = file_with_header(4097, 1, 1);
    assert(dnfast_keyring_find_fd_signer(&ring, fd) == NULL); close(fd);
    fd = file_with_header(1, 16 * 1024 * 1024, 1);
    assert(dnfast_keyring_find_fd_signer(&ring, fd) == NULL); close(fd);
    fd = file_with_header(1, 16 * 1024 * 1024 + 1, 0);
    assert(dnfast_keyring_find_fd_signer(&ring, fd) == NULL); close(fd);
    fd = file_with_header(1, 1, 1);
    uint8_t entry[16] = {0};
    put32(entry, RPMTAG_RSAHEADER); put32(entry + 4, 7);
    put32(entry + 8, 1); put32(entry + 12, 1);
    assert(pwrite(fd, entry, sizeof(entry), 112) == sizeof(entry));
    assert(dnfast_keyring_find_fd_signer(&ring, fd) == NULL); close(fd);
    fd = file_with_header(1, 1, 0);
    assert(dnfast_keyring_find_fd_signer(&ring, fd) == NULL); close(fd);
    return 0;
}
