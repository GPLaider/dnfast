#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#ifdef DNFAST_NATIVE_REAL
#include <rpm/header.h>
#include <rpm/rpmcrypto.h>
#include <rpm/rpmtag.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define DNFAST_LEAD_SIZE 96
#define DNFAST_HEADER_SIZE 16
#define DNFAST_MAX_INDEX 4000000
#define DNFAST_MAX_HEADER (512 * 1024 * 1024)

static uint32_t be32(const uint8_t *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | value[3];
}

static int header_end(int fd, off_t start, off_t *end) {
    uint8_t intro[DNFAST_HEADER_SIZE];
    if (pread(fd, intro, sizeof(intro), start) != sizeof(intro) ||
        intro[0] != 0x8e || intro[1] != 0xad || intro[2] != 0xe8 ||
        intro[3] != 1) return -1;
    uint32_t count = be32(intro + 8);
    uint32_t data = be32(intro + 12);
    if (count > DNFAST_MAX_INDEX || data > DNFAST_MAX_HEADER) return -1;
    uint64_t size = DNFAST_HEADER_SIZE + (uint64_t)count * 16 + data;
    if (size > INT64_MAX || start > INT64_MAX - (off_t)size) return -1;
    *end = start + (off_t)size;
    return 0;
}

static int payload_offset(int fd, off_t *payload) {
    off_t signature_end = 0;
    if (header_end(fd, DNFAST_LEAD_SIZE, &signature_end) != 0) return -1;
    off_t main_start = (signature_end + 7) & ~(off_t)7;
    return header_end(fd, main_start, payload);
}

int dnfast_verify_payload_digest(int fd, Header header) {
    const char *expected = headerGetString(header, RPMTAG_PAYLOADSHA256);
    uint64_t algorithm = PGPHASHALGO_SHA256;
    off_t offset = 0;
    struct stat metadata;
    if (expected == NULL || expected[0] == '\0' || algorithm == 0 ||
        payload_offset(fd, &offset) != 0 || fstat(fd, &metadata) != 0 ||
        offset >= metadata.st_size) return -1;
    DIGEST_CTX digest = rpmDigestInit((int)algorithm, RPMDIGEST_NONE);
    if (digest == NULL) return -1;
    uint8_t buffer[65536];
    off_t cursor = offset;
    int result = 0;
    while (cursor < metadata.st_size) {
        size_t wanted = sizeof(buffer);
        if (metadata.st_size - cursor < (off_t)wanted)
            wanted = (size_t)(metadata.st_size - cursor);
        ssize_t count = pread(fd, buffer, wanted, cursor);
        if (count <= 0 || rpmDigestUpdate(digest, buffer, (size_t)count) != 0) {
            result = -1; break;
        }
        cursor += count;
    }
    void *actual = NULL;
    size_t actual_len = 0;
    if (rpmDigestFinal(digest, &actual, &actual_len, 1) != 0 || actual == NULL)
        result = -1;
    else {
        if (actual_len > 0 && ((char *)actual)[actual_len - 1] == '\0') --actual_len;
        if (strlen(expected) != actual_len || strncasecmp(expected, actual,
             actual_len) != 0) result = -1;
    }
    free(actual);
    return result;
}
#endif
