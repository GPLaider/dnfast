#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#ifdef DNFAST_NATIVE_REAL
#include <rpm/rpmtag.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNFAST_LEAD_SIZE 96
#define DNFAST_HEADER_SIZE 16
#define DNFAST_MAX_SIG_INDEX 4096
#define DNFAST_MAX_SIG_DATA (16 * 1024 * 1024)

static uint32_t be32(const uint8_t *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | value[3];
}

const dnfast_signer_identity *dnfast_keyring_find_fd_signer(
    const dnfast_keyring *ring, int fd) {
    uint8_t intro[DNFAST_HEADER_SIZE];
    if (pread(fd, intro, sizeof(intro), DNFAST_LEAD_SIZE) != sizeof(intro) ||
        intro[0] != 0x8e || intro[1] != 0xad || intro[2] != 0xe8 ||
        intro[3] != 1) return NULL;
    uint32_t index_count = be32(intro + 8);
    uint32_t data_size = be32(intro + 12);
    if (index_count == 0 || index_count > DNFAST_MAX_SIG_INDEX ||
        data_size == 0 || data_size > DNFAST_MAX_SIG_DATA) return NULL;
    size_t index_bytes = (size_t)index_count * 16;
    if (index_bytes > SIZE_MAX - data_size) return NULL;
    size_t total = index_bytes + data_size;
    uint8_t *contents = malloc(total);
    if (contents == NULL || pread(fd, contents, total,
            DNFAST_LEAD_SIZE + DNFAST_HEADER_SIZE) != (ssize_t)total) {
        free(contents); return NULL;
    }
    const dnfast_signer_identity *found = NULL;
    for (uint32_t index = 0; found == NULL && index < index_count; ++index) {
        const uint8_t *entry = contents + (size_t)index * 16;
        uint32_t tag = be32(entry);
        uint32_t type = be32(entry + 4);
        uint32_t offset = be32(entry + 8);
        uint32_t count = be32(entry + 12);
        if ((tag == RPMTAG_RSAHEADER || tag == RPMTAG_DSAHEADER) && type == 7 &&
            offset <= data_size && count <= data_size - offset) {
            found = dnfast_keyring_find_packet_signer(
                ring, contents + index_bytes + offset, count);
            continue;
        }
        if (tag != RPMTAG_OPENPGP || offset >= data_size) continue;
        const char *encoded = (const char *)(contents + index_bytes + offset);
        size_t available = data_size - offset;
        if (memchr(encoded, '\0', available) == NULL) continue;
        found = dnfast_keyring_find_encoded_signer(ring, encoded);
    }
    free(contents);
    return found;
}
#endif
