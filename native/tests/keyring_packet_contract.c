#include "internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char allowed[] = "71E503D1200A69E8AFEF7AE220CB5C5EE7605F7D";

static size_t hex_bytes(const char *hex, uint8_t out[20]) {
    for (size_t index = 0; index < 20; ++index) {
        unsigned high = hex[index * 2] <= '9' ? hex[index * 2] - '0' : hex[index * 2] - 'A' + 10;
        unsigned low = hex[index * 2 + 1] <= '9' ? hex[index * 2 + 1] - '0' : hex[index * 2 + 1] - 'A' + 10;
        out[index] = (uint8_t)((high << 4) | low);
    }
    return 20;
}

static size_t signature(uint8_t out[128], unsigned type, int hashed,
                        int duplicate) {
    uint8_t fingerprint[20];
    hex_bytes(allowed, fingerprint);
    size_t hashed_len = hashed ? 23U * (duplicate ? 2U : 1U) : 0;
    size_t body_len = 6 + hashed_len + (hashed ? 2 : 25) + 2;
    out[0] = 0x88;
    out[1] = (uint8_t)body_len;
    uint8_t *body = out + 2;
    body[0] = 4; body[1] = 0; body[2] = 22; body[3] = 10;
    body[4] = (uint8_t)(hashed_len >> 8); body[5] = (uint8_t)hashed_len;
    size_t cursor = 6;
    for (int copy = 0; copy < (hashed ? (duplicate ? 2 : 1) : 0); ++copy) {
        body[cursor++] = 22; body[cursor++] = (uint8_t)type;
        body[cursor++] = 4; memcpy(body + cursor, fingerprint, 20); cursor += 20;
    }
    size_t unhashed_len = hashed ? 0 : 23;
    body[cursor++] = 0; body[cursor++] = (uint8_t)unhashed_len;
    if (!hashed) {
        body[cursor++] = 22; body[cursor++] = 33; body[cursor++] = 4;
        memcpy(body + cursor, fingerprint, 20); cursor += 20;
    }
    body[cursor++] = 0; body[cursor++] = 0;
    return cursor + 2;
}

int main(void) {
    dnfast_signer_identity identities[2] = {0};
    memcpy(identities[0].key_id, "20CB5C5EE7605F7D", 17);
    memcpy(identities[0].signing, allowed, 41);
    memcpy(identities[1].key_id, "20CB5C5EE7605F7D", 17);
    memcpy(identities[1].signing, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 41);
    dnfast_keyring ring = {.value = NULL, .identities = identities, .identity_count = 2};
    uint8_t packet[128];
    size_t length = signature(packet, 33, 1, 0);
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length) == &identities[0]);
    packet[0] = 0xc2;
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length) == &identities[0]);
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length - 1) == NULL);
    length = signature(packet, 33, 0, 0);
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length) == NULL);
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length - 1) == NULL);
    length = signature(packet, 20, 1, 0);
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length) == NULL);
    length = signature(packet, 33, 1, 1);
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length) == NULL);
    packet[34] ^= 1;
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length) == NULL);
    puts("assert conflicting-type33-full-fingerprints=true");
    length = signature(packet, 33, 1, 0);
    packet[length] = 0;
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length + 1) == NULL);
    identities[1].signing[0] = '7';
    memcpy(identities[1].signing, allowed, 41);
    length = signature(packet, 33, 1, 0);
    assert(dnfast_keyring_find_packet_signer(&ring, packet, length) == NULL);
    puts("assert same-short-id-distinct-full-fingerprints=true");
    return 0;
}
