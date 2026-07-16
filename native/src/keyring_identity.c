#include "internal.h"

#ifdef DNFAST_NATIVE_REAL
#include <rpm/header.h>
#include <rpm/rpmbase64.h>
#include <rpm/rpmcrypto.h>
#include <rpm/rpmkeyring.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmtd.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static void hex_upper(const uint8_t *bytes, size_t count, char *out) {
    static const char alphabet[] = "0123456789ABCDEF";
    for (size_t index = 0; index < count; ++index) {
        out[index * 2] = alphabet[bytes[index] >> 4]; out[index * 2 + 1] = alphabet[bytes[index] & 15];
    }
    out[count * 2] = '\0';
}

static int packet_span(const uint8_t *data, size_t available, unsigned *tag,
                       size_t *header_size, size_t *body_size);

static int subpacket_span(const uint8_t *data, size_t available,
                          size_t *header_size, size_t *body_size) {
    if (available == 0) return -1;
    if (data[0] < 192) { *header_size = 1; *body_size = data[0]; }
    else if (data[0] < 255 && available >= 2) {
        *header_size = 2;
        *body_size = ((size_t)data[0] - 192) * 256 + data[1] + 192;
    } else if (data[0] == 255 && available >= 5) {
        *header_size = 5;
        *body_size = ((size_t)data[1] << 24) | ((size_t)data[2] << 16) |
            ((size_t)data[3] << 8) | data[4];
    } else return -1;
    return *body_size <= available - *header_size && *body_size > 0 ? 0 : -1;
}

const dnfast_signer_identity *dnfast_keyring_find_packet_signer(
    const dnfast_keyring *ring, const uint8_t *packet, size_t packet_len) {
    unsigned tag = 0;
    size_t header_size = 0;
    size_t body_size = 0;
    if (packet_span(packet, packet_len, &tag, &header_size, &body_size) != 0 ||
        header_size + body_size != packet_len || tag != PGPTAG_SIGNATURE ||
        body_size < 6 || packet[header_size] != 4)
        return NULL;
    const uint8_t *body = packet + header_size;
    size_t hashed_len = ((size_t)body[4] << 8) | body[5];
    if (hashed_len > body_size - 6) return NULL;
    const uint8_t *fingerprint = NULL; size_t cursor = 0;
    while (cursor < hashed_len) {
        size_t sub_header = 0;
        size_t sub_body = 0;
        if (subpacket_span(body + 6 + cursor, hashed_len - cursor,
                           &sub_header, &sub_body) != 0) return NULL;
        const uint8_t *subpacket = body + 6 + cursor + sub_header;
        unsigned subpacket_type = subpacket[0] & 0x7f;
        if (subpacket_type == 33) {
            if (fingerprint != NULL || sub_body != 22 || subpacket[1] != 4)
                return NULL;
            fingerprint = subpacket + 2;
        }
        cursor += sub_header + sub_body;
    }
    if (fingerprint == NULL) return NULL;
    const dnfast_signer_identity *found = NULL;
    for (size_t item = 0; item < ring->identity_count; ++item) {
        char fingerprint_hex[41];
        hex_upper(fingerprint, 20, fingerprint_hex);
        if (strcmp(fingerprint_hex, ring->identities[item].signing) == 0) {
            if (found != NULL) return NULL;
            found = &ring->identities[item];
        }
    }
    return found;
}

static int add_identity(dnfast_keyring *ring, rpmPubkey primary,
                        rpmPubkey signing, const char *signing_fp) {
    const char *primary_fp = rpmPubkeyFingerprintAsHex(primary);
    const char *key_id = rpmPubkeyKeyIDAsHex(signing);
    if (primary_fp == NULL || key_id == NULL || strlen(primary_fp) != 40 ||
        strlen(key_id) != 16 || signing_fp == NULL || strlen(signing_fp) != 40)
        return -1;
    dnfast_signer_identity *next = realloc(
        ring->identities, (ring->identity_count + 1) * sizeof(*next));
    if (next == NULL) return -1;
    ring->identities = next;
    dnfast_signer_identity *item = &next[ring->identity_count++];
    for (size_t index = 0; index < 16; ++index)
        item->key_id[index] = (char)toupper((unsigned char)key_id[index]);
    item->key_id[16] = '\0';
    for (size_t index = 0; index < 40; ++index)
        item->primary[index] = (char)toupper((unsigned char)primary_fp[index]);
    item->primary[40] = '\0';
    for (size_t index = 0; index < 40; ++index)
        item->signing[index] = (char)toupper((unsigned char)signing_fp[index]);
    item->signing[40] = '\0';
    return 0;
}

static int packet_span(const uint8_t *data, size_t available, unsigned *tag,
                       size_t *header_size, size_t *body_size) {
    if (available < 2 || (data[0] & 0x80) == 0) return -1;
    size_t header = 0, body = 0;
    if ((data[0] & 0x40) != 0) {
        *tag = data[0] & 0x3f;
        if (data[1] < 192) { header = 2; body = data[1]; }
        else if (data[1] < 224 && available >= 3) {
            header = 3; body = ((size_t)data[1] - 192) * 256 + data[2] + 192;
        } else if (data[1] == 255 && available >= 6) {
            header = 6;
            body = ((size_t)data[2] << 24) | ((size_t)data[3] << 16) |
                   ((size_t)data[4] << 8) | data[5];
        } else return -1;
    } else {
        *tag = (data[0] >> 2) & 15;
        unsigned kind = data[0] & 3;
        if (kind == 0) { header = 2; body = data[1]; }
        else if (kind == 1 && available >= 3) {
            header = 3; body = ((size_t)data[1] << 8) | data[2];
        } else if (kind == 2 && available >= 5) {
            header = 5; body = ((size_t)data[1] << 24) |
                ((size_t)data[2] << 16) | ((size_t)data[3] << 8) | data[4];
        } else return -1;
    }
    if (body > available - header) return -1;
    *header_size = header;
    *body_size = body;
    return 0;
}

static int v4_fingerprint(const uint8_t *body, size_t body_len,
                          uint8_t **fingerprint, size_t *fingerprint_len) {
    if (body_len > 65535 || body_len == 0 || body[0] != 4) return -1;
    uint8_t prefix[3] = {0x99, (uint8_t)(body_len >> 8), (uint8_t)body_len};
    DIGEST_CTX digest = rpmDigestInit(PGPHASHALGO_SHA1, RPMDIGEST_NONE);
    if (digest == NULL) return -1;
    if (rpmDigestUpdate(digest, prefix, sizeof(prefix)) != 0 ||
        rpmDigestUpdate(digest, body, body_len) != 0) {
        void *discard = NULL;
        size_t discard_len = 0;
        rpmDigestFinal(digest, &discard, &discard_len, 0);
        free(discard);
        return -1;
    }
    return rpmDigestFinal(digest, (void **)fingerprint, fingerprint_len, 0);
}

static int subkey_fingerprint(const uint8_t *certificate, size_t length,
                              const char *key_id, char out[41]) {
    size_t offset = 0;
    while (offset < length) {
        unsigned tag = 0;
        size_t header_size = 0;
        size_t body_size = 0;
        if (packet_span(certificate + offset, length - offset, &tag,
                        &header_size, &body_size) != 0)
            return -1;
        if (tag == PGPTAG_PUBLIC_SUBKEY) {
            uint8_t *fingerprint = NULL;
            size_t fingerprint_len = 0;
            if (v4_fingerprint(certificate + offset + header_size, body_size,
                               &fingerprint, &fingerprint_len) == 0 &&
                fingerprint_len == 20) {
                char parsed_hex[17];
                hex_upper(fingerprint + 12, 8, parsed_hex);
                if (strcasecmp(parsed_hex, key_id) == 0) {
                    hex_upper(fingerprint, fingerprint_len, out);
                    free(fingerprint);
                    return 0;
                }
            }
            free(fingerprint);
        }
        offset += header_size + body_size;
    }
    return -1;
}

static int add_certificate(dnfast_keyring *ring, const uint8_t *packet,
                           size_t length) {
    char *lint = NULL;
    rpmRC lint_result = pgpPubKeyLint(packet, length, &lint);
    if (lint_result != RPMRC_OK || lint != NULL) {
        free(lint);
        return -29;
    }
    rpmPubkey primary = rpmPubkeyNew(packet, length);
    if (primary == NULL) return -30;
    int result = add_identity(ring, primary, primary,
                              rpmPubkeyFingerprintAsHex(primary));
    int count = 0;
    rpmPubkey *subkeys = rpmGetSubkeys(primary, &count);
    if (result != 0) result = -31;
    for (int index = 0; result == 0 && index < count; ++index) {
        char fingerprint[41];
        const char *key_id = rpmPubkeyKeyIDAsHex(subkeys[index]);
        if (key_id == NULL || subkey_fingerprint(packet, length, key_id,
                                                  fingerprint) != 0)
            result = -32;
        else result = add_identity(ring, primary, subkeys[index], fingerprint);
    }
    for (int index = 0; index < count; ++index)
        subkeys[index] = rpmPubkeyFree(subkeys[index]);
    free(subkeys);
    if (result == 0 && rpmKeyringAddKey(ring->value, primary) < 0) result = -33;
    primary = rpmPubkeyFree(primary);
    return result;
}

int dnfast_keyring_import_armor(dnfast_keyring *ring,
                                const dnfast_key_blob *blob) {
    char *armor = malloc(blob->length + 1);
    uint8_t *packets = NULL; size_t packet_len = 0;
    if (armor == NULL) return -10;
    memcpy(armor, blob->data, blob->length);
    armor[blob->length] = '\0';
    int kind = pgpParsePkts(armor, &packets, &packet_len);
    free(armor);
    if (kind != PGPARMOR_PUBKEY) { free(packets); return -11; }
    size_t offset = 0;
    while (offset < packet_len) {
        size_t certificate_len = 0;
        if (pgpPubKeyCertLen(packets + offset, packet_len - offset,
                             &certificate_len) != 0 || certificate_len == 0 ||
            certificate_len > packet_len - offset) {
            free(packets); return -20;
        }
        int added = add_certificate(ring, packets + offset, certificate_len);
        if (added != 0) { free(packets); return added; }
        offset += certificate_len;
    }
    free(packets);
    return 0;
}

const dnfast_signer_identity *dnfast_keyring_find_signer(
    const dnfast_keyring *ring, Header header) {
    struct rpmtd_s td = {0};
    if (!headerGet(header, RPMTAG_OPENPGP, &td, HEADERGET_DEFAULT)) return NULL;
    rpmtdInit(&td);
    const dnfast_signer_identity *found = NULL;
    const char *encoded = NULL;
    while (found == NULL && (encoded = rpmtdNextString(&td)) != NULL)
        found = dnfast_keyring_find_encoded_signer(ring, encoded);
    rpmtdFreeData(&td);
    return found;
}

const dnfast_signer_identity *dnfast_keyring_find_encoded_signer(
    const dnfast_keyring *ring, const char *encoded) {
    void *packet = NULL;
    size_t packet_len = 0;
    const dnfast_signer_identity *found = NULL;
    if (rpmBase64Decode(encoded, &packet, &packet_len) == 0 && packet != NULL)
        found = dnfast_keyring_find_packet_signer(ring, packet, packet_len);
    free(packet);
    return found;
}
#endif
