#include "internal.h"

#include <stdlib.h>
#include <string.h>

#ifdef DNFAST_NATIVE_REAL
#include <rpm/header.h>
#include <rpm/rpmio.h>
#include <rpm/rpmkeyring.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmtag.h>
#include <unistd.h>

static int copy_text(char *out, size_t capacity, const char *value) {
    if (value == NULL || strlen(value) >= capacity) return -1;
    memcpy(out, value, strlen(value) + 1);
    return 0;
}

static int copy_optional_text(char *out, size_t capacity, const char *value) {
    if (value == NULL) {
        out[0] = '\0';
        return 0;
    }
    return copy_text(out, capacity, value);
}

#endif

dnfast_status dnfast_keyring_open(const dnfast_key_blob *keys, size_t count,
                                  dnfast_keyring **output,
                                  dnfast_error *error) {
    if (keys == NULL || count == 0 || output == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmKeyringNew", "invalid key bundle");
    *output = NULL;
#ifdef DNFAST_NATIVE_REAL
    dnfast_keyring *ring = calloc(1, sizeof(*ring));
    if (ring == NULL || (ring->value = rpmKeyringNew()) == NULL) {
        free(ring);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmKeyringNew", "keyring allocation failed");
    }
    for (size_t index = 0; index < count; ++index) {
        int imported = keys[index].data == NULL || keys[index].length == 0
            ? -1 : dnfast_keyring_import_armor(ring, &keys[index]);
        if (imported != 0) {
            char message[64];
            snprintf(message, sizeof(message), "certificate import failed at %d", imported);
            dnfast_keyring_free(ring);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "rpm", "pgpParsePkts", message);
        }
    }
    *output = ring;
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmKeyringNew", "real native build disabled");
#endif
}

dnfast_status dnfast_keyring_fixture_open(dnfast_keyring **output,
                                          dnfast_error *error) {
    if (output == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmKeyringNew", "null keyring output");
    *output = NULL;
#ifdef DNFAST_NATIVE_REAL
    dnfast_keyring *ring = calloc(1, sizeof(*ring));
    if (ring == NULL || (ring->value = rpmKeyringNew()) == NULL) {
        free(ring);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmKeyringNew", "RPM keyring creation failed");
    }
    *output = ring;
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmKeyringNew", "real native build disabled");
#endif
}

dnfast_status dnfast_keyring_verify_fd(dnfast_keyring *ring, int raw_fd,
                                       dnfast_verified_package *package,
                                       dnfast_error *error) {
    if (ring == NULL || raw_fd < 0 || package == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmReadPackageFile", "invalid verifier input");
#ifdef DNFAST_NATIVE_REAL
    memset(package, 0, sizeof(*package));
    rpmts ts = rpmtsCreate();
    Header header = NULL;
    FD_t fd = NULL;
    char read_message[64];
    const char *failure_message = "verifier setup failed";
    if (ts == NULL || rpmtsSetKeyring(ts, ring->value) != 0) goto failure;
    rpmtsSetVSFlags(ts, RPMVSF_NEEDPAYLOAD);
    rpmtsSetVfyFlags(ts, RPMVSF_NEEDPAYLOAD);
    rpmtsSetVfyLevel(ts, RPMSIG_VERIFIABLE_TYPE);
    fd = fdDup(raw_fd);
    if (fd == NULL || Fseek(fd, 0, SEEK_SET) < 0) {
        failure_message = "retained fd duplication failed";
        goto failure;
    }
    rpmRC read_result = rpmReadPackageFile(ts, fd, "<dnfast-retained-fd>", &header);
    if (read_result != RPMRC_OK) {
        snprintf(read_message, sizeof(read_message), "rpm verification result %d",
                 (int)read_result);
        failure_message = read_message;
        goto failure;
    }
    if (dnfast_verify_payload_digest(raw_fd, header) != 0) {
        failure_message = "compressed payload digest verification failed";
        goto failure;
    }
    const dnfast_signer_identity *signer = dnfast_keyring_find_signer(ring, header);
    if (signer == NULL) signer = dnfast_keyring_find_fd_signer(ring, raw_fd);
    char epoch[32];
    snprintf(epoch, sizeof(epoch), "%llu",
             (unsigned long long)headerGetNumber(header, RPMTAG_EPOCHNUM));
    if (signer == NULL) {
        failure_message = "verified signature issuer was not attributed";
        goto failure;
    }
    if (copy_text(package->name, sizeof(package->name),
            headerGetString(header, RPMTAG_NAME)) != 0 ||
        copy_text(package->epoch, sizeof(package->epoch), epoch) != 0 ||
        copy_text(package->version, sizeof(package->version),
            headerGetString(header, RPMTAG_VERSION)) != 0 ||
        copy_text(package->release, sizeof(package->release),
            headerGetString(header, RPMTAG_RELEASE)) != 0 ||
        copy_text(package->arch, sizeof(package->arch),
            headerGetString(header, RPMTAG_ARCH)) != 0 ||
        copy_optional_text(package->vendor, sizeof(package->vendor),
            headerGetString(header, RPMTAG_VENDOR)) != 0) {
        failure_message = "verified header field invalid";
        goto failure;
    }
    memcpy(package->primary_fingerprint, signer->primary, 41);
    memcpy(package->signing_fingerprint, signer->signing, 41);
    header = headerFree(header);
    if (fd != NULL) Fclose(fd);
    ts = rpmtsFree(ts);
    return DNFAST_STATUS_OK;
failure:
    header = headerFree(header);
    if (fd != NULL) Fclose(fd);
    ts = rpmtsFree(ts);
    return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                            "rpm", "rpmReadPackageFile", failure_message);
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmReadPackageFile", "real native build disabled");
#endif
}

void dnfast_keyring_free(dnfast_keyring *ring) {
    if (ring == NULL) return;
#ifdef DNFAST_NATIVE_REAL
    ring->value = rpmKeyringFree(ring->value);
    free(ring->identities);
#endif
    free(ring);
}
