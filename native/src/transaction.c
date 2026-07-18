#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef DNFAST_NATIVE_REAL
#include <rpm/rpmcrypto.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmpgp.h>

static int same_package(const dnfast_verified_package *left,
                        const dnfast_verified_package *right) {
    return strcmp(left->name, right->name) == 0 &&
        strcmp(left->epoch, right->epoch) == 0 &&
        strcmp(left->version, right->version) == 0 &&
        strcmp(left->release, right->release) == 0 &&
        strcmp(left->arch, right->arch) == 0 &&
        strcmp(left->vendor, right->vendor) == 0 &&
        strcmp(left->primary_fingerprint, right->primary_fingerprint) == 0 &&
        strcmp(left->signing_fingerprint, right->signing_fingerprint) == 0;
}

static int artifact_digest(int fd, uint8_t output[32], uint64_t *size) {
    DIGEST_CTX digest = rpmDigestInit(PGPHASHALGO_SHA256, RPMDIGEST_NONE);
    uint8_t buffer[64 * 1024];
    off_t offset = 0;
    void *result = NULL;
    size_t result_size = 0;
    if (digest == NULL) return -1;
    for (;;) {
        ssize_t count = pread(fd, buffer, sizeof(buffer), offset);
        if (count < 0 || (count > 0 && rpmDigestUpdate(digest, buffer, (size_t)count) != 0))
            goto failure;
        if (count == 0) break;
        offset += count;
    }
    if (rpmDigestFinal(digest, &result, &result_size, 0) != 0 || result_size != 32)
        goto failure_finalized;
    memcpy(output, result, 32);
    *size = (uint64_t)offset;
    free(result);
    return 0;
failure:
    (void)rpmDigestFinal(digest, &result, &result_size, 0);
failure_finalized:
    free(result);
    return -1;
}

int dnfast_transaction_reverify(dnfast_context *context,
                                dnfast_transaction_item *item) {
    struct stat current;
    uint8_t digest[32];
    uint64_t size = 0;
    dnfast_verified_package actual;
    return context == NULL || item == NULL || item->erase ||
        context->transaction_identity_keyring == NULL ||
        fstat(item->retained_fd, &current) != 0 || current.st_dev != item->device ||
        current.st_ino != item->inode || artifact_digest(item->retained_fd, digest, &size) != 0 ||
        size != item->expected.artifact_size ||
        memcmp(digest, item->expected.artifact_sha256, 32) != 0 ||
        dnfast_keyring_verify_fd(context->transaction_identity_keyring,
            item->retained_fd, &actual, NULL) != DNFAST_STATUS_OK ||
        !same_package(&actual, &item->expected.package);
}

static int retain_fd(int raw_fd, dnfast_transaction_item *item) {
    struct stat value;
    if (fstat(raw_fd, &value) != 0 || !S_ISREG(value.st_mode) ||
        value.st_uid != 0 || value.st_nlink != 1 ||
        (value.st_mode & (S_IWGRP | S_IWOTH)) != 0) return -1;
    item->retained_fd = fcntl(raw_fd, F_DUPFD_CLOEXEC, 3);
    if (item->retained_fd < 0) return -1;
    item->device = value.st_dev;
    item->inode = value.st_ino;
    return 0;
}

static dnfast_status append_item(dnfast_context *context,
                                 dnfast_transaction_item *item,
                                 dnfast_error *error) {
    if (context->transaction_item_count >= context->limits.max_packages)
        return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                "rpm", "transaction", "action limit exceeded");
    size_t count = context->transaction_item_count + 1;
    void *grown = realloc(context->transaction_items,
                          count * sizeof(*context->transaction_items));
    if (grown == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "realloc", "transaction allocation failed");
    context->transaction_items = grown;
    context->transaction_items[context->transaction_item_count] = item;
    context->transaction_item_count = count;
    return DNFAST_STATUS_OK;
}
#endif

dnfast_status dnfast_transaction_add_install(
    dnfast_context *context, dnfast_keyring *keyring, int retained_fd,
    const dnfast_transaction_install *expected,
    dnfast_error *error) {
    if (context == NULL || keyring == NULL || retained_fd < 0 ||
        expected == NULL || expected->upgrade > 3)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "transaction", "invalid install action");
#ifdef DNFAST_NATIVE_REAL
    if (context->inventory_write_txn == NULL ||
        context->transaction_phase != DNFAST_TRANSACTION_PREFLIGHT ||
        keyring->value != context->transaction_keyring)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "transaction", "transaction is not mutable");
    dnfast_transaction_item *item = calloc(1, sizeof(*item));
    dnfast_verified_package actual;
    if (item != NULL) item->retained_fd = -1;
    if (item == NULL || retain_fd(retained_fd, item) != 0) goto failure;
    dnfast_status status = dnfast_keyring_verify_fd(keyring, item->retained_fd,
                                                    &actual, error);
    if (status != DNFAST_STATUS_OK) { close(item->retained_fd); free(item); return status; }
    if (!same_package(&actual, &expected->package)) goto failure;
    item->expected = *expected;
    if (dnfast_transaction_reverify(context, item) != 0) goto failure;
    status = append_item(context, item, error);
    if (status == DNFAST_STATUS_OK) return status;
    close(item->retained_fd); free(item); return status;
failure:
    if (item != NULL && item->retained_fd >= 0) close(item->retained_fd);
    free(item);
    return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                            "rpm", "rpmReadPackageFile", "retained RPM identity changed");
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtsAddInstallElement", "real native build disabled");
#endif
}

dnfast_status dnfast_transaction_add_erase(
    dnfast_context *context, uint64_t db_instance,
    const uint8_t header_sha256[32], dnfast_error *error) {
    if (context == NULL || db_instance == 0 || db_instance > UINT32_MAX ||
        header_sha256 == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "transaction", "invalid erase action");
#ifdef DNFAST_NATIVE_REAL
    if (context->inventory_write_txn == NULL ||
        context->transaction_phase != DNFAST_TRANSACTION_PREFLIGHT)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "transaction", "transaction is not mutable");
    dnfast_transaction_item *item = calloc(1, sizeof(*item));
    if (item == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "calloc", "transaction allocation failed");
    item->retained_fd = -1;
    item->erase = 1;
    item->db_instance = (uint32_t)db_instance;
    memcpy(item->header_sha256, header_sha256, 32);
    dnfast_status status = append_item(context, item, error);
    if (status != DNFAST_STATUS_OK) free(item);
    return status;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtsAddEraseElement", "real native build disabled");
#endif
}

void dnfast_transaction_clear(dnfast_context *context) {
    if (context == NULL) return;
#ifdef DNFAST_NATIVE_REAL
    for (size_t index = 0; index < context->transaction_item_count; ++index) {
        dnfast_transaction_item *item = context->transaction_items[index];
        if (item->active_fd != NULL) { Fclose(item->active_fd); item->active_fd = NULL; }
        if (item->retained_fd >= 0) close(item->retained_fd);
        free(item);
    }
    for (size_t index = 0; index < context->transaction_problem_count; ++index)
        free(context->transaction_problems[index]);
    free(context->transaction_items);
    free(context->transaction_problems);
    context->transaction_items = NULL;
    context->transaction_item_count = 0;
    context->transaction_problems = NULL;
    context->transaction_problem_count = 0;
#endif
}
