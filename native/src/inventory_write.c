#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>

static _Atomic uint64_t global_test_count;
static _Atomic uint64_t global_real_count;

dnfast_status dnfast_inventory_write_begin(dnfast_context *context,
                                           dnfast_keyring *keyring,
                                           const char *root,
                                           uint64_t timeout_milliseconds,
                                           dnfast_error *error) {
    if (context == NULL || keyring == NULL || root == NULL || strcmp(root, "/") != 0)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpmdb", NULL, "write root must be /");
    if (!pthread_equal(context->owner, pthread_self()))
        return dnfast_set_error(error, DNFAST_STATUS_WRONG_THREAD,
                                "rpmdb", NULL, "wrong owner thread");
    if (geteuid() != 0)
        return dnfast_set_error(error, DNFAST_STATUS_PERMISSION_DENIED,
                                "rpmdb", "geteuid", "root execution required");
#ifdef DNFAST_NATIVE_REAL
    if (context->inventory_write_ts != NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpmdb", NULL, "write context already active");
    dnfast_status status = dnfast_inventory_prepare_rpm(error);
    if (status != DNFAST_STATUS_OK) return status;
    rpmts ts = rpmtsCreate();
    if (ts == NULL || rpmtsSetRootDir(ts, root) != 0) {
        rpmtsFree(ts);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmtsCreate", "write context failed");
    }
    if (keyring->value == NULL || rpmtsSetKeyring(ts, keyring->value) != 0) {
        rpmtsFree(ts);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmtsSetKeyring", "isolated keyring rejected");
    }
    context->inventory_keyring_sequence = 1;
    struct timespec started;
    (void)clock_gettime(CLOCK_MONOTONIC, &started);
    rpmtxn txn = NULL;
    do {
        txn = rpmtxnBegin(ts, RPMTXN_WRITE);
        if (txn != NULL) break;
        status = dnfast_callback_check(&context->callbacks, error);
        if (status != DNFAST_STATUS_OK) {
            rpmtsFree(ts);
            return status;
        }
        struct timespec now;
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t start_ns = (uint64_t)started.tv_sec * UINT64_C(1000000000) + (uint64_t)started.tv_nsec;
        uint64_t now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
        uint64_t elapsed = (now_ns - start_ns) / UINT64_C(1000000);
        if (elapsed >= timeout_milliseconds) break;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    } while (txn == NULL);
    if (txn == NULL) {
        rpmtsFree(ts);
        return dnfast_set_error(error, DNFAST_STATUS_LOCK_TIMEOUT,
                                "rpm", "rpmtxnBegin", "rpmdb write lock failed");
    }
    context->transaction_keyring = rpmKeyringLink(keyring->value);
    if (context->transaction_keyring == NULL) {
        rpmtxnEnd(txn);
        rpmtsFree(ts);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmKeyringLink", "isolated keyring retention failed");
    }
    context->transaction_identity_keyring = keyring;
    context->inventory_write_ts = ts;
    context->inventory_write_txn = txn;
    context->inventory_rpmdb_sequence = 2;
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtxnBegin", "real native build disabled");
#endif
}

dnfast_status dnfast_inventory_read_locked(dnfast_context *context,
                                           dnfast_error *error) {
#ifdef DNFAST_NATIVE_REAL
    if (context == NULL || context->inventory_write_ts == NULL ||
        context->inventory_write_txn == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpmdb", NULL, "write context is not active");
    return dnfast_inventory_collect(context, context->inventory_write_ts, error);
#else
    (void)context;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtxnBegin", "real native build disabled");
#endif
}

void dnfast_inventory_write_end(dnfast_context *context) {
    if (context == NULL) return;
#ifdef DNFAST_NATIVE_REAL
    dnfast_transaction_clear(context);
    if (context->inventory_write_txn != NULL)
        context->inventory_write_txn = rpmtxnEnd(context->inventory_write_txn);
    if (context->inventory_write_ts != NULL)
        context->inventory_write_ts = rpmtsFree(context->inventory_write_ts);
    if (context->transaction_keyring != NULL)
        context->transaction_keyring = rpmKeyringFree(context->transaction_keyring);
    context->transaction_identity_keyring = NULL;
#endif
}

uint64_t dnfast_inventory_rpm_run_count(const dnfast_context *context) {
    return context == NULL ? 0 : context->inventory_rpm_run_count;
}

dnfast_status dnfast_inventory_test_run(dnfast_context *context,
                                        int32_t *rpm_result,
                                        dnfast_error *error) {
    if (context == NULL || rpm_result == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmtsRun", "invalid TEST context");
#ifdef DNFAST_NATIVE_REAL
    if (context->inventory_write_ts == NULL || context->inventory_write_txn == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmtsRun", "write context is not active");
    rpmtransFlags previous = rpmtsFlags(context->inventory_write_ts);
    (void)rpmtsSetFlags(context->inventory_write_ts, previous | RPMTRANS_FLAG_TEST);
    context->inventory_rpm_run_count++;
    context->inventory_test_count++;
    (void)atomic_fetch_add(&global_test_count, UINT64_C(1));
    *rpm_result = rpmtsRun(context->inventory_write_ts, NULL, 0);
    if (context->inventory_fail_next_test != 0) {
        context->inventory_fail_next_test = 0;
        *rpm_result = -99;
    }
    (void)rpmtsSetFlags(context->inventory_write_ts, previous);
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtsRun", "real native build disabled");
#endif
}

dnfast_status dnfast_inventory_run(dnfast_context *context,
                                   int32_t *rpm_result,
                                   dnfast_error *error) {
    if (context == NULL || rpm_result == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmtsRun", "invalid run context");
#ifdef DNFAST_NATIVE_REAL
    if (context->inventory_write_ts == NULL || context->inventory_write_txn == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmtsRun", "write context is not active");
    context->inventory_rpm_run_count++;
    context->inventory_real_count++;
    (void)atomic_fetch_add(&global_real_count, UINT64_C(1));
    *rpm_result = rpmtsRun(context->inventory_write_ts, NULL, 0);
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtsRun", "real native build disabled");
#endif
}

uint64_t dnfast_inventory_test_count(const dnfast_context *context) {
    return context == NULL ? 0 : context->inventory_test_count;
}

uint64_t dnfast_inventory_real_count(const dnfast_context *context) {
    return context == NULL ? 0 : context->inventory_real_count;
}

void dnfast_inventory_fixture_fail_next_test(dnfast_context *context) {
    if (context != NULL) context->inventory_fail_next_test = 1;
}

void dnfast_inventory_fixture_reset_global_counts(void) {
    atomic_store(&global_test_count, UINT64_C(0));
    atomic_store(&global_real_count, UINT64_C(0));
}

uint64_t dnfast_inventory_fixture_global_test_count(void) {
    return atomic_load(&global_test_count);
}

uint64_t dnfast_inventory_fixture_global_real_count(void) {
    return atomic_load(&global_real_count);
}

uint64_t dnfast_inventory_keyring_sequence(const dnfast_context *context) {
    return context == NULL ? 0 : context->inventory_keyring_sequence;
}

uint64_t dnfast_inventory_rpmdb_sequence(const dnfast_context *context) {
    return context == NULL ? 0 : context->inventory_rpmdb_sequence;
}
