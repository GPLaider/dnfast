#include "internal.h"

dnfast_status dnfast_transaction_verify_db(dnfast_context *context, dnfast_error *error) {
#ifdef DNFAST_NATIVE_REAL
    if (context == NULL || context->transaction_phase != DNFAST_TRANSACTION_STARTED)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "rpmtsVerifyDB", "real run has not started");
    rpmts ts = rpmtsCreate();
    int failed = context->transaction_fail_callback == 6 || ts == NULL || rpmtsSetRootDir(ts, "/") != 0 ||
        rpmtsSetKeyring(ts, context->transaction_keyring) != 0 || rpmtsVerifyDB(ts) != 0;
    rpmtsFree(ts);
    return failed ? dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
        "rpm", "rpmtsVerifyDB", "rpmdb verification failed") : DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtsVerifyDB", "real native build disabled");
#endif
}

size_t dnfast_transaction_problem_count(const dnfast_context *context) {
#ifdef DNFAST_NATIVE_REAL
    return context == NULL ? 0 : context->transaction_problem_count;
#else
    (void)context; return 0;
#endif
}

const char *dnfast_transaction_problem(const dnfast_context *context, size_t index) {
#ifdef DNFAST_NATIVE_REAL
    return context == NULL || index >= context->transaction_problem_count
        ? NULL : context->transaction_problems[index];
#else
    (void)context; (void)index; return NULL;
#endif
}

dnfast_transaction_counts dnfast_transaction_get_counts(const dnfast_context *context) {
    dnfast_transaction_counts empty = {0};
#ifdef DNFAST_NATIVE_REAL
    return context == NULL ? empty : context->transaction_counts;
#else
    (void)context; return empty;
#endif
}

dnfast_transaction_phase dnfast_transaction_get_phase(const dnfast_context *context) {
#ifdef DNFAST_NATIVE_REAL
    return context == NULL ? DNFAST_TRANSACTION_PREFLIGHT : context->transaction_phase;
#else
    (void)context; return DNFAST_TRANSACTION_PREFLIGHT;
#endif
}

void dnfast_transaction_fixture_fail_callback(dnfast_context *context, uint8_t point) {
#ifdef DNFAST_NATIVE_REAL
    if (context != NULL && point >= 1 && point <= 7)
        context->transaction_fail_callback = point;
#else
    (void)context; (void)point;
#endif
}
