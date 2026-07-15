#include "dnfast_native.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct probe_state {
    unsigned calls;
    dnfast_status result;
} probe_state;

static dnfast_status interrupt(void *user_data) {
    probe_state *state = user_data;
    ++state->calls;
    return state->result;
}

static int fail(const char *message, dnfast_error *error, dnfast_context *context) {
    fprintf(stderr, "%s: status=%d component=%s symbol=%s message=%s\n", message,
            error->status, error->component == NULL ? "" : error->component,
            error->symbol == NULL ? "" : error->symbol,
            error->message == NULL ? "" : error->message);
    dnfast_context_free(context);
    dnfast_error_free(error);
    return 1;
}

int main(int argc, char **argv) {
    dnfast_limits limits = dnfast_limits_default();
    limits.pool_architecture = DNFAST_POOL_ARCHITECTURE_AARCH64;
    probe_state state = {0, DNFAST_STATUS_OK};
    dnfast_callbacks callbacks = {DNFAST_NATIVE_ABI_VERSION, &state, interrupt, NULL};
    dnfast_context *context = NULL;
    dnfast_error error = {0};
    dnfast_status status;
    size_t allocations_before = dnfast_context_allocation_count();
    if (argc != 2) {
        return 2;
    }
    if (strcmp(argv[1], "malformed") == 0) {
        limits.abi_version = UINT32_C(999);
    } else if (strcmp(argv[1], "abi1") == 0) {
        callbacks.abi_version = UINT32_C(1);
    }
    status = dnfast_context_open(&limits, &callbacks, &context, &error);
    if (strcmp(argv[1], "abi1") == 0) {
        int correct = status == DNFAST_STATUS_UNSUPPORTED_ABI && context == NULL &&
                      dnfast_context_allocation_count() == allocations_before;
        dnfast_error_free(&error);
        return correct ? 0 : 1;
    }
    if (strcmp(argv[1], "unsupported") == 0) {
        int correct = status == DNFAST_STATUS_UNSUPPORTED_ABI && context == NULL &&
                      error.component != NULL && strcmp(error.component, "rpm") == 0 &&
                      error.symbol != NULL && strcmp(error.symbol, "rpmtsRun") == 0;
        dnfast_error_free(&error);
        return correct ? 0 : 1;
    }
    if (strcmp(argv[1], "missing_queue") == 0) {
        int correct = status == DNFAST_STATUS_UNSUPPORTED_ABI && context == NULL &&
                      dnfast_context_allocation_count() == 0 &&
                      error.component != NULL && strcmp(error.component, "solv") == 0 &&
                      error.symbol != NULL && strcmp(error.symbol, "queue_init") == 0;
        dnfast_error_free(&error);
        return correct ? 0 : 1;
    }
    if (strcmp(argv[1], "stale") == 0 || strcmp(argv[1], "malformed") == 0) {
        int correct = status == DNFAST_STATUS_UNSUPPORTED_ABI && context == NULL;
        dnfast_error_free(&error);
        return correct ? 0 : 1;
    }
    if (status != DNFAST_STATUS_OK || context == NULL) {
        return fail("open failed", &error, context);
    }
    if (strcmp(argv[1], "interrupt") == 0) {
        state.result = DNFAST_STATUS_INTERRUPTED;
        status = dnfast_context_check(context, &error);
        if (status != DNFAST_STATUS_INTERRUPTED || state.calls != 1) {
            return fail("interrupt contract failed", &error, context);
        }
    } else if (strcmp(argv[1], "misleading") == 0) {
        state.result = DNFAST_STATUS_NATIVE_FAILURE;
        status = dnfast_context_check(context, &error);
        if (status != DNFAST_STATUS_CALLBACK_FAILED) {
            return fail("invalid callback success accepted", &error, context);
        }
    } else if (strcmp(argv[1], "happy") != 0) {
        return fail("unknown scenario", &error, context);
    }
    dnfast_context_free(context);
    dnfast_error_free(&error);
    return 0;
}
