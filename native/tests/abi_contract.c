#include "dnfast_native.h"

#include <stdint.h>

static dnfast_status interrupt(void *user_data) {
    (void)user_data;
    return DNFAST_STATUS_INTERRUPTED;
}

int main(void) {
    dnfast_limits limits = dnfast_limits_default();
    limits.pool_architecture = DNFAST_POOL_ARCHITECTURE_AARCH64;
    dnfast_callbacks callbacks = {
        .abi_version = DNFAST_NATIVE_ABI_VERSION,
        .user_data = 0,
        .interrupt = interrupt,
        .transaction_start = NULL,
    };
    dnfast_context *context = 0;
    dnfast_error error = {0};
    dnfast_status status = dnfast_context_open(&limits, &callbacks, &context, &error);
    if (status == DNFAST_STATUS_OK) {
        dnfast_context_free(context);
    }
    dnfast_error_free(&error);
    return status == DNFAST_STATUS_OK ? 0 : 1;
}
