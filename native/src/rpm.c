#include "internal.h"

#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#ifdef DNFAST_NATIVE_REAL
#include <solv/pool.h>
#include <solv/poolarch.h>
#endif

static _Atomic uint64_t context_allocation_count;

uint64_t dnfast_context_allocation_count(void) {
    return atomic_load(&context_allocation_count);
}

dnfast_status dnfast_context_open(const dnfast_limits *limits,
                                  const dnfast_callbacks *callbacks,
                                  dnfast_context **out_context,
                                  dnfast_error *out_error) {
    dnfast_library libraries[4] = {{0}};
    dnfast_status status;
    if (out_context == NULL || limits == NULL || callbacks == NULL) {
        return dnfast_set_error(out_error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "dnfast", NULL, "required argument is null");
    }
    *out_context = NULL;
    if (limits->abi_version != DNFAST_NATIVE_ABI_VERSION ||
        callbacks->abi_version != DNFAST_NATIVE_ABI_VERSION) {
        return dnfast_set_error(out_error, DNFAST_STATUS_UNSUPPORTED_ABI,
                                "dnfast", NULL, "ABI version mismatch");
    }
    const char *pool_architecture = NULL;
    switch (limits->pool_architecture) {
    case DNFAST_POOL_ARCHITECTURE_AARCH64:
        pool_architecture = "aarch64";
        break;
    case DNFAST_POOL_ARCHITECTURE_X86_64:
        pool_architecture = "x86_64";
        break;
    default:
        return dnfast_set_error(out_error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "dnfast", "pool_architecture",
                                "an explicit supported pool architecture is required");
    }
#ifndef DNFAST_NATIVE_REAL
    (void)pool_architecture;
#endif
    status = dnfast_load_libraries(libraries, out_error);
    if (status != DNFAST_STATUS_OK) {
        return status;
    }
    (void)atomic_fetch_add(&context_allocation_count, UINT64_C(1));
    dnfast_context *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        dnfast_unload_libraries(libraries);
        return dnfast_set_error(out_error, DNFAST_STATUS_NATIVE_FAILURE,
                                "dnfast", NULL, "context allocation failed");
    }
    memcpy(context->libraries, libraries, sizeof(libraries));
    context->callbacks = *callbacks;
    context->limits = *limits;
    context->owner = pthread_self();
#ifdef DNFAST_NATIVE_REAL
    context->pool = pool_create();
    if (context->pool == NULL) {
        dnfast_unload_libraries(context->libraries);
        free(context);
        return dnfast_set_error(out_error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "pool_create", "pool allocation failed");
    }
    pool_setarch(context->pool, pool_architecture);
#endif
    *out_context = context;
    return DNFAST_STATUS_OK;
}

void dnfast_context_free(dnfast_context *context) {
    if (context == NULL) {
        return;
    }
    dnfast_solver_clear(context);
    dnfast_inventory_write_end(context);
    dnfast_inventory_clear(context);
#ifdef DNFAST_NATIVE_REAL
    if (context->module_considered != NULL) {
        context->pool->considered = NULL;
        map_free(context->module_considered);
        free(context->module_considered);
    }
    pool_free(context->pool);
#endif
    dnfast_unload_libraries(context->libraries);
    free(context);
}

const char *dnfast_context_pool_architecture(const dnfast_context *context) {
    if (context == NULL) return NULL;
    switch (context->limits.pool_architecture) {
    case DNFAST_POOL_ARCHITECTURE_AARCH64: return "aarch64";
    case DNFAST_POOL_ARCHITECTURE_X86_64: return "x86_64";
    default: return NULL;
    }
}
