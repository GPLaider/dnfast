#include "internal.h"

#ifdef DNFAST_NATIVE_REAL
#include <solv/pool.h>
#include <solv/transaction.h>
#endif

const char *dnfast_solver_action_kind(const dnfast_context *context, size_t index) {
#ifdef DNFAST_NATIVE_REAL
    if (context == NULL || context->transaction == NULL || index >= context->action_count)
        return NULL;
    Id package = context->transaction->steps.elements[index];
    Solvable *solvable = pool_id2solvable(context->pool, package);
    int mode = solvable->repo == context->pool->installed
        ? SOLVER_TRANSACTION_SHOW_ALL : SOLVER_TRANSACTION_SHOW_ACTIVE;
    switch (transaction_type(context->transaction, package,
                             mode | SOLVER_TRANSACTION_SHOW_OBSOLETES)) {
        case SOLVER_TRANSACTION_ERASE: return "erase";
        case SOLVER_TRANSACTION_REINSTALLED: return "reinstalled";
        case SOLVER_TRANSACTION_DOWNGRADED: return "downgraded";
        case SOLVER_TRANSACTION_UPGRADED: return "upgraded";
        case SOLVER_TRANSACTION_OBSOLETED: return "obsoleted";
        case SOLVER_TRANSACTION_REINSTALL: return "reinstall";
        case SOLVER_TRANSACTION_DOWNGRADE: return "downgrade";
        case SOLVER_TRANSACTION_UPGRADE: return "upgrade";
        case SOLVER_TRANSACTION_OBSOLETES: return "obsoletes";
        default: return "install";
    }
#else
    (void)context;
    (void)index;
    return NULL;
#endif
}

const char *dnfast_solver_action_obsoletes(const dnfast_context *context, size_t index) {
    return context == NULL || index >= context->action_count ? NULL : context->action_obsoletes[index];
}

const char *dnfast_solver_action_requested_spec(const dnfast_context *context,
                                                size_t index) {
    return context == NULL || context->action_requested_specs == NULL ||
            index >= context->action_count
        ? NULL : context->action_requested_specs[index];
}

uint8_t dnfast_solver_action_requested_relation_kind(const dnfast_context *context,
                                                     size_t index) {
    return context == NULL || context->action_requested_relation_kinds == NULL ||
            index >= context->action_count
        ? 0 : context->action_requested_relation_kinds[index];
}

size_t dnfast_solver_satisfied_spec_count(const dnfast_context *context) {
    return context == NULL ? 0 : context->satisfied_spec_count;
}

const char *dnfast_solver_satisfied_spec(const dnfast_context *context,
                                         size_t index) {
    return context == NULL || index >= context->satisfied_spec_count
        ? NULL : context->satisfied_specs[index];
}
