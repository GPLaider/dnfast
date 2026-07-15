#include "internal.h"

#include <stdlib.h>

#ifdef DNFAST_NATIVE_REAL
#include <solv/solver.h>
#include <solv/transaction.h>
#endif

static void free_texts(char ***items, size_t *count) {
    size_t index;
    for (index = 0; index < *count; ++index) free((*items)[index]);
    free(*items);
    *items = NULL;
    *count = 0;
}

void dnfast_solver_clear(dnfast_context *context) {
    if (context == NULL) return;
#ifdef DNFAST_NATIVE_REAL
    if (context->transaction != NULL) transaction_free(context->transaction);
    if (context->solver != NULL) solver_free(context->solver);
    context->transaction = NULL;
    context->solver = NULL;
#endif
    if (context->action_obsoletes != NULL)
        for (size_t index = 0; index < context->action_count; ++index) free(context->action_obsoletes[index]);
    free(context->action_obsoletes); context->action_obsoletes = NULL;
    if (context->action_requested_specs != NULL)
        for (size_t index = 0; index < context->action_count; ++index) free(context->action_requested_specs[index]);
    free(context->action_requested_specs); context->action_requested_specs = NULL;
    free(context->action_requested_relation_kinds);
    context->action_requested_relation_kinds = NULL;
    free_texts(&context->actions, &context->action_count);
    for (size_t index = 0; index < context->decision_count; ++index) {
        free(context->decision_provider[index]); free(context->decision_relation[index]);
    }
    free_texts(&context->decision_requiring, &context->decision_count);
    free(context->decision_provider); context->decision_provider = NULL;
    free(context->decision_relation); context->decision_relation = NULL;
    free(context->decision_kind); context->decision_kind = NULL;
    free(context->decision_installed); context->decision_installed = NULL;
    free_texts(&context->problems, &context->problem_count);
}
