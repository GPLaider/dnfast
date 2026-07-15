#include "internal.h"

#include <stdlib.h>
#include <string.h>

#ifdef DNFAST_NATIVE_REAL
#include <solv/knownid.h>
#include <solv/pool.h>
#include <solv/queue.h>
#include <solv/solvable.h>
#include <solv/solver.h>
#include <solv/transaction.h>

static char *copy_text(const char *value) {
    size_t length = strlen(value);
    char *copy = malloc(length + 1);
    if (copy != NULL) memcpy(copy, value, length + 1);
    return copy;
}

char *dnfast_solvable_identity(Pool *pool, Solvable *item) {
    const char *name = pool_id2str(pool, item->name);
    const char *evr = pool_id2str(pool, item->evr);
    const char *arch = pool_id2str(pool, item->arch);
    int has_epoch = strchr(evr, ':') != NULL;
    size_t length = strlen(name) + strlen(evr) + strlen(arch) + (has_epoch ? 3 : 5);
    char *value = malloc(length);
    if (value != NULL) snprintf(value, length, has_epoch ? "%s-%s.%s" : "%s-0:%s.%s", name, evr, arch);
    return value;
}

static int selected_provider(dnfast_context *context, Id dependency, Id *provider) {
    Pool *pool = context->pool;
    Id candidate, offset, found = 0;
    FOR_PROVIDES(candidate, offset, dependency) {
        if (solver_get_decisionlevel(context->solver, candidate) <= 0) continue;
        if (found != 0 && found != candidate) return -1;
        found = candidate;
    }
    *provider = found;
    return found == 0 ? 0 : 1;
}

static int append(dnfast_context *context, Solvable *requiring, Id dependency, Id provider, uint8_t kind) {
    size_t index = context->decision_count, count = index + 1;
    void *grown = realloc(context->decision_requiring, count * sizeof(char *)); if (grown == NULL) return 0; context->decision_requiring = grown;
    grown = realloc(context->decision_provider, count * sizeof(char *)); if (grown == NULL) return 0; context->decision_provider = grown;
    grown = realloc(context->decision_relation, count * sizeof(char *)); if (grown == NULL) return 0; context->decision_relation = grown;
    grown = realloc(context->decision_kind, count); if (grown == NULL) return 0; context->decision_kind = grown;
    grown = realloc(context->decision_installed, count); if (grown == NULL) return 0; context->decision_installed = grown;
    context->decision_requiring[index] = NULL; context->decision_provider[index] = NULL; context->decision_relation[index] = NULL;
    context->decision_count = count;
    context->decision_requiring[index] = dnfast_solvable_identity(context->pool, requiring);
    context->decision_provider[index] = dnfast_solvable_identity(context->pool, pool_id2solvable(context->pool, provider));
    context->decision_relation[index] = copy_text(pool_dep2str(context->pool, dependency));
    context->decision_kind[index] = kind;
    context->decision_installed[index] = pool_id2solvable(context->pool, provider)->repo == context->pool->installed;
    if (context->decision_requiring[index] == NULL || context->decision_provider[index] == NULL || context->decision_relation[index] == NULL) return 0;
    return 1;
}

static int append_reverse_weak(dnfast_context *context, Solvable *item,
                               Id item_id, Id dependency) {
    Pool *pool = context->pool;
    Id target, offset;
    FOR_PROVIDES(target, offset, dependency) {
        Solvable *requiring;
        if (target == item_id || solver_get_decisionlevel(context->solver, target) <= 0)
            continue;
        requiring = pool_id2solvable(pool, target);
        if (requiring->repo == pool->installed) continue;
        if (!append(context, requiring, dependency, item_id, 1)) return 0;
    }
    return 1;
}

dnfast_status dnfast_decisions_collect(dnfast_context *context, dnfast_error *error) {
    Queue dependencies;
    queue_init(&dependencies);
    for (int index = 0; index < context->transaction->steps.count; ++index) {
        Solvable *item = pool_id2solvable(context->pool, context->transaction->steps.elements[index]);
        if (item->repo == context->pool->installed) continue;
        Id keys[2] = {SOLVABLE_REQUIRES, SOLVABLE_RECOMMENDS};
        for (int kind = 0; kind < 2; ++kind) {
            queue_empty(&dependencies);
            solvable_lookup_deparray(item, keys[kind], &dependencies, -1);
            for (int offset = 0; offset < dependencies.count; ++offset) {
                if (strncmp(pool_dep2str(context->pool, dependencies.elements[offset]), "rpmlib(", 7) == 0) continue;
                Id provider = 0;
                int found = selected_provider(context, dependencies.elements[offset], &provider);
                if (found < 0) { queue_free(&dependencies); return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE, "libsolv", "provider", "ambiguous selected provider"); }
                if (found > 0 && !append(context, item, dependencies.elements[offset], provider, (uint8_t)kind)) { queue_free(&dependencies); return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE, "dnfast", "malloc", "decision allocation failed"); }
            }
        }
        Id reverse_keys[2] = {SOLVABLE_SUPPLEMENTS, SOLVABLE_ENHANCES};
        for (int kind = 0; kind < 2; ++kind) {
            queue_empty(&dependencies);
            solvable_lookup_deparray(item, reverse_keys[kind], &dependencies, -1);
            for (int offset = 0; offset < dependencies.count; ++offset) {
                if (!append_reverse_weak(context, item,
                                         context->transaction->steps.elements[index],
                                         dependencies.elements[offset])) {
                    queue_free(&dependencies);
                    return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                            "dnfast", "malloc",
                                            "reverse decision allocation failed");
                }
            }
        }
    }
    queue_free(&dependencies);
    return DNFAST_STATUS_OK;
}
#endif

size_t dnfast_solver_decision_count(const dnfast_context *context) { return context == NULL ? 0 : context->decision_count; }
#define TEXT_GETTER(name, field) const char *name(const dnfast_context *context, size_t index) { return context == NULL || index >= context->decision_count ? NULL : context->field[index]; }
TEXT_GETTER(dnfast_solver_decision_requiring, decision_requiring)
TEXT_GETTER(dnfast_solver_decision_provider, decision_provider)
TEXT_GETTER(dnfast_solver_decision_relation, decision_relation)
uint8_t dnfast_solver_decision_kind(const dnfast_context *context, size_t index) { return context == NULL || index >= context->decision_count ? 0 : context->decision_kind[index]; }
uint8_t dnfast_solver_decision_provider_installed(const dnfast_context *context, size_t index) { return context == NULL || index >= context->decision_count ? 0 : context->decision_installed[index]; }
