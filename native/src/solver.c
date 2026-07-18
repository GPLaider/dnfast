#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef DNFAST_NATIVE_REAL
#include <solv/pool.h>
#include <solv/poolarch.h>
#include <solv/evr.h>
#include <solv/problems.h>
#include <solv/queue.h>
#include <solv/repo.h>
#include <solv/repo_repomdxml.h>
#include <solv/repo_rpmmd.h>
#include <solv/selection.h>
#include <solv/solver.h>
#include <solv/transaction.h>

static uint64_t monotonic_micros(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000000) +
           (uint64_t)value.tv_nsec / UINT64_C(1000);
}
#endif

#ifdef DNFAST_NATIVE_REAL
static char *copy_text(const char *text) {
    size_t length = strlen(text);
    char *copy = malloc(length + 1);
    if (copy != NULL) memcpy(copy, text, length + 1);
    return copy;
}
#endif

static dnfast_status owner_check(dnfast_context *context, dnfast_error *error) {
    if (context == NULL) return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                                 "solver", NULL, "context is null");
    if (!pthread_equal(context->owner, pthread_self()))
        return dnfast_set_error(error, DNFAST_STATUS_WRONG_THREAD,
                                "solver", NULL, "wrong owner thread");
    return DNFAST_STATUS_OK;
}

#ifdef DNFAST_NATIVE_REAL
static int add_xml(Repo *repo, FILE *stream, int mode) {
    int result = mode == 1 ? repo_add_repomdxml(repo, stream, 0)
                       : repo_add_rpmmd(repo, stream, NULL,
                                         mode == 2 ? REPO_EXTEND_SOLVABLES : 0);
    return result;
}
#endif

static dnfast_status add_repo_kind(dnfast_context *context,
                                   const dnfast_repo_input *input,
                                   int include_filelists,
                                   dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) return status;
    if (input == NULL || input->abi_version != DNFAST_NATIVE_ABI_VERSION ||
        input->id == NULL || input->repomd_path == NULL ||
        input->primary_path == NULL ||
        (include_filelists && input->filelists_path == NULL))
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver", NULL, "invalid repository input");
#ifdef DNFAST_NATIVE_REAL
    FILE *streams[3] = {NULL, NULL, NULL};
    struct stat identity[3];
    size_t metadata_count = include_filelists ? 3 : 2;
    status = dnfast_metadata_open(input, streams, identity, metadata_count, error);
    if (status != DNFAST_STATUS_OK) return status;
    int metadata_fds[3] = {fileno(streams[0]), fileno(streams[1]), -1};
    if (include_filelists) metadata_fds[2] = fileno(streams[2]);
    status = dnfast_limits_before_repo(context, metadata_fds,
                                       metadata_count, error);
    if (status != DNFAST_STATUS_OK) {
        dnfast_metadata_close(streams);
        return status;
    }
    status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) {
        dnfast_metadata_close(streams);
        return status;
    }
    Repo *repo = repo_create(context->pool, input->id);
    if (repo == NULL || add_xml(repo, streams[0], 1) != 0 ||
        add_xml(repo, streams[1], 0) != 0 ||
        (include_filelists && add_xml(repo, streams[2], 2) != 0)) {
        if (repo != NULL) repo_free(repo, 1);
        dnfast_metadata_close(streams);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "repo_add_rpmmd", "rpm-md load failed");
    }
    status = dnfast_callback_check(&context->callbacks, error);
    if (status == DNFAST_STATUS_OK)
        status = dnfast_limits_finalize_repo(context, repo, input, streams,
                                             identity, metadata_count, error);
    dnfast_metadata_close(streams);
    if (status != DNFAST_STATUS_OK) {
        repo_free(repo, 1);
        return status;
    }
    repo->priority = -input->priority;
    repo->subpriority = -input->cost;
    repo_internalize(repo);
    if (input->installed) pool_set_installed(context->pool, repo);
    return DNFAST_STATUS_OK;
#else
    (void)input;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "repo_add_rpmmd", "real native build disabled");
#endif
}

dnfast_status dnfast_solver_add_repo(dnfast_context *context,
                                     const dnfast_repo_input *input,
                                     dnfast_error *error) {
    return add_repo_kind(context, input, 1, error);
}

dnfast_status dnfast_solver_add_repo_primary(dnfast_context *context,
                                             const dnfast_repo_input *input,
                                             dnfast_error *error) {
    return add_repo_kind(context, input, 0, error);
}

dnfast_status dnfast_solver_prepare(dnfast_context *context,
                                    dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) return status;
#ifdef DNFAST_NATIVE_REAL
    if (context->pool->whatprovides == NULL) {
        pool_addfileprovides(context->pool);
        pool_createwhatprovides(context->pool);
    }
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "pool_createwhatprovides",
                            "real native build disabled");
#endif
}

dnfast_status dnfast_solver_set_module_excludes(
    dnfast_context *context, const char *const *nevras, size_t nevra_count,
    dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    if ((nevra_count != 0 && nevras == NULL) || nevra_count > UINT32_MAX)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver", "module_excludes",
                                "invalid module exclude set");
#ifdef DNFAST_NATIVE_REAL
    int *resolved = NULL;
    size_t resolved_count = 0;
    for (size_t input = 0; input < nevra_count; ++input) {
        if (nevras[input] == NULL || nevras[input][0] == '\0') {
            free(resolved);
            return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                    "solver", "module_excludes",
                                    "empty module artifact identity");
        }
        for (size_t prior = 0; prior < input; ++prior) {
            if (strcmp(nevras[input], nevras[prior]) == 0) {
                free(resolved);
                return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                        "solver", "module_excludes",
                                        "duplicate module artifact identity");
            }
        }
        size_t matches = 0;
        for (Id id = 1; id < context->pool->nsolvables; ++id) {
            Solvable *item = pool_id2solvable(context->pool, id);
            if (item == NULL || item->repo == NULL ||
                item->repo == context->pool->installed)
                continue;
            char *identity = dnfast_solvable_identity(context->pool, item);
            int same = identity != NULL && strcmp(identity, nevras[input]) == 0;
            if (!same && identity != NULL) {
                char *zero_epoch = strstr(identity, "-0:");
                if (zero_epoch != NULL) {
                    size_t prefix = (size_t)(zero_epoch - identity) + 1;
                    size_t expected = strlen(identity) - 2;
                    same = strlen(nevras[input]) == expected &&
                           memcmp(nevras[input], identity, prefix) == 0 &&
                           strcmp(nevras[input] + prefix, identity + prefix + 2) == 0;
                }
            }
            free(identity);
            if (!same) continue;
            if (resolved_count == SIZE_MAX / sizeof(int)) {
                free(resolved);
                return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                        "solver", "module_excludes",
                                        "module exclude set is too large");
            }
            int *grown = realloc(resolved, (resolved_count + 1) * sizeof(int));
            if (grown == NULL) {
                free(resolved);
                return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                        "dnfast", "realloc",
                                        "module exclude allocation failed");
            }
            resolved = grown;
            resolved[resolved_count++] = id;
            ++matches;
        }
        if (matches == 0) {
            free(resolved);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "solver", "module_excludes",
                                    "module artifact is absent from selected repositories");
        }
    }
    Map *considered = NULL;
    if (resolved_count != 0) {
        considered = calloc(1, sizeof(*considered));
        if (considered == NULL) {
            free(resolved);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "dnfast", "calloc",
                                    "module considered map allocation failed");
        }
        map_init(considered, context->pool->nsolvables);
        map_setall(considered);
        for (size_t index = 0; index < resolved_count; ++index)
            map_clr(considered, resolved[index]);
    }
    free(resolved);
    Map *previous = context->module_considered;
    context->module_considered = considered;
    context->pool->considered = considered;
    /* whatprovides may have been built using the prior considered map.  A
     * stream switch must rebuild it so disabled artifacts cannot influence
     * selection, FORCEBEST, dependencies, or provider choice. */
    if (context->pool->whatprovides != NULL)
        pool_freewhatprovides(context->pool);
    if (previous != NULL) {
        map_free(previous);
        free(previous);
    }
    return DNFAST_STATUS_OK;
#else
    (void)nevras;
    (void)nevra_count;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "module_excludes",
                            "real native build disabled");
#endif
}

#ifdef DNFAST_NATIVE_REAL
static dnfast_status copy_problems(dnfast_context *context, dnfast_error *error) {
    Id count = solver_problem_count(context->solver);
    Id index;
    context->problems = calloc((size_t)count, sizeof(char *));
    if (count != 0 && context->problems == NULL) goto allocation;
    for (index = 1; index <= count; ++index) {
        const char *text = solver_problem2str(context->solver, index);
        context->problems[context->problem_count] = copy_text(text == NULL ? "unknown problem" : text);
        if (context->problems[context->problem_count] == NULL) goto allocation;
        ++context->problem_count;
    }
    return DNFAST_STATUS_OK;
allocation:
    return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                            "dnfast", "malloc", "result allocation failed");
}

static dnfast_status copy_actions(dnfast_context *context, dnfast_error *error) {
    Queue *steps = &context->transaction->steps;
    int index;
    transaction_order(context->transaction, 0);
    context->actions = calloc((size_t)steps->count, sizeof(char *));
    context->action_obsoletes = calloc((size_t)steps->count, sizeof(char *));
    if (steps->count != 0 && (context->actions == NULL || context->action_obsoletes == NULL)) goto allocation;
    for (index = 0; index < steps->count; ++index) {
        Solvable *solvable = pool_id2solvable(context->pool, steps->elements[index]);
        context->actions[context->action_count] = dnfast_solvable_identity(context->pool, solvable);
        if (context->actions[context->action_count] == NULL) goto allocation;
        Id old = transaction_obs_pkg(context->transaction, steps->elements[index]);
        if (old != 0) {
            context->action_obsoletes[context->action_count] = dnfast_solvable_identity(context->pool, pool_id2solvable(context->pool, old));
            if (context->action_obsoletes[context->action_count] == NULL) goto allocation;
        }
        ++context->action_count;
    }
    return DNFAST_STATUS_OK;
allocation:
    return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                            "dnfast", "malloc", "result allocation failed");
}

static int action_is_final_active(const dnfast_context *context, size_t index,
                                  uint8_t operation) {
    Id package = context->transaction->steps.elements[index];
    Solvable *solvable = pool_id2solvable(context->pool, package);
    int mode = solvable->repo == context->pool->installed
        ? SOLVER_TRANSACTION_SHOW_ALL : SOLVER_TRANSACTION_SHOW_ACTIVE;
    Id type = transaction_type(context->transaction, package,
                               mode | SOLVER_TRANSACTION_SHOW_OBSOLETES);
    switch (operation) {
        case 0:
            return type == SOLVER_TRANSACTION_INSTALL ||
                type == SOLVER_TRANSACTION_REINSTALL ||
                type == SOLVER_TRANSACTION_DOWNGRADE ||
                type == SOLVER_TRANSACTION_CHANGE ||
                type == SOLVER_TRANSACTION_UPGRADE ||
                type == SOLVER_TRANSACTION_OBSOLETES ||
                type == SOLVER_TRANSACTION_MULTIINSTALL ||
                type == SOLVER_TRANSACTION_MULTIREINSTALL;
        case 1:
            return type == SOLVER_TRANSACTION_ERASE;
        case 2:
            return type == SOLVER_TRANSACTION_DOWNGRADE ||
                type == SOLVER_TRANSACTION_CHANGE ||
                type == SOLVER_TRANSACTION_UPGRADE ||
                type == SOLVER_TRANSACTION_OBSOLETES;
        case 3:
            return type == SOLVER_TRANSACTION_DOWNGRADE;
        case 4:
            return type == SOLVER_TRANSACTION_REINSTALL ||
                type == SOLVER_TRANSACTION_CHANGE ||
                type == SOLVER_TRANSACTION_MULTIREINSTALL;
        case 5:
            return type == SOLVER_TRANSACTION_DOWNGRADE ||
                type == SOLVER_TRANSACTION_CHANGE ||
                type == SOLVER_TRANSACTION_UPGRADE ||
                type == SOLVER_TRANSACTION_OBSOLETES ||
                type == SOLVER_TRANSACTION_REINSTALL ||
                type == SOLVER_TRANSACTION_MULTIREINSTALL;
        case 6:
            return type == SOLVER_TRANSACTION_ERASE;
        default:
            return 0;
    }
}

static Id operation_job(uint8_t operation, uint8_t best) {
    switch (operation) {
        case 0:
            return SOLVER_INSTALL | (best ? SOLVER_FORCEBEST : 0);
        case 1:
            return SOLVER_ERASE;
        case 2:
            return SOLVER_UPDATE | SOLVER_FORCEBEST;
        case 3:
            return SOLVER_DISTUPGRADE | SOLVER_TARGETED | SOLVER_FORCEBEST;
        case 4:
            return SOLVER_INSTALL | SOLVER_ORUPDATE | SOLVER_TARGETED |
                SOLVER_FORCEBEST;
        case 5:
            return SOLVER_DISTUPGRADE | SOLVER_TARGETED |
                (best ? SOLVER_FORCEBEST : 0);
        case 6:
            return SOLVER_ERASE;
        default:
            return SOLVER_NOOP;
    }
}

static dnfast_status exact_installed_selector(
    dnfast_context *context, Queue *selector, Id *installed_out,
    dnfast_error *error) {
    Queue selected;
    Id installed = 0;
    queue_init(&selected);
    selection_solvables(context->pool, selector, &selected);
    for (int index = 0; index < selected.count; ++index) {
        Id id = selected.elements[index];
        Solvable *item = pool_id2solvable(context->pool, id);
        if (item == NULL || item->repo != context->pool->installed) continue;
        if (installed != 0 && installed != id) {
            queue_free(&selected);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "libsolv", "autoremove",
                                    "candidate matches multiple installed packages");
        }
        installed = id;
    }
    queue_free(&selected);
    if (installed == 0)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "autoremove",
                                "autoremove candidate is not installed");
    queue_empty(selector);
    queue_push2(selector, SOLVER_SOLVABLE, installed);
    *installed_out = installed;
    return DNFAST_STATUS_OK;
}

static int queue_contains_id(const Queue *queue, Id id) {
    for (int index = 0; index < queue->count; ++index)
        if (queue->elements[index] == id) return 1;
    return 0;
}

static dnfast_status prepare_autoremove_jobs(
    dnfast_context *context, Queue *job, Queue *selectors,
    size_t selector_count, dnfast_error *error) {
    Queue candidates;
    Queue roots;
    Queue unneeded;
    queue_init(&candidates);
    queue_init(&roots);
    queue_init(&unneeded);
    for (size_t index = 0; index < selector_count; ++index) {
        if (selectors[index].count != 2 ||
            (selectors[index].elements[0] & SOLVER_SELECTMASK) != SOLVER_SOLVABLE) {
            queue_free(&candidates);
            queue_free(&roots);
            queue_free(&unneeded);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "libsolv", "autoremove",
                                    "autoremove selector is not exact");
        }
        Id id = selectors[index].elements[1];
        if (queue_contains_id(&candidates, id)) {
            queue_free(&candidates);
            queue_free(&roots);
            queue_free(&unneeded);
            return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                    "solver", "autoremove",
                                    "duplicate autoremove candidate");
        }
        queue_push(&candidates, id);
    }
    Repo *system = context->pool->installed;
    if (system == NULL) {
        queue_free(&candidates);
        queue_free(&roots);
        queue_free(&unneeded);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "autoremove",
                                "installed repository is absent");
    }
    for (Id id = system->start; id < system->end; ++id) {
        Solvable *item = pool_id2solvable(context->pool, id);
        if (item == NULL || item->repo != system || queue_contains_id(&candidates, id))
            continue;
        queue_push2(&roots, SOLVER_USERINSTALLED | SOLVER_SOLVABLE, id);
    }
    Solver *probe = solver_create(context->pool);
    if (probe == NULL || solver_solve(probe, &roots) != 0) {
        if (probe != NULL) solver_free(probe);
        queue_free(&candidates);
        queue_free(&roots);
        queue_free(&unneeded);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "solver_get_unneeded",
                                "unneeded-package calculation failed");
    }
    solver_get_unneeded(probe, &unneeded, 0);
    solver_free(probe);
    queue_empty(job);
    for (int index = 0; index < candidates.count; ++index) {
        Id id = candidates.elements[index];
        if (queue_contains_id(&unneeded, id))
            queue_push2(job, SOLVER_ERASE | SOLVER_SOLVABLE, id);
    }
    queue_free(&candidates);
    queue_free(&roots);
    queue_free(&unneeded);
    return DNFAST_STATUS_OK;
}

static dnfast_status exact_replacement_candidate(
    dnfast_context *context, Queue *selector, uint8_t operation,
    Id *candidate_out, dnfast_error *error) {
    Queue selected;
    Id installed = 0;
    Id candidate = 0;
    queue_init(&selected);
    selection_solvables(context->pool, selector, &selected);
    for (int index = 0; index < selected.count; ++index) {
        Id id = selected.elements[index];
        Solvable *item = pool_id2solvable(context->pool, id);
        if (item == NULL || item->repo != context->pool->installed) continue;
        if (installed != 0 && installed != id) {
            queue_free(&selected);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "libsolv", "replacement",
                                    "selector matches multiple installed packages");
        }
        installed = id;
    }
    if (installed == 0 && context->pool->installed != NULL) {
        Repo *system = context->pool->installed;
        for (Id id = system->start; id < system->end; ++id) {
            Solvable *old = pool_id2solvable(context->pool, id);
            if (old == NULL || old->repo != system) continue;
            int matched = 0;
            for (int index = 0; index < selected.count; ++index) {
                Solvable *available = pool_id2solvable(
                    context->pool, selected.elements[index]);
                if (available != NULL && available->repo != system &&
                    available->name == old->name && available->arch == old->arch) {
                    matched = 1;
                    break;
                }
            }
            if (!matched) continue;
            if (installed != 0 && installed != id) {
                queue_free(&selected);
                return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                        "libsolv", "replacement",
                                        "selector maps to multiple installed packages");
            }
            installed = id;
        }
    }
    if (installed == 0) {
        queue_free(&selected);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "replacement",
                                "replacement target is not installed");
    }
    Solvable *old = pool_id2solvable(context->pool, installed);
    for (int index = 0; index < selected.count; ++index) {
        Id id = selected.elements[index];
        Solvable *item = pool_id2solvable(context->pool, id);
        if (item == NULL || item->repo == NULL ||
            item->repo == context->pool->installed || item->name != old->name ||
            item->arch != old->arch || item->vendor != old->vendor)
            continue;
        int comparison = pool_evrcmp(context->pool, item->evr, old->evr,
                                     EVRCMP_COMPARE);
        if ((operation == 3 && comparison >= 0) ||
            (operation == 4 && comparison != 0))
            continue;
        if (candidate == 0) {
            candidate = id;
            continue;
        }
        Solvable *current = pool_id2solvable(context->pool, candidate);
        int version = pool_evrcmp(context->pool, item->evr, current->evr,
                                 EVRCMP_COMPARE);
        if (version > 0 ||
            (version == 0 && item->repo->priority > current->repo->priority) ||
            (version == 0 && item->repo->priority == current->repo->priority &&
             item->repo->subpriority > current->repo->subpriority) ||
            (version == 0 && item->repo->priority == current->repo->priority &&
             item->repo->subpriority == current->repo->subpriority && id < candidate))
            candidate = id;
    }
    queue_free(&selected);
    if (candidate == 0)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "replacement",
                                operation == 3
                                    ? "no older same-identity repository package"
                                    : "exact installed EVRA is absent from repositories");
    *candidate_out = candidate;
    return DNFAST_STATUS_OK;
}

static void free_selector_provenance(char **requested_specs,
                                     uint8_t *requested_relation_kinds,
                                     size_t count) {
    size_t index;
    if (requested_specs != NULL)
        for (index = 0; index < count; ++index) free(requested_specs[index]);
    free(requested_specs);
    free(requested_relation_kinds);
}

static dnfast_status copy_selector_provenance(dnfast_context *context,
                                              const dnfast_solve_request *request,
                                              Queue *selectors,
                                              const uint8_t *selector_relation_kinds,
                                              uint8_t operation,
                                              dnfast_error *error) {
    char **requested_specs = calloc(context->action_count, sizeof(char *));
    uint8_t *requested_relation_kinds = calloc(context->action_count,
                                               sizeof(uint8_t));
    char **satisfied_specs = calloc(request->name_count, sizeof(char *));
    size_t satisfied_spec_count = 0;
    if (context->action_count != 0 &&
        (requested_specs == NULL || requested_relation_kinds == NULL)) {
        free_selector_provenance(requested_specs, requested_relation_kinds,
                                 context->action_count);
        free(satisfied_specs);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "dnfast", "calloc", "selector provenance allocation failed");
    }
    if (request->name_count != 0 && satisfied_specs == NULL) {
        free_selector_provenance(requested_specs, requested_relation_kinds,
                                 context->action_count);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "dnfast", "calloc", "satisfied selector allocation failed");
    }
    for (size_t selector_index = 0; selector_index < request->name_count;
         ++selector_index) {
        Queue selected;
        size_t match_count = 0;
        size_t action_index = 0;
        queue_init(&selected);
        selection_solvables(context->pool, &selectors[selector_index], &selected);
        for (int selected_index = 0; selected_index < selected.count;
             ++selected_index) {
            for (size_t candidate_index = 0;
                 candidate_index < context->action_count; ++candidate_index) {
                if (context->transaction->steps.elements[candidate_index] !=
                    selected.elements[selected_index] ||
                    !action_is_final_active(context, candidate_index, operation))
                    continue;
                ++match_count;
                action_index = candidate_index;
            }
        }
        queue_free(&selected);
        /* A valid selector can be satisfied entirely by the installed repo and
         * therefore produce no active transaction step.  That is an
         * idempotent no-op, not lost provenance: provenance is attached only to
         * executable actions. */
        if (match_count == 0) {
            satisfied_specs[satisfied_spec_count] =
                copy_text(request->names[selector_index]);
            if (satisfied_specs[satisfied_spec_count] == NULL) {
                free_selector_provenance(requested_specs,
                                         requested_relation_kinds,
                                         context->action_count);
                for (size_t index = 0; index < satisfied_spec_count; ++index)
                    free(satisfied_specs[index]);
                free(satisfied_specs);
                return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                        "dnfast", "malloc",
                                        "satisfied selector allocation failed");
            }
            ++satisfied_spec_count;
            continue;
        }
        if (match_count != 1) {
            free_selector_provenance(requested_specs, requested_relation_kinds,
                                     context->action_count);
            for (size_t index = 0; index < satisfied_spec_count; ++index)
                free(satisfied_specs[index]);
            free(satisfied_specs);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "libsolv", "selection_solvables",
                                    "selector has multiple final active transaction actions");
        }
        if (requested_specs[action_index] != NULL) {
            free_selector_provenance(requested_specs, requested_relation_kinds,
                                     context->action_count);
            for (size_t index = 0; index < satisfied_spec_count; ++index)
                free(satisfied_specs[index]);
            free(satisfied_specs);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "libsolv", "selection_solvables",
                                    "selectors overlap on final active transaction action");
        }
        requested_specs[action_index] = copy_text(request->names[selector_index]);
        if (requested_specs[action_index] == NULL) {
            free_selector_provenance(requested_specs, requested_relation_kinds,
                                     context->action_count);
            for (size_t index = 0; index < satisfied_spec_count; ++index)
                free(satisfied_specs[index]);
            free(satisfied_specs);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "dnfast", "malloc",
                                    "selector provenance allocation failed");
        }
        requested_relation_kinds[action_index] =
            selector_relation_kinds[selector_index];
    }
    context->action_requested_specs = requested_specs;
    context->action_requested_relation_kinds = requested_relation_kinds;
    context->satisfied_specs = satisfied_specs;
    context->satisfied_spec_count = satisfied_spec_count;
    return DNFAST_STATUS_OK;
}
#endif

static dnfast_status solve_operation(dnfast_context *context,
                                     const dnfast_solve_request *request,
                                     const dnfast_selector_providers *mapped,
                                     size_t mapped_count,
                                     uint8_t operation,
                                     dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) return status;
    if (request == NULL || request->abi_version != DNFAST_NATIVE_ABI_VERSION || operation > 6 ||
        (request->name_count == 0 && operation != 2 && operation != 5) ||
        (request->name_count != 0 && request->names == NULL) ||
        (mapped_count != 0 && mapped == NULL) ||
        (mapped_count != 0 && operation != 0))
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver", NULL, "invalid solve request");
    dnfast_solver_clear(context);
#ifdef DNFAST_NATIVE_REAL
    Queue job;
    Queue *selectors;
    uint8_t *selector_relation_kinds;
    queue_init(&job);
    if (context->pool->whatprovides == NULL) {
        pool_addfileprovides(context->pool);
        pool_createwhatprovides(context->pool);
    }
    selectors = request->name_count == 0 ? NULL : calloc(request->name_count, sizeof(Queue));
    selector_relation_kinds = request->name_count == 0 ? NULL : calloc(request->name_count, sizeof(uint8_t));
    if (request->name_count != 0 && (selectors == NULL || selector_relation_kinds == NULL)) {
        free(selectors);
        free(selector_relation_kinds);
        queue_free(&job);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "dnfast", "calloc", "selector allocation failed");
    }
    if (request->name_count == 0) {
        Id command = operation == 5 ? SOLVER_DISTUPGRADE : SOLVER_UPDATE;
        queue_push2(&job, command | SOLVER_SOLVABLE_ALL |
                    (request->best ? SOLVER_FORCEBEST : 0), 0);
    }
    for (size_t name_index = 0; name_index < request->name_count; ++name_index) {
        int start = job.count;
        const dnfast_selector_providers *mapping = NULL;
        for (size_t mapped_index = 0; mapped_index < mapped_count; ++mapped_index) {
            if (mapped[mapped_index].selector_index == name_index) {
                if (mapping != NULL) {
                    status = dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                              "solver", NULL,
                                              "duplicate mapped selector");
                    goto cleanup;
                }
                mapping = &mapped[mapped_index];
            } else if (mapped[mapped_index].selector_index >= request->name_count) {
                status = dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                          "solver", NULL,
                                          "mapped selector index is out of range");
                goto cleanup;
            }
        }
        if (mapping != NULL) {
            Queue providers;
            queue_init(&providers);
            if (request->names[name_index] == NULL ||
                request->names[name_index][0] != '/' ||
                mapping->provider_count == 0 || mapping->providers == NULL) {
                queue_free(&providers);
                status = dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                          "solver", NULL,
                                          "invalid mapped absolute selector");
                goto cleanup;
            }
            for (size_t provider_index = 0;
                 provider_index < mapping->provider_count; ++provider_index) {
                const dnfast_solvable_reference *reference =
                    &mapping->providers[provider_index];
                Repo *repo = NULL;
                Id solvable_id = 0;
                uint32_t ordinal = 0;
                if (reference->repository_id == NULL ||
                    reference->repository_id[0] == '\0' ||
                    reference->expected_identity == NULL ||
                    reference->expected_identity[0] == '\0') {
                    queue_free(&providers);
                    status = dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                              "solver", NULL,
                                              "invalid mapped provider reference");
                    goto cleanup;
                }
                for (int repo_index = 1; repo_index < context->pool->nrepos;
                     ++repo_index) {
                    Repo *candidate = context->pool->repos[repo_index];
                    if (candidate != NULL && candidate->name != NULL &&
                        strcmp(candidate->name, reference->repository_id) == 0) {
                        if (repo != NULL) {
                            queue_free(&providers);
                            status = dnfast_set_error(error,
                                DNFAST_STATUS_NATIVE_FAILURE, "libsolv", "repo",
                                "mapped provider repository is ambiguous");
                            goto cleanup;
                        }
                        repo = candidate;
                    }
                }
                if (repo == NULL) {
                    queue_free(&providers);
                    status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                              "libsolv", "repo",
                                              "mapped provider repository is absent");
                    goto cleanup;
                }
                for (Id candidate = repo->start; candidate < repo->end; ++candidate) {
                    Solvable *solvable = pool_id2solvable(context->pool, candidate);
                    if (solvable->repo != repo) continue;
                    if (ordinal == reference->package_ordinal) {
                        solvable_id = candidate;
                        break;
                    }
                    ++ordinal;
                }
                if (solvable_id == 0) {
                    queue_free(&providers);
                    status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                              "libsolv", "repo",
                                              "mapped provider ordinal is absent");
                    goto cleanup;
                }
                char *identity = dnfast_solvable_identity(
                    context->pool, pool_id2solvable(context->pool, solvable_id));
                if (identity == NULL ||
                    strcmp(identity, reference->expected_identity) != 0) {
                    free(identity);
                    queue_free(&providers);
                    status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                              "libsolv", "solvable",
                                              "mapped provider identity differs");
                    goto cleanup;
                }
                free(identity);
                for (int seen = 0; seen < providers.count; ++seen) {
                    if (providers.elements[seen] == solvable_id) {
                        queue_free(&providers);
                        status = dnfast_set_error(error,
                            DNFAST_STATUS_INVALID_ARGUMENT, "solver", NULL,
                            "duplicate mapped provider");
                        goto cleanup;
                    }
                }
                queue_push(&providers, solvable_id);
            }
            Id how = SOLVER_SOLVABLE;
            Id what = providers.elements[0];
            if (providers.count > 1) {
                what = pool_queuetowhatprovides(context->pool, &providers);
                how = SOLVER_SOLVABLE_ONE_OF;
            }
            queue_push2(&selectors[name_index], how, what);
            queue_push2(&job, how, what);
            queue_free(&providers);
            selector_relation_kinds[name_index] = 0;
            job.elements[start] |= operation_job(operation, request->best);
            continue;
        }
        int selector_flags = SELECTION_NAME | SELECTION_PROVIDES | SELECTION_REL;
        /* Filelist matching scans the repository's very large file index. It
         * is semantically relevant only to absolute path selectors; ordinary
         * names, capabilities, and version relations are completely covered by
         * NAME/PROVIDES/REL. DNF-style type dispatch avoids an O(filelists)
         * scan for every normal install request without weakening path lookup. */
        if (request->names[name_index] != NULL &&
            request->names[name_index][0] == '/')
            selector_flags |= SELECTION_FILELIST;
        int selection_flags = selector_flags;
        queue_init(&selectors[name_index]);
        /* Internal policy jobs (currently modular stream blacklists) precede
         * user selectors.  Preserve them when the first selector is appended;
         * without SELECTION_ADD libsolv replaces the queue and also breaks the
         * start/count provenance invariant below. */
        if (job.count != 0) selection_flags |= SELECTION_ADD;
        if (request->names[name_index] == NULL || request->names[name_index][0] == '\0' ||
            selection_make(context->pool, &selectors[name_index],
                           request->names[name_index],
                           selector_flags) == 0 ||
            selection_make(context->pool, &job, request->names[name_index],
                           selection_flags) == 0) {
            status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                      "libsolv", "selection_make", "no matching package or provide");
            goto cleanup;
        }
        if (job.count != start + 2) {
            status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                      "libsolv", "selection_make",
                                      "selector did not produce one job dependency");
            goto cleanup;
        }
        selector_relation_kinds[name_index] =
            ISRELDEP(job.elements[start + 1]) ? 1 : 0;
        if (operation == 3 || operation == 4) {
            Id candidate = 0;
            status = exact_replacement_candidate(
                context, &selectors[name_index], operation, &candidate, error);
            if (status != DNFAST_STATUS_OK) goto cleanup;
            queue_empty(&selectors[name_index]);
            queue_push2(&selectors[name_index], SOLVER_SOLVABLE, candidate);
            job.elements[start] = SOLVER_SOLVABLE |
                operation_job(operation, request->best) |
                SOLVER_SETEVR | SOLVER_SETARCH | SOLVER_SETVENDOR;
            job.elements[start + 1] = candidate;
            continue;
        }
        if (operation == 6) {
            Id installed = 0;
            status = exact_installed_selector(
                context, &selectors[name_index], &installed, error);
            if (status != DNFAST_STATUS_OK) goto cleanup;
            job.elements[start] = SOLVER_NOOP | SOLVER_SOLVABLE;
            job.elements[start + 1] = installed;
            continue;
        }
        for (int index = start; index < job.count; index += 2) {
            job.elements[index] |= operation_job(operation, request->best);
        }
    }
    if (operation == 6) {
        status = prepare_autoremove_jobs(context, &job, selectors,
                                         request->name_count, error);
        if (status != DNFAST_STATUS_OK) goto cleanup;
    }
    context->solver = solver_create(context->pool);
    if (!request->install_weak_deps)
        solver_set_flag(context->solver, SOLVER_FLAG_IGNORE_RECOMMENDED, 1);
    solver_set_flag(context->solver, SOLVER_FLAG_STRICT_REPO_PRIORITY, 1);
    if (operation == 3 || operation == 5) {
        solver_set_flag(context->solver, SOLVER_FLAG_DUP_ALLOW_DOWNGRADE, 1);
        solver_set_flag(context->solver, SOLVER_FLAG_DUP_ALLOW_ARCHCHANGE, 0);
        solver_set_flag(context->solver, SOLVER_FLAG_DUP_ALLOW_VENDORCHANGE, 0);
        solver_set_flag(context->solver, SOLVER_FLAG_DUP_ALLOW_NAMECHANGE, 0);
        solver_set_flag(context->solver, SOLVER_FLAG_KEEP_ORPHANS, 1);
    }
    uint64_t solve_started = monotonic_micros();
    if (solver_solve(context->solver, &job) != 0) status = copy_problems(context, error);
    else {
        uint64_t solver_finished = monotonic_micros();
        context->transaction = solver_create_transaction(context->solver);
        if (context->transaction == NULL)
            status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                      "libsolv", "solver_create_transaction",
                                      "transaction allocation failed");
        else status = copy_actions(context, error);
        if (status == DNFAST_STATUS_OK)
            status = copy_selector_provenance(context, request, selectors,
                                              selector_relation_kinds,
                                              operation, error);
        uint64_t actions_finished = monotonic_micros();
        if (status == DNFAST_STATUS_OK) status = dnfast_decisions_collect(context, error);
        if (getenv("DNFAST_NATIVE_TRACE") != NULL) {
            uint64_t decisions_finished = monotonic_micros();
            fprintf(stderr,
                    "dnfast_native_trace solver_us=%llu actions_us=%llu decisions_us=%llu decisions=%zu\n",
                    (unsigned long long)(solver_finished - solve_started),
                    (unsigned long long)(actions_finished - solver_finished),
                    (unsigned long long)(decisions_finished - actions_finished),
                    context->decision_count);
        }
    }
cleanup:
    for (size_t selector_index = 0; selector_index < request->name_count;
         ++selector_index) queue_free(&selectors[selector_index]);
    free(selectors);
    free(selector_relation_kinds);
    queue_free(&job);
    return status;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "solver_solve", "real native build disabled");
#endif
}

dnfast_status dnfast_solver_solve_install(dnfast_context *context,
                                          const dnfast_solve_request *request,
                                          dnfast_error *error) {
    return solve_operation(context, request, NULL, 0, 0, error);
}

dnfast_status dnfast_solver_solve_operation(dnfast_context *context,
                                            const dnfast_solve_request *request,
                                            uint8_t operation,
                                            dnfast_error *error) {
    return solve_operation(context, request, NULL, 0, operation, error);
}

dnfast_status dnfast_solver_solve_mapped_operation(
    dnfast_context *context,
    const dnfast_solve_request *request,
    const dnfast_selector_providers *selectors,
    size_t selector_count,
    uint8_t operation,
    dnfast_error *error) {
    return solve_operation(context, request, selectors, selector_count,
                           operation, error);
}

size_t dnfast_solver_action_count(const dnfast_context *context) {
    return context == NULL ? 0 : context->action_count;
}
const char *dnfast_solver_action(const dnfast_context *context, size_t index) {
    return context == NULL || index >= context->action_count ? NULL : context->actions[index];
}
const char *dnfast_solver_action_repo(const dnfast_context *context, size_t index) {
#ifdef DNFAST_NATIVE_REAL
    if (context == NULL || context->transaction == NULL || index >= context->action_count)
        return NULL;
    Solvable *solvable = pool_id2solvable(context->pool,
                                          context->transaction->steps.elements[index]);
    return solvable->repo == NULL ? "@unknown" : solvable->repo->name;
#else
    (void)context;
    (void)index;
    return NULL;
#endif
}
size_t dnfast_solver_problem_count(const dnfast_context *context) {
    return context == NULL ? 0 : context->problem_count;
}
const char *dnfast_solver_problem(const dnfast_context *context, size_t index) {
    return context == NULL || index >= context->problem_count ? NULL : context->problems[index];
}

dnfast_status dnfast_context_check(dnfast_context *context,
                                   dnfast_error *out_error) {
    if (context == NULL) return dnfast_set_error(out_error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "dnfast", NULL, "context is null");
    if (!pthread_equal(context->owner, pthread_self())) {
        return dnfast_set_error(out_error, DNFAST_STATUS_WRONG_THREAD,
                                "dnfast", NULL, "context used from non-owner thread");
    }
    return dnfast_callback_check(&context->callbacks, out_error);
}
