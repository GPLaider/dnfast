#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef DNFAST_NATIVE_REAL
#include <solv/pool.h>
#include <solv/poolarch.h>
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
        default:
            return 0;
    }
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
                                     uint8_t operation,
                                     dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) return status;
    if (request == NULL || request->abi_version != DNFAST_NATIVE_ABI_VERSION || operation > 2 ||
        (request->name_count == 0 && operation != 2) ||
        (request->name_count != 0 && request->names == NULL))
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver", NULL, "invalid solve request");
    dnfast_solver_clear(context);
#ifdef DNFAST_NATIVE_REAL
    Queue job;
    Queue *selectors;
    uint8_t *selector_relation_kinds;
    queue_init(&job);
    pool_createwhatprovides(context->pool);
    selectors = request->name_count == 0 ? NULL : calloc(request->name_count, sizeof(Queue));
    selector_relation_kinds = request->name_count == 0 ? NULL : calloc(request->name_count, sizeof(uint8_t));
    if (request->name_count != 0 && (selectors == NULL || selector_relation_kinds == NULL)) {
        free(selectors);
        free(selector_relation_kinds);
        queue_free(&job);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "dnfast", "calloc", "selector allocation failed");
    }
    if (request->name_count == 0)
        queue_push2(&job, SOLVER_UPDATE | SOLVER_SOLVABLE_ALL |
                    (request->best ? SOLVER_FORCEBEST : 0), 0);
    for (size_t name_index = 0; name_index < request->name_count; ++name_index) {
        int start = job.count;
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
        if (name_index != 0) selection_flags |= SELECTION_ADD;
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
        for (int index = start; index < job.count; index += 2) {
            if (operation == 0)
                job.elements[index] |= SOLVER_INSTALL |
                                       (request->best ? SOLVER_FORCEBEST : 0);
            else if (operation == 1) job.elements[index] |= SOLVER_ERASE;
            else job.elements[index] |= SOLVER_UPDATE | SOLVER_FORCEBEST;
        }
    }
    context->solver = solver_create(context->pool);
    if (!request->install_weak_deps)
        solver_set_flag(context->solver, SOLVER_FLAG_IGNORE_RECOMMENDED, 1);
    solver_set_flag(context->solver, SOLVER_FLAG_STRICT_REPO_PRIORITY, 1);
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
    return solve_operation(context, request, 0, error);
}

dnfast_status dnfast_solver_solve_operation(dnfast_context *context,
                                            const dnfast_solve_request *request,
                                            uint8_t operation,
                                            dnfast_error *error) {
    return solve_operation(context, request, operation, error);
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
