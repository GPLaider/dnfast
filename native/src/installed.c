#include "internal.h"

#include <limits.h>

#ifdef DNFAST_NATIVE_REAL
#include <solv/pool.h>
#include <solv/repo.h>
#include <solv/repo_rpmdb.h>
#endif

dnfast_status dnfast_solver_add_rpmdb(dnfast_context *context,
                                      const char *root,
                                      dnfast_error *error) {
    if (context == NULL || root == NULL || root[0] != '/')
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpmdb", NULL, "invalid rpmdb root");
    if (!pthread_equal(context->owner, pthread_self()))
        return dnfast_set_error(error, DNFAST_STATUS_WRONG_THREAD,
                                "rpmdb", NULL, "wrong owner thread");
    dnfast_status status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) return status;
#ifdef DNFAST_NATIVE_REAL
    pool_set_rootdir(context->pool, root);
    Repo *previous = context->pool->installed;
    if (previous != NULL) dnfast_solver_clear(context);
    Repo *repo = repo_create(context->pool, "@System");
    if (repo == NULL || repo_add_rpmdb(repo, previous, 0) != 0) {
        if (repo != NULL) repo_free(repo, 1);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "repo_add_rpmdb", "rpmdb load failed");
    }
    repo->priority = INT_MIN;
    repo_internalize(repo);
    pool_set_installed(context->pool, repo);
    if (previous != NULL) repo_free(previous, 1);
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solvext", "repo_add_rpmdb", "real native build disabled");
#endif
}
