#define _GNU_SOURCE
#include "internal.h"

#include <dlfcn.h>
#ifdef DNFAST_NATIVE_REAL
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <solv/pool.h>
#include <solv/repo.h>
#include <solv/repo_rpmmd.h>
#include <solv/solver.h>
#include <solv/solvversion.h>
#include <solv/transaction.h>
#endif
#include <stdlib.h>
#include <string.h>

#ifdef DNFAST_NATIVE_REAL
_Static_assert(LIBSOLV_VERSION_MAJOR == 0 && LIBSOLV_VERSION_MINOR == 7 &&
                   LIBSOLV_VERSION_PATCH == 39,
               "dnfast requires libsolv 0.7.39 headers");
_Static_assert(sizeof(Pool *) == sizeof(void *) && sizeof(Repo *) == sizeof(void *) &&
                   sizeof(Solver *) == sizeof(void *) &&
                   sizeof(Transaction *) == sizeof(void *) &&
                   sizeof(rpmts) == sizeof(void *),
               "native opaque handle layout is unsupported");

#ifndef RPMVSF_MASK_NOSIGNATURES
#error "dnfast requires RPM 6 verification flag headers"
#endif
#endif

typedef struct dnfast_requirement {
    size_t library;
    const char *symbol;
} dnfast_requirement;

static char *dnfast_copy(const char *value) {
    size_t length = value == NULL ? 0 : strlen(value);
    char *copy = malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, value == NULL ? "" : value, length + 1);
    }
    return copy;
}

dnfast_status dnfast_set_error(dnfast_error *error, dnfast_status status,
                               const char *component, const char *symbol,
                               const char *message) {
    if (error != NULL) {
        dnfast_error_free(error);
        error->status = status;
        error->component = dnfast_copy(component);
        error->symbol = dnfast_copy(symbol);
        error->message = dnfast_copy(message);
    }
    return status;
}

void dnfast_error_free(dnfast_error *error) {
    if (error == NULL) {
        return;
    }
    free(error->component);
    free(error->symbol);
    free(error->message);
    memset(error, 0, sizeof(*error));
}

static const char *dnfast_soname(size_t index) {
    static const char *const defaults[] = {
        "libsolv.so.1", "libsolvext.so.1", "librpm.so.10", "librpmio.so.10"
    };
    static const char *const variables[] = {
        "DNFAST_LIBSOLV", "DNFAST_LIBSOLVEXT", "DNFAST_LIBRPM", "DNFAST_LIBRPMIO"
    };
    const char *override = getenv(variables[index]);
    return override == NULL || override[0] == '\0' ? defaults[index] : override;
}

dnfast_status dnfast_load_libraries(dnfast_library libraries[4],
                                    dnfast_error *error) {
    static const char *const components[] = {"solv", "solvext", "rpm", "rpmio"};
    static const dnfast_requirement requirements[] = {
        {0, "pool_create"}, {0, "pool_free"},
        {1, "repo_add_rpmmd"},
        {2, "rpmtsCreate"}, {2, "rpmtsFree"}, {2, "rpmtsRun"},
        {2, "rpmReadConfigFiles"}, {2, "rpmtsSetRootDir"},
        {2, "rpmtxnBegin"}, {2, "rpmtxnEnd"},
        {2, "rpmtsInitIterator"}, {2, "rpmdbNextIterator"},
        {2, "rpmdbFreeIterator"}, {2, "headerGetString"},
        {2, "headerGetNumber"}, {2, "headerGetInstance"},
        {2, "headerExport"}, {2, "rpmExpand"}, {2, "RPMVERSION"},
        {2, "rpmKeyringNew"}, {2, "rpmKeyringFree"},
        {2, "rpmKeyringLink"},
        {2, "rpmtsSetKeyring"}, {2, "rpmtsFlags"}, {2, "rpmtsSetFlags"},
        {2, "rpmReadPackageFile"}, {2, "headerGet"}, {2, "headerFree"},
        {2, "rpmtdInit"}, {2, "rpmtdNextString"}, {2, "rpmtdFreeData"},
        {2, "rpmtsSetVSFlags"}, {2, "rpmtsSetVfyFlags"},
        {2, "rpmtsSetVfyLevel"},
        {2, "rpmtsAddInstallElement"}, {2, "rpmtsAddEraseElement"},
        {2, "rpmtsCheck"}, {2, "rpmtsOrder"}, {2, "rpmtsProblems"},
        {2, "rpmtsSetNotifyCallback"}, {2, "rpmtsVerifyDB"},
        {2, "rpmdbGetIteratorOffset"},
        {2, "rpmpsNumProblems"}, {2, "rpmpsInitIterator"},
        {2, "rpmpsiNext"}, {2, "rpmpsGetProblem"},
        {2, "rpmpsFreeIterator"}, {2, "rpmpsFree"},
        {2, "rpmProblemString"},
        {3, "Fclose"}, {3, "Fseek"}, {3, "Fileno"}, {3, "fdDup"},
        {3, "pgpParsePkts"}, {3, "pgpPubKeyCertLen"},
        {3, "pgpPubKeyLint"}, {3, "pgpPrtParams"},
        {3, "pgpDigParamsSignID"}, {3, "pgpDigParamsFree"},
        {3, "rpmBase64Decode"}, {3, "rpmKeyringAddKey"},
        {3, "rpmGetSubkeys"}, {3, "rpmPubkeyNew"},
        {3, "rpmPubkeyFree"}, {3, "rpmPubkeyFingerprintAsHex"},
        {3, "rpmPubkeyKeyIDAsHex"}, {3, "rpmDigestInit"},
        {3, "rpmDigestUpdate"}, {3, "rpmDigestFinal"},
        {0, "solver_create"}, {0, "solver_solve"},
        {0, "solver_free"}, {0, "solver_set_flag"},
        {0, "solver_problem_count"}, {0, "solver_problem2str"},
        {0, "solver_create_transaction"}, {0, "transaction_free"},
        {0, "transaction_order"}, {0, "transaction_type"}, {0, "selection_make"},
        {0, "selection_solvables"},
        {0, "queue_init"}, {0, "queue_free"},
        {0, "transaction_obs_pkg"},
        {0, "solver_get_decisionlevel"}, {0, "solvable_lookup_deparray"},
        {0, "pool_dep2str"}, {0, "pool_addrelproviders"}, {0, "pool_id2str"},
        {0, "pool_createwhatprovides"}, {0, "pool_setarch"},
        {0, "pool_solvable2str"},
        {0, "pool_set_rootdir"}, {0, "pool_set_installed"},
        {0, "repo_create"}, {0, "repo_free"},
        {0, "repo_internalize"}, {1, "repo_add_repomdxml"},
        {1, "repo_add_rpmdb"}, {0, "solvable_lookup_idarray"},
        {0, "solv_version"}, {0, "solv_version_major"},
        {0, "solv_version_minor"}, {0, "solv_version_patch"}
    };
    size_t index;
    for (index = 0; index < 4; ++index) {
        libraries[index].component = components[index];
        libraries[index].handle = dlopen(dnfast_soname(index), RTLD_NOW | RTLD_LOCAL);
        if (libraries[index].handle == NULL) {
            dnfast_status status = dnfast_set_error(
                error, DNFAST_STATUS_UNSUPPORTED_ABI, components[index], NULL,
                dlerror());
            dnfast_unload_libraries(libraries);
            return status;
        }
    }
    for (index = 0; index < sizeof(requirements) / sizeof(requirements[0]); ++index) {
        dlerror();
        if (dlsym(libraries[requirements[index].library].handle,
                  requirements[index].symbol) == NULL) {
            const char *detail = dlerror();
            const char *component = libraries[requirements[index].library].component;
            dnfast_status status = dnfast_set_error(
                error, DNFAST_STATUS_UNSUPPORTED_ABI, component,
                requirements[index].symbol, detail);
            dnfast_unload_libraries(libraries);
            return status;
        }
    }
#ifdef DNFAST_NATIVE_REAL
    if (solv_version_major != 0 || solv_version_minor != 7 ||
        solv_version_patch != 39 || strcmp(solv_version, "0.7.39") != 0) {
        dnfast_status status = dnfast_set_error(
            error, DNFAST_STATUS_UNSUPPORTED_ABI, "solv", "solv_version",
            "runtime libsolv version differs from locked ABI");
        dnfast_unload_libraries(libraries);
        return status;
    }
#endif
    return DNFAST_STATUS_OK;
}

void dnfast_unload_libraries(dnfast_library libraries[4]) {
    size_t index;
    for (index = 4; index > 0; --index) {
        if (libraries[index - 1].handle != NULL) {
            dlclose(libraries[index - 1].handle);
            libraries[index - 1].handle = NULL;
        }
    }
}
dnfast_limits dnfast_limits_default(void) {
    dnfast_limits limits = {
        .abi_version = DNFAST_NATIVE_ABI_VERSION,
        .max_packages = UINT32_C(2000000),
        .max_relations_per_package = UINT32_C(16384),
        .pool_architecture = DNFAST_POOL_ARCHITECTURE_INVALID,
        .max_metadata_bytes = UINT64_C(17179869184),
    };
    return limits;
}
