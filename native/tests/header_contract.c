#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <solv/pool.h>
#include <solv/repo_rpmmd.h>
#include <solv/solver.h>
#include <solv/solvversion.h>
#include <solv/transaction.h>

#include "dnfast_native.h"

#if LIBSOLV_VERSION_MAJOR != 0 || LIBSOLV_VERSION_MINOR != 7 ||              \
    LIBSOLV_VERSION_PATCH != 39
#error "dnfast requires libsolv 0.7.39 headers"
#endif

#ifndef RPMVSF_MASK_NOSIGNATURES
#error "RPM headers must expose verification flag macros"
#endif

_Static_assert(DNFAST_NATIVE_ABI_VERSION == 4, "unexpected dnfast ABI");
_Static_assert(offsetof(dnfast_solvable_reference, repository_id) == 0,
               "mapped reference repository field moved");
_Static_assert(offsetof(dnfast_solvable_reference, package_ordinal) >
                   offsetof(dnfast_solvable_reference, repository_id),
               "mapped reference ordinal field moved");
_Static_assert(offsetof(dnfast_solvable_reference, expected_identity) >
                   offsetof(dnfast_solvable_reference, package_ordinal),
               "mapped reference identity field moved");
_Static_assert(offsetof(dnfast_selector_providers, providers) >
                   offsetof(dnfast_selector_providers, selector_index),
               "mapped selector provider field moved");
_Static_assert(offsetof(dnfast_selector_providers, provider_count) >
                   offsetof(dnfast_selector_providers, providers),
               "mapped selector count field moved");
_Static_assert(
    _Generic(&dnfast_solver_prepare,
             dnfast_status (*)(dnfast_context *, dnfast_error *): 1,
             default: 0),
    "prepare signature changed");
_Static_assert(
    _Generic(&dnfast_solver_release_result,
             void (*)(dnfast_context *): 1,
             default: 0),
    "result release signature changed");
_Static_assert(
    _Generic(&dnfast_solver_solve_mapped_operation,
             dnfast_status (*)(dnfast_context *, const dnfast_solve_request *,
                               const dnfast_selector_providers *, size_t,
                               uint8_t, dnfast_error *): 1,
             default: 0),
    "mapped solve signature changed");
_Static_assert(
    _Generic(&dnfast_solver_set_module_excludes,
             dnfast_status (*)(dnfast_context *, const char *const *, size_t,
                               dnfast_error *): 1,
             default: 0),
    "module exclude signature changed");

int main(void) { return 0; }
