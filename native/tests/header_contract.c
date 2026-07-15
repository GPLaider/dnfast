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

_Static_assert(DNFAST_NATIVE_ABI_VERSION == 3, "unexpected dnfast ABI");

int main(void) { return 0; }
