#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILDER=${DNFAST_NATIVE_BUILD:-"$ROOT/tools/fedora44-native-build.sh"}

[[ -f $BUILDER ]] || {
  printf 'requested-spec NULL contract: native build harness is missing: %s\n' "$BUILDER" >&2
  exit 1
}

normal_count=$(grep -Ec 'native_requested_spec_null_contract_lane=normal.*native/tests/requested_spec_null_contract\.c' "$BUILDER" || true)
sanitize_count=$(grep -Ec 'native_requested_spec_null_contract_lane=asan-ubsan.*native/tests/requested_spec_null_contract\.c' "$BUILDER" || true)
all_count=$(grep -Fc 'native/tests/requested_spec_null_contract.c' "$BUILDER" || true)

[[ $normal_count == 1 ]] || {
  printf 'requested-spec NULL contract: normal native test lane is not wired exactly once\n' >&2
  exit 1
}
[[ $sanitize_count == 1 ]] || {
  printf 'requested-spec NULL contract: ASAN/UBSAN native test lane is not wired exactly once\n' >&2
  exit 1
}
[[ $all_count == 2 ]] || {
  printf 'requested-spec NULL contract: test must be wired only in the normal and ASAN/UBSAN lanes\n' >&2
  exit 1
}
grep -Eq 'native_requested_spec_null_contract_lane=asan-ubsan.*ASAN_OPTIONS=.*UBSAN_OPTIONS=.*requested-spec-null-contract' "$BUILDER" || {
  printf 'requested-spec NULL contract: sanitizer runtime options are missing\n' >&2
  exit 1
}
grep -Eq 'native_requested_spec_null_contract_lane=normal.*pkg-config --cflags libsolv rpm.*pkg-config --libs libsolv rpm.*-lsolvext -ldl -lpthread' "$BUILDER" || {
  printf 'requested-spec NULL contract: normal lane does not use the pinned native compile/link contract\n' >&2
  exit 1
}

printf '%s\n' 'requested_spec_null_contract_wiring=passed'
