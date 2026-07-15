#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# Given: a successful focused probe reports its summary after publication.
# When: the public harness implementation is inspected.
# Then: only the atomic publisher may create the canonical receipt.
if sed -n '/^main_build()/,$p' "$ROOT/tools/fedora44-native-build.sh" | grep -Fq '>>"$X86_POOL_PROBE_RECEIPT"'; then
  echo 'main build unexpectedly writes the canonical x86 pool probe receipt' >&2
  exit 1
fi

# Given: a completed focused-probe staging area and a failed staging area.
# When: the harness executes its no-QEMU publication contract.
# Then: it must reject a premature canonical artifact, publish guest proof before
# the final receipt, and never publish a valid-looking final receipt for the
# failed case.
bash "$ROOT/tools/fedora44-native-build.sh" --test-x86-pool-probe-publication \
  | grep -Fqx 'x86_pool_probe_publication_contract=passed'
printf '%s\n' 'x86_pool_probe_publication_test=passed'
