#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d "$ROOT/.x86-pool-probe-lifecycle.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT INT TERM HUP

# Given: a caller invokes the no-QEMU focused-probe lifecycle contract.
# When: the harness returns success.
# Then: the caller can validate both canonical proof artifacts immediately.
DNFAST_X86_POOL_PROBE_LIFECYCLE_DIR="$TMP" \
  bash "$ROOT/tools/fedora44-native-build.sh" --test-x86-pool-probe-lifecycle \
  | grep -Fqx 'x86_pool_probe_lifecycle_contract=passed'

receipt="$TMP/task-1-x86-pool-probe-qemu.log"
guest_log="$TMP/x86-pool-probe-guest.log"
test -s "$receipt"
test -s "$guest_log"
if find "$TMP" -maxdepth 1 -type d -name '.task-1-x86-pool-probe-qemu.log.stage.*' -print -quit | grep -q .; then
  echo 'x86 pool probe lifecycle left a staging directory after caller-visible completion' >&2
  exit 1
fi
bash "$ROOT/tools/fedora44-native-build.sh" --validate-x86-pool-probe-receipt "$receipt" \
  | grep -Fqx "x86_pool_probe_receipt_validation=passed file=$receipt"
printf '%s\n' 'x86_pool_probe_lifecycle_test=passed'
