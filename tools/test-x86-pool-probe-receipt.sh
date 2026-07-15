#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d "$ROOT/.x86-pool-probe-receipt.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM HUP

RECEIPT="$TMP/receipt.log"
GUEST_LOG="$TMP/x86-pool-probe-guest.log"
OTHER_GUEST_LOG="$TMP/other-guest.log"
printf 'guest transcript\n' >"$GUEST_LOG"
printf 'other transcript\n' >"$OTHER_GUEST_LOG"
GUEST_LOG_HASH=$(sha256sum "$GUEST_LOG" | awk '{print $1}')

{
  printf '%s\n' \
    'x86_pool_probe_receipt_format=1' \
    'x86_pool_probe_native_tests=passed' \
    'native_pool_arch=x86_64 noarch_solve=passed' \
    'x86_pool_probe_runtime_cleanup=completed status=0' \
    'x86_pool_probe_host_harness_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
    'x86_pool_probe_source_harness_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
    'x86_pool_probe_source_rpm_c_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
    'x86_pool_probe_source_native_rs_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
    'x86_pool_probe_binary_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
    'x86_pool_probe_result_sha256=0000000000000000000000000000000000000000000000000000000000000000'
  printf 'x86_pool_probe_guest_log=%s\n' "$(realpath -e -- "$GUEST_LOG")"
  printf 'x86_pool_probe_guest_log_sha256=%s\n' "$GUEST_LOG_HASH"
} >"$RECEIPT"

RELATIVE_RECEIPT=${RECEIPT#"$ROOT"/}
bash "$ROOT/tools/fedora44-native-build.sh" --validate-x86-pool-probe-receipt "$RELATIVE_RECEIPT" \
  | grep -Fqx "x86_pool_probe_receipt_validation=passed file=$(realpath -e -- "$RECEIPT")"

sed -i "s|^x86_pool_probe_guest_log=.*|x86_pool_probe_guest_log=$(realpath -e -- "$OTHER_GUEST_LOG")|" "$RECEIPT"
if bash "$ROOT/tools/fedora44-native-build.sh" --validate-x86-pool-probe-receipt "$RELATIVE_RECEIPT" >"$TMP/malicious.out" 2>&1; then
  echo 'malicious guest transcript binding unexpectedly accepted' >&2
  exit 1
fi
grep -Fqx 'fedora44-vm: x86 pool probe guest transcript binding missing' "$TMP/malicious.out"
printf '%s\n' 'x86_pool_probe_receipt_relative-and-malicious-binding=passed'
