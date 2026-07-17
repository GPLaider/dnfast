#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/dnfast-symbols.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM HUP
TOOLROOT=${FEDORA44_TOOLROOT:-$ROOT/.cache/fedora44-vm/toolroot}
export PKG_CONFIG_PATH="$TOOLROOT/usr/lib64/pkgconfig:$TOOLROOT/usr/share/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$TOOLROOT"

for source in common solver decisions actions installed inventory inventory_write transaction transaction_run transaction_result transaction_payload_fault keyring keyring_identity rpm_signature rpm_payload limits metadata_io modulemd rpm callbacks; do
  cc -std=c17 -Wno-unused-parameter -DDNFAST_NATIVE_REAL -I"$ROOT/native/include" \
    -I"$ROOT/native/src" $(pkg-config --cflags libsolv rpm modulemd-2.0) \
    -c "$ROOT/native/src/$source.c" -o "$TMP/$source.o"
done
nm -u "$TMP"/*.o | awk '{print $NF}' | sort -u >"$TMP/undefined"
nm -g --defined-only "$TMP/actions.o" | awk '{print $NF}' | sort -u >"$TMP/actions-defined"
grep -Fxq dnfast_solver_action_requested_relation_kind "$TMP/actions-defined"
nm -D --defined-only "$TOOLROOT/usr/lib64/libsolv.so.1" \
  "$TOOLROOT/usr/lib64/libsolvext.so.1" "$TOOLROOT/usr/lib64/librpm.so.10" \
  "$TOOLROOT/usr/lib64/librpmio.so.10" | awk '{print $3}' | sed 's/@@.*//' | sort -u >"$TMP/native"
comm -12 "$TMP/undefined" "$TMP/native" >"$TMP/used"
while IFS= read -r symbol; do
  grep -Fq "\"$symbol\"" "$ROOT/native/src/common.c" || {
    echo "native symbol missing from preallocation probe: $symbol" >&2
    exit 1
  }
done <"$TMP/used"
grep -Fxq queue_init "$TMP/used"
grep -Fxq queue_free "$TMP/used"
printf 'assert runtime-symbol-coverage=true count=%s\n' "$(wc -l <"$TMP/used")"
