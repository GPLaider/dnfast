#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COMMON="$ROOT/tools/fedora44-vm-common.sh"
BUILDER="$ROOT/tools/fedora44-native-build.sh"
PASS=0

expect_ok() {
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); else echo "not ok - $name"; exit 1; fi
}

expect_fail() {
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then echo "not ok - $name"; exit 1; else PASS=$((PASS + 1)); fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Given: the checked-in immutable manifests. When: validating them. Then: both pass.
expect_ok "canonical locks validate" "$COMMON" validate-locks

# Given: an errexit caller. When: sourcing common helpers. Then: sourcing returns successfully.
expect_ok "common helpers are source-safe" bash -euo pipefail -c 'source "$1"; type validate_locks >/dev/null' _ "$COMMON"

# Given: probe mode. When: inspecting its guest contract. Then: happy and hidden rpmtsRun probes are mandatory.
expect_ok "probe includes hidden rpmtsRun failure" grep -q 'DNFAST_HIDE_RPMTSRUN' "$BUILDER"
expect_ok "guest enables real native backend" grep -q 'export DNFAST_NATIVE_REAL=1' "$BUILDER"

# Given: a URL lock with a modified hash. When: validating it. Then: validation fails closed.
cp "$ROOT/.omo/evidence/fedora44-build-qemu-closure-urls.lock" "$tmp/urls"
sed -i '1s/^./0/' "$tmp/urls"
expect_fail "tampered URL lock rejected" env FEDORA44_URL_LOCK="$tmp/urls" "$COMMON" validate-locks

# Given: a correctly shaped but third-party URL row. When: parsing it. Then: allowlisting rejects it.
read -r row_hash row_file row_url <"$ROOT/.omo/evidence/fedora44-build-qemu-closure-urls.lock"
expect_fail "third-party URL rejected" "$COMMON" validate-url-row "$row_hash" "$row_file" "https://evil.example/$row_file"

# Given: a top-level index with the same basename on an evil host. When: cross-checking it. Then: exact URL equality rejects it.
cp "$ROOT/.omo/evidence/fedora44-top-level-rpm-urls.txt" "$tmp/top-urls"
sed -i '3s#https://[^/]\+#https://evil.example#' "$tmp/top-urls"
expect_fail "evil same-basename top-level URL rejected" env FEDORA44_TOP_URLS="$tmp/top-urls" "$COMMON" validate-locks

# Given: the wrong host architecture. When: preflight runs. Then: it fails before mutation.
expect_fail "wrong host architecture rejected" env FEDORA44_UNAME_M=x86_64 "$COMMON" preflight

# Given: an unwritable KVM override. When: preflight runs. Then: no TCG fallback is accepted.
expect_fail "missing KVM rejected" env FEDORA44_KVM="$tmp/missing" "$COMMON" preflight

# Given: temporary runtime artifacts. When: cleanup runs. Then: all are removed.
mkdir "$tmp/runtime"; : >"$tmp/runtime/socket"
expect_ok "runtime cleanup succeeds" "$COMMON" cleanup "$tmp/runtime"
test ! -e "$tmp/runtime" || { echo "not ok - runtime cleanup removes directory"; exit 1; }
PASS=$((PASS + 1))

echo "ok $PASS Fedora 44 VM contracts"
