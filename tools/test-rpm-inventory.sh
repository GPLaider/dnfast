#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURE="$ROOT/fixtures/rpm/generated-build10/repos"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/dnfast-inventory.XXXXXX")
HOLDER=
trap '[[ -z $HOLDER ]] || sudo kill -KILL "$HOLDER" 2>/dev/null || true; rm -rf "$TMP"; sudo rm -rf /run/dnfast' EXIT INT TERM HUP
export DNFAST_NATIVE_REAL=1

inventory() { cargo run -q --offline --locked -p dnfast-native --example inventory; }
solve() { cargo run -q --offline --locked -p dnfast-native --example solve -- "$@"; }
gate() { sudo env DNFAST_NATIVE_REAL=1 ASAN_OPTIONS="${ASAN_OPTIONS:-}" target/debug/examples/inventory_gate "$@" </dev/null; }
repo() {
  local directory="$FIXTURE/main/repodata"
  zstd -qdf "$directory/primary.xml.zst" -o "$TMP/primary.xml"
  zstd -qdf "$directory/filelists.xml.zst" -o "$TMP/filelists.xml"
  printf 'main,%s,%s,%s,99,1000' "$directory/repomd.xml" "$TMP/primary.xml" "$TMP/filelists.xml"
}

sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 /run/dnfast
gcc -std=c17 -Wall -Wextra -Werror native/tests/rpm_write_holder.c $(pkg-config --cflags --libs rpm) -o "$TMP/rpm-write-holder"
cargo build -q --offline --locked -p dnfast-native --features test-fixtures --example inventory_gate
START_NS=$(date +%s%N)
if target/debug/examples/inventory_gate >"$TMP/nonroot.out" 2>&1; then exit 1; fi
ELAPSED_NS=$(($(date +%s%N) - START_NS))
[[ $ELAPSED_NS -lt 2000000000 ]]
grep -Eq 'PermissionDenied|root execution required' "$TMP/nonroot.out"
BEFORE=$(inventory)
[[ $(inventory) == "$BEFORE" ]]
grep -q '^rpm_version=6.0.1$' <<<"$BEFORE"
grep -Eq '^backend=.+$' <<<"$BEFORE"
if grep -q '^package=gpg-pubkey ' <<<"$BEFORE"; then grep -q '^package=gpg-pubkey .* arch=Noarch ' <<<"$BEFORE"; fi
HAPPY_GATE=$(gate)
grep -q 'test_count=1' <<<"$HAPPY_GATE"
grep -q 'real_run_count=2' <<<"$HAPPY_GATE"
CANCEL_GATE=$(gate --cancel-before)
grep -q 'pre_start_cancel_released=true' <<<"$CANCEL_GATE"
TEST_FAIL=$(gate --test-fail)
grep -q 'test_failed=-99 test_calls=1 real_calls=0' <<<"$TEST_FAIL"
MUTATION="$FIXTURE/main/dnfast-dep-1.0-1.noarch.rpm"
STALE=$(gate "$MUTATION")
grep -q 'stale_inventory=true' <<<"$STALE"
grep -q 'real_run_count=0' <<<"$STALE"
AFTER=$(inventory)
[[ $(sed -n 's/^digest=//p' <<<"$BEFORE") != $(sed -n 's/^digest=//p' <<<"$AFTER") ]]
grep -q '^package=dnfast-dep ' <<<"$AFTER"
CONTENTION=$(gate --contention "$TMP/rpm-write-holder" "$TMP/native-lock-ready")
ELAPSED=$(sed -n 's/^contention_elapsed=//p' <<<"$CONTENTION")
[[ $ELAPSED -ge 29 && $ELAPSED -le 31 ]]
rm -f "$TMP/native-lock-ready"
INTERRUPTED=$(gate --interrupt-contention "$TMP/rpm-write-holder" "$TMP/native-lock-ready")
grep -q 'interrupted_promptly=true test_calls=0 real_calls=0' <<<"$INTERRUPTED"
MAIN=$(repo)
RESULT=$(DNFAST_RPMDB_ROOT=/ solve dnfast-app no-weak "$MAIN")
grep -q 'dnfast-app-0:1.0-1.noarch' <<<"$RESULT"
! grep -q 'dnfast-dep-0:1.0-1.noarch' <<<"$RESULT"
sudo rpm --nodeps --nosignature -i "$FIXTURE/main/dnfast-upgrade-1.0-1.noarch.rpm"
sudo rpm --nodeps --nosignature --replacefiles -i "$FIXTURE/main/dnfast-upgrade-2.0-1.noarch.rpm"
DUPLICATES=$(inventory)
[[ $(grep -c '^package=dnfast-upgrade ' <<<"$DUPLICATES") -eq 2 ]]
[[ $(grep '^package=dnfast-upgrade ' <<<"$DUPLICATES" | sed -n 's/.* instance=\([0-9]*\).*/\1/p' | sort -u | wc -l) -eq 2 ]]
[[ $(grep '^package=dnfast-upgrade ' <<<"$DUPLICATES" | sed -n 's/.* header=\([0-9a-f]*\)$/\1/p' | sort -u | wc -l) -eq 2 ]]
sudo rpm --nodeps -e dnfast-dep
sudo rpm --nodeps -e --allmatches dnfast-upgrade
DBPATH=$(rpm --eval '%{_dbpath}')
DBFILE=$(find "$DBPATH" -maxdepth 1 -type f -name '*.sqlite' | head -1)
[[ -n $DBFILE ]]
MODE=$(stat -c %a "$DBFILE")
sudo chmod 000 "$DBFILE"
if inventory >"$TMP/unreadable.out" 2>&1; then exit 1; fi
sudo chmod "$MODE" "$DBFILE"
sudo cp -a "$DBFILE" "$TMP/rpmdb.saved"
sudo truncate -s 17 "$DBFILE"
if inventory >"$TMP/corrupt.out" 2>&1; then exit 1; fi
sudo cp -a "$TMP/rpmdb.saved" "$DBFILE"
rpm --verifydb
printf '%s\n' \
  'assert identical-state-digest=true' \
  'assert header-change-digest=true' \
  'assert stale-real-run-zero=true' \
  'assert native-rpm-lock-deadline=true' \
  'assert native-rpm-lock-interrupt=true' \
  'assert test-failure-real-zero=true' \
  'assert installed-provider-no-redundant=true' \
  'assert duplicate-instances-distinct=true' \
  'assert corrupt-unreadable-fail=true' \
  'assert rpmdb-verify=true'
