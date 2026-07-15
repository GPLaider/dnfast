#!/usr/bin/env bash
set -euo pipefail

cd /home/fedora/src
export DNFAST_NATIVE_REAL=1

executor=/usr/libexec/dnfast-executor
dnfast=/usr/bin/dnfast
provision=/home/fedora/src/target/debug/examples/provision

inventory_digest() { rpm -qa | sort | sha256sum | awk '{print $1}'; }
plan_digest() { sudo sha256sum "$1" | awk '{print $1}'; }
input_root() { printf '/var/lib/dnfast/inputs/%s\n' "$(plan_digest "$1")"; }
assert_staging_empty() { ! sudo find /var/lib/dnfast/staging -mindepth 1 -print -quit | grep -q .; }

execute_yes() {
  local plan=$1
  sudo "$dnfast" apply "$plan" --assumeyes
}

execute_no() {
  local plan=$1
  sudo "$dnfast" apply "$plan" --assumeno
}

expect_failure() {
  if "$@"; then
    echo "unexpected executor success: $*" >&2
    exit 1
  fi
}

ttl=700
fresh_install() {
  local current=$ttl
  ttl=$((ttl + 1))
  sudo env DNFAST_NATIVE_REAL=1 DNFAST_PROVISION_TTL_SECONDS="$current" "$provision" install
}

wrong_install() {
  sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-executor --features test-fixtures --example provision -- wrong-install
}

vendor_mismatch_install() {
  sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-executor --features test-fixtures --example provision -- vendor-mismatch-install
}

repo_binding_install() {
  sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-executor --features test-fixtures --example provision -- repo-binding-install
}

prepare_two_repository_fixture() {
  local fixture=/tmp/dnfast-two-repository-fixture
  rm -rf "$fixture"
  DNFAST_FIXTURE_GUEST=1 tools/build-fixture-repo.sh "$fixture"
  test -f "$fixture/repos/main/dnfast-dep-1.0-1.noarch.rpm"
  test -f "$fixture/repos/alternate/dnfast-app-1.0-1.noarch.rpm"
  test -f "$fixture/keys/allowed.asc"
  test -f "$fixture/keys/alternate.asc"
  printf '%s\n' "$fixture"
}

two_repository_install() {
  local fixture=$1
  sudo env DNFAST_NATIVE_REAL=1 DNFAST_FIXTURE_ROOT="$fixture" cargo run --offline --locked -q -p dnfast-executor --features test-fixtures --example provision -- two-repo-install
}

wrong_key_two_repository_install() {
  local fixture=$1
  sudo env DNFAST_NATIVE_REAL=1 DNFAST_FIXTURE_ROOT="$fixture" cargo run --offline --locked -p dnfast-executor --features test-fixtures --example provision -- wrong-key-two-repo-install
}

wrong_key_provision_only() {
  local fixture plan
  fixture=$(prepare_two_repository_fixture)
  plan=$(wrong_key_two_repository_install "$fixture")
  printf 'wrong_key_provision_plan=%s\n' "$plan"
}

assert_two_repository_happy_matrix() {
  local fixture plan
  fixture=$(prepare_two_repository_fixture)
  plan=$(two_repository_install "$fixture")
  sudo grep -F '"repo_id":"alternate"' "$plan"
  sudo grep -F '"repo_id":"main"' "$plan"
  sudo cat "$(input_root "$plan")/alternate-trust.json"
  cargo run --offline --locked -q -p dnfast-native --example trust_probe -- "$fixture/keys/alternate.asc" "$fixture/repos/alternate/dnfast-app-1.0-1.noarch.rpm"
  cargo run --offline --locked -q -p dnfast-native --example trust_probe -- "$fixture/keys/allowed.asc" "$fixture/repos/two-repo-main/dnfast-dep-1.0-1.noarch.rpm"
  execute_yes "$plan"
  rpm -q dnfast-app dnfast-dep
  assert_staging_empty
  rm -rf "$fixture"
}

install_fixed_binaries() {
  sudo install -o root -g root -m 0755 target/debug/dnfast-executor "$executor"
  sudo install -o root -g root -m 0755 target/debug/dnfast "$dnfast"
}

assert_fixed_executor_boundary() {
  local actual=/tmp/dnfast-executor.actual probe=/tmp/dnfast-executor-boundary-probe
  gcc -std=c17 -Wall -Wextra -Werror tools/executor-boundary-probe.c -o "$probe"
  sudo install -o root -g root -m 0755 "$executor" "$actual"
  (
    trap 'sudo install -o root -g root -m 0755 "$actual" "$executor"; sudo rm -f "$actual"' EXIT
    sudo install -o root -g root -m 0755 "$probe" "$executor"
    local_plan=$(fresh_install)
    sudo env DNFAST_TEST_SENTINEL=must-not-survive bash -c "exec 9</dev/null; exec '$dnfast' apply '$local_plan'" | grep -Fx executor_boundary=passed
  )
  rm -f "$probe"
}

assert_direct_fd_boundary() {
  local plan before pty_probe pty_target
  expect_failure sudo bash -c "exec 3>&-; exec '$executor' --plan-fd 3 --assumeyes"
  expect_failure sudo bash -c "exec 3</dev/null; exec '$executor' --plan-fd 3 --assumeyes"
  pty_probe=/tmp/dnfast-pty-executor-probe
  pty_target=/tmp/dnfast-pty-fd3-target
  gcc -std=c17 -Wall -Wextra -Werror tools/pty-executor-probe.c -lutil -o "$pty_probe"
  gcc -std=c17 -Wall -Wextra -Werror tools/pty-fd3-target.c -o "$pty_target"
  "$pty_probe" >/tmp/dnfast-pty-probe-usage.log 2>&1 || test $? -eq 2
  grep -F 'usage:' /tmp/dnfast-pty-probe-usage.log
  "$pty_probe" "$pty_target" /etc/hosts >/tmp/dnfast-pty-fd3.log 2>&1
  grep -F 'fd3_exec=present' /tmp/dnfast-pty-fd3.log
  grep -Fx 'pty_exit=0' /tmp/dnfast-pty-fd3.log
  plan=$(fresh_install)
  before=$(inventory_digest)
  test "${executor#/}" != "$executor"
  test "${plan#/}" != "$plan"
  sudo "$pty_probe" "$executor" "$plan" >/tmp/dnfast-pty-default-no.log 2>&1 || {
    status=$?
    cat /tmp/dnfast-pty-default-no.log >&2
    printf 'pty_default_no_exit=%s\n' "$status" >&2
    return "$status"
  }
  grep -Fx 'pty_args=2' /tmp/dnfast-pty-default-no.log
  grep -F 'Continue? [y/N]' /tmp/dnfast-pty-default-no.log
  grep -F 'pty_exit=0' /tmp/dnfast-pty-default-no.log
  plan=$(fresh_install)
  before=$(inventory_digest)
  sudo "$pty_probe" --public-apply "$dnfast" "$plan" >/tmp/dnfast-public-pty-default-no.log 2>&1 || {
    status=$?
    cat /tmp/dnfast-public-pty-default-no.log >&2
    printf 'public_pty_default_no_exit=%s\n' "$status" >&2
    return "$status"
  }
  grep -Fx 'pty_public_apply=1' /tmp/dnfast-public-pty-default-no.log
  grep -F 'plan_sha256=' /tmp/dnfast-public-pty-default-no.log
  grep -F 'plan_action[0]={"operation":"install","name":"dnfast-noarch"' /tmp/dnfast-public-pty-default-no.log
  grep -F 'Continue? [y/N]' /tmp/dnfast-public-pty-default-no.log
  grep -F 'pty_exit=0' /tmp/dnfast-public-pty-default-no.log
  test "$before" = "$(inventory_digest)"
  assert_staging_empty
  rm -f "$pty_probe" "$pty_target"
  test "$before" = "$(inventory_digest)"
  assert_staging_empty
}

assert_sigkill_recovery() {
  local id=018f1234-5678-7abc-8def-0123456789ab seed pid plan status=0 before journal_dir
  journal_dir="/var/lib/dnfast/transactions/$id"
  before=$(inventory_digest)
  sudo rm -rf "/var/lib/dnfast/transactions/$id"
  sudo target/debug/examples/recovery_seed >/tmp/dnfast-recovery-seed.log 2>&1 &
  seed=$!
  for _ in $(seq 1 100); do
    grep -Fx "recovery_seed_started=$id" /tmp/dnfast-recovery-seed.log >/dev/null 2>&1 && break
    sleep 0.1
  done
  grep -Fx "recovery_seed_started=$id" /tmp/dnfast-recovery-seed.log
  pid=$(sed -n 's/^recovery_seed_pid=//p' /tmp/dnfast-recovery-seed.log)
  test -n "$pid"
  sudo kill -KILL "$pid"
  wait "$seed" || status=$?
  test "$status" -eq 137
  plan=$(fresh_install)
  execute_no "$plan"
  sudo grep -R -F --include='*.json' '"state":"rpm_result"' "$journal_dir"
  sudo grep -R -F --include='*.json' '"return_code":-1' "$journal_dir"
  sudo grep -R -F --include='*.json' '"state":"reconciled"' "$journal_dir"
  sudo grep -R -F --include='*.json' '"success":false' "$journal_dir"
  test "$before" = "$(inventory_digest)"
  assert_staging_empty
}

if [[ ${DNFAST_RECOVERY_ONLY:-0} == 1 ]]; then
  before=$(inventory_digest)
  install_fixed_binaries
  for directory in /var/lib/dnfast/transactions /var/lib/dnfast/staging; do
    sudo install -d -o root -g root -m 0700 "$directory"
    test "$(sudo stat -c '%u:%g:%a' "$directory")" = '0:0:700'
  done
  test "$before" = "$(inventory_digest)"
  assert_staging_empty
  assert_sigkill_recovery
  echo "executor_qemu_recovery=passed"
  exit 0
fi

if [[ ${DNFAST_EXECUTOR_PTY_ONLY:-0} == 1 ]]; then
  install_fixed_binaries
  assert_fixed_executor_boundary
  assert_direct_fd_boundary
  echo "executor_qemu_pty=passed"
  exit 0
fi

if [[ ${DNFAST_MULTI_REPO_ONLY:-0} == 1 ]]; then
  echo "DNFAST_MULTI_REPO_ONLY is forbidden: use host detached wrong-key orchestration" >&2
  exit 64
fi

if [[ ${DNFAST_WRONG_KEY_PROVISION_ONLY:-0} == 1 ]]; then
  wrong_key_provision_only
  echo "executor_qemu_wrong_key_provision=completed"
  exit 0
fi

if [[ ${DNFAST_MULTI_REPO_HAPPY_ONLY:-0} == 1 ]]; then
  install_fixed_binaries
  assert_two_repository_happy_matrix
  echo "executor_qemu_two_repository_happy=passed"
  exit 0
fi

install_fixed_binaries
assert_fixed_executor_boundary
assert_direct_fd_boundary
assert_sigkill_recovery
assert_two_repository_happy_matrix

before=$(inventory_digest)
plan=$(fresh_install)
execute_no "$plan"
test "$before" = "$(inventory_digest)"
assert_staging_empty

plan=$(fresh_install)
expect_failure sudo setpriv --reuid=fedora --regid=fedora --clear-groups "$dnfast" apply "$plan" --assumeyes

expired=$(sudo env DNFAST_NATIVE_REAL=1 DNFAST_PROVISION_TTL_SECONDS=0 "$provision" install)
before=$(inventory_digest)
expect_failure execute_yes "$expired"
test "$before" = "$(inventory_digest)"

plan=$(wrong_install)
before=$(inventory_digest)
if execute_yes "$plan" >/tmp/dnfast-canonical-mismatch.log 2>&1; then
  echo "canonical mismatch proposal unexpectedly executed" >&2
  exit 1
fi
grep -F 'root re-solve action bytes differ' /tmp/dnfast-canonical-mismatch.log
test "$before" = "$(inventory_digest)"
assert_staging_empty

plan=$(vendor_mismatch_install)
before=$(inventory_digest)
if execute_yes "$plan" >/tmp/dnfast-vendor-mismatch.log 2>&1; then
  echo "signed RPM with mismatched rpm-md Vendor unexpectedly executed" >&2
  exit 1
fi
grep -F 'RPM header Vendor differs from rpm-md and plan' /tmp/dnfast-vendor-mismatch.log
test "$before" = "$(inventory_digest)"
assert_staging_empty

plan=$(repo_binding_install)
before=$(inventory_digest)
if execute_yes "$plan" >/tmp/dnfast-repo-binding-mismatch.log 2>&1; then
  echo "cross-repository artifact unexpectedly executed" >&2
  exit 1
fi
grep -F 'artifact does not match proposal' /tmp/dnfast-repo-binding-mismatch.log
test "$before" = "$(inventory_digest)"
assert_staging_empty

plan=$(fresh_install)
before=$(inventory_digest)
sudo sh -c "printf x > '$plan'"
expect_failure execute_yes "$plan"
test "$before" = "$(inventory_digest)"

for file in policy.json main-trust.json main-repomd main-primary main-filelists main-key artifact-dnfast-noarch; do
  plan=$(fresh_install)
  root=$(input_root "$plan")
  before=$(inventory_digest)
  sudo sh -c "printf x > '$root/$file'"
  expect_failure execute_yes "$plan"
  test "$before" = "$(inventory_digest)"
done

for kind in symlink hardlink; do
  plan=$(fresh_install)
  root=$(input_root "$plan")
  before=$(inventory_digest)
  if [[ $kind == symlink ]]; then
    sudo mv "$root/policy.json" "$root/policy.original"
    sudo ln -s policy.original "$root/policy.json"
  else
    sudo ln "$root/policy.json" "$root/policy.alias"
  fi
  expect_failure execute_yes "$plan"
  test "$before" = "$(inventory_digest)"
done

plan=$(fresh_install)
before=$(inventory_digest)
sudo mv /var/lib/dnfast/inputs /var/lib/dnfast/inputs.real
sudo ln -s inputs.real /var/lib/dnfast/inputs
expect_failure execute_yes "$plan"
sudo rm /var/lib/dnfast/inputs
sudo mv /var/lib/dnfast/inputs.real /var/lib/dnfast/inputs
test "$before" = "$(inventory_digest)"

plan=$(fresh_install)
execute_yes "$plan"
expect_failure execute_yes "$plan"
sudo rpm -e dnfast-noarch

plan=$(fresh_install)
sudo rpm -i fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm
before=$(inventory_digest)
expect_failure execute_yes "$plan"
test "$before" = "$(inventory_digest)"
sudo rpm -e dnfast-noarch

assert_staging_empty
echo "executor_qemu_matrix=passed"
