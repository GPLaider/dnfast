#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/tools/fedora44-vm-common.sh"

SANITIZE=0
PROBE=0
KEEP_CACHE=0
INVENTORY_ONLY=0
RECOVERY_ONLY=0
EXECUTOR_PTY_ONLY=0
MULTI_REPO_ONLY=0
MULTI_REPO_WRONG_KEY_DIAGNOSTIC=0
WRONG_KEY_APPLY_MARKER_TEST=0
X86_POOL_PROBE=0
X86_POOL_PROBE_RECEIPT=
X86_POOL_PROBE_GUEST_LOG=
X86_POOL_PROBE_VALIDATE_RECEIPT=
X86_POOL_PROBE_PUBLICATION_TEST=0
X86_POOL_PROBE_LIFECYCLE_TEST=0
X86_POOL_PROBE_STAGE_DIR=
X86_POOL_PROBE_STAGE_RECEIPT=
X86_POOL_PROBE_STAGE_GUEST_LOG=
X86_POOL_PROBE_LOCK_FD=
WORK=${FEDORA44_WORK:-"$ROOT/.cache/fedora44-vm"}

usage() {
  echo "usage: $0 [--sanitize] [--probe] [--x86-pool-probe] [--validate-x86-pool-probe-receipt FILE] [--test-x86-pool-probe-publication] [--test-x86-pool-probe-lifecycle] [--test-wrong-key-apply-marker-contract] [--recovery-only] [--executor-pty-only] [--executor-multirepo-only] [--executor-multirepo-wrong-key-diagnostic] [--work DIR] [--keep-cache]"
}

while (($#)); do
  case $1 in
    --sanitize) SANITIZE=1 ;;
    --probe) PROBE=1 ;;
    --keep-cache) KEEP_CACHE=1 ;;
    --inventory-only) INVENTORY_ONLY=1 ;;
    --recovery-only) RECOVERY_ONLY=1 ;;
    --executor-pty-only) EXECUTOR_PTY_ONLY=1 ;;
    --executor-multirepo-only) MULTI_REPO_ONLY=1 ;;
    --executor-multirepo-wrong-key-diagnostic) MULTI_REPO_WRONG_KEY_DIAGNOSTIC=1 ;;
    --test-wrong-key-apply-marker-contract) WRONG_KEY_APPLY_MARKER_TEST=1 ;;
    --x86-pool-probe) X86_POOL_PROBE=1 ;;
    --validate-x86-pool-probe-receipt) shift; X86_POOL_PROBE_VALIDATE_RECEIPT=${1:?--validate-x86-pool-probe-receipt requires a file} ;;
    --test-x86-pool-probe-publication) X86_POOL_PROBE_PUBLICATION_TEST=1 ;;
    --test-x86-pool-probe-lifecycle) X86_POOL_PROBE=1; X86_POOL_PROBE_LIFECYCLE_TEST=1 ;;
    --work) shift; WORK=${1:?--work requires a directory} ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

if ((X86_POOL_PROBE)); then
  X86_POOL_PROBE_RECEIPT=${DNFAST_X86_POOL_PROBE_RECEIPT:-"$ROOT/.omo/evidence/task-1-x86-pool-probe-qemu.log"}
  X86_POOL_PROBE_GUEST_LOG="$(dirname "$X86_POOL_PROBE_RECEIPT")/x86-pool-probe-guest.log"
fi

RUNTIME=$(mktemp -d "${TMPDIR:-/tmp}/dnfast-f44.XXXXXX")
TOOLROOT="$WORK/toolroot"
PORT=

finish() {
  local status=$?
  if ((status != 0)) && [[ -f $RUNTIME/serial.log ]]; then cp "$RUNTIME/serial.log" "$WORK/last-serial.log"; fi
  cleanup "$RUNTIME"
  if ((X86_POOL_PROBE)); then
    discard_x86_pool_probe_stage
  fi
  ((KEEP_CACHE)) || rm -rf "$WORK/staging"
  exit "$status"
}
trap finish EXIT INT TERM HUP

prepare_x86_pool_probe_receipt() {
  local receipt_dir receipt_name
  receipt_dir=$(dirname "$X86_POOL_PROBE_RECEIPT")
  receipt_name=$(basename "$X86_POOL_PROBE_RECEIPT")
  mkdir -p "$receipt_dir"
  exec {X86_POOL_PROBE_LOCK_FD}>"$receipt_dir/.${receipt_name}.lock"
  flock -n "$X86_POOL_PROBE_LOCK_FD" || die "x86 pool probe publication already in progress: $X86_POOL_PROBE_RECEIPT"
  rm -f -- "$X86_POOL_PROBE_RECEIPT" "$X86_POOL_PROBE_GUEST_LOG"
  X86_POOL_PROBE_STAGE_DIR=$(mktemp -d "$receipt_dir/.${receipt_name}.stage.XXXXXX")
  X86_POOL_PROBE_STAGE_RECEIPT="$X86_POOL_PROBE_STAGE_DIR/receipt.log"
  X86_POOL_PROBE_STAGE_GUEST_LOG="$X86_POOL_PROBE_STAGE_DIR/x86-pool-probe-guest.log"
  {
    printf 'x86_pool_probe_receipt_format=1\n'
    printf 'x86_pool_probe_host_harness_sha256=%s\n' "$(sha256sum "$ROOT/tools/fedora44-native-build.sh" | awk '{print $1}')"
    printf 'x86_pool_probe_guest_log=%s\n' "$X86_POOL_PROBE_STAGE_GUEST_LOG"
  } >"$X86_POOL_PROBE_STAGE_RECEIPT"
}

discard_x86_pool_probe_stage() {
  if [[ -n $X86_POOL_PROBE_STAGE_DIR ]]; then
    rm -rf -- "$X86_POOL_PROBE_STAGE_DIR"
  fi
  X86_POOL_PROBE_STAGE_DIR=
  X86_POOL_PROBE_STAGE_RECEIPT=
  X86_POOL_PROBE_STAGE_GUEST_LOG=
}

publish_x86_pool_probe_receipt() {
  local receipt_dir receipt_name receipt_tmp guest_log_hash
  [[ -n $X86_POOL_PROBE_STAGE_DIR && -s $X86_POOL_PROBE_STAGE_RECEIPT && -s $X86_POOL_PROBE_STAGE_GUEST_LOG ]] || {
    printf 'fedora44-vm: x86 pool probe staging artifacts are incomplete\n' >&2
    return 1
  }
  [[ ! -e $X86_POOL_PROBE_RECEIPT && ! -e $X86_POOL_PROBE_GUEST_LOG ]] || {
    printf 'fedora44-vm: x86 pool probe canonical artifacts unexpectedly exist before publication\n' >&2
    return 1
  }
  receipt_dir=$(dirname "$X86_POOL_PROBE_RECEIPT")
  receipt_name=$(basename "$X86_POOL_PROBE_RECEIPT")
  receipt_tmp=$(mktemp "$receipt_dir/.${receipt_name}.publish.XXXXXX")
  guest_log_hash=$(sha256sum "$X86_POOL_PROBE_STAGE_GUEST_LOG" | awk '{print $1}')
  if ! awk '!/^x86_pool_probe_guest_log=/' "$X86_POOL_PROBE_STAGE_RECEIPT" >"$receipt_tmp"; then
    rm -f -- "$receipt_tmp"
    return 1
  fi
  {
    printf 'x86_pool_probe_guest_log=%s\n' "$X86_POOL_PROBE_GUEST_LOG"
    printf 'x86_pool_probe_guest_log_sha256=%s\n' "$guest_log_hash"
    printf 'x86_pool_probe_runtime_cleanup=completed status=0\n'
  } >>"$receipt_tmp"
  if ! mv -- "$X86_POOL_PROBE_STAGE_GUEST_LOG" "$X86_POOL_PROBE_GUEST_LOG"; then
    rm -f -- "$receipt_tmp"
    return 1
  fi
  if [[ -e $X86_POOL_PROBE_RECEIPT ]] || ! (validate_x86_pool_probe_receipt "$receipt_tmp" >/dev/null); then
    rm -f -- "$receipt_tmp" "$X86_POOL_PROBE_GUEST_LOG"
    return 1
  fi
  if ! mv -- "$receipt_tmp" "$X86_POOL_PROBE_RECEIPT"; then
    rm -f -- "$receipt_tmp" "$X86_POOL_PROBE_GUEST_LOG"
    return 1
  fi
  discard_x86_pool_probe_stage
}

complete_x86_pool_probe() {
  if [[ -n $RUNTIME ]]; then
    cleanup "$RUNTIME"
    RUNTIME=
  fi
  publish_x86_pool_probe_receipt || return 1
  validate_x86_pool_probe_receipt "$X86_POOL_PROBE_RECEIPT" >/dev/null
  printf 'x86_pool_probe_completion=published-and-validated receipt=%s\n' "$X86_POOL_PROBE_RECEIPT"
}

validate_x86_pool_probe_receipt() {
  local receipt=$1 key value guest_log bound_guest_log guest_log_hash
  receipt=$(realpath -e -- "$receipt") || die "x86 pool probe receipt is not readable: $1"
  [[ -r $receipt ]] || die "x86 pool probe receipt is not readable: $receipt"
  grep -Fqx 'x86_pool_probe_receipt_format=1' "$receipt" || die "x86 pool probe receipt format marker missing"
  grep -Fqx 'x86_pool_probe_native_tests=passed' "$receipt" || die "x86 pool probe native test marker missing"
  grep -Fqx 'native_pool_arch=x86_64 noarch_solve=passed' "$receipt" || die "x86 pool probe result marker missing"
  grep -Fqx 'x86_pool_probe_runtime_cleanup=completed status=0' "$receipt" || die "x86 pool probe cleanup marker missing"
  guest_log=$(realpath -e -- "$(dirname "$receipt")/x86-pool-probe-guest.log") || die "x86 pool probe guest transcript missing or empty: $(dirname "$receipt")/x86-pool-probe-guest.log"
  [[ $(grep -c '^x86_pool_probe_guest_log=' "$receipt") -eq 1 ]] || die "x86 pool probe guest transcript binding missing"
  bound_guest_log=$(sed -n 's/^x86_pool_probe_guest_log=//p' "$receipt")
  bound_guest_log=$(realpath -e -- "$bound_guest_log") || die "x86 pool probe guest transcript binding missing"
  [[ $bound_guest_log == "$guest_log" ]] || die "x86 pool probe guest transcript binding missing"
  [[ -s $guest_log ]] || die "x86 pool probe guest transcript missing or empty: $guest_log"
  for key in \
    x86_pool_probe_host_harness_sha256 \
    x86_pool_probe_source_harness_sha256 \
    x86_pool_probe_source_rpm_c_sha256 \
    x86_pool_probe_source_native_rs_sha256 \
    x86_pool_probe_binary_sha256 \
    x86_pool_probe_result_sha256 \
    x86_pool_probe_guest_log_sha256; do
    value=$(sed -n "s/^${key}=//p" "$receipt")
    [[ $value =~ ^[[:xdigit:]]{64}$ ]] || die "x86 pool probe receipt has invalid $key"
  done
  guest_log_hash=$(sha256sum "$guest_log" | awk '{print $1}')
  value=$(sed -n 's/^x86_pool_probe_guest_log_sha256=//p' "$receipt")
  [[ $value == "$guest_log_hash" ]] || die "x86 pool probe guest transcript hash mismatch"
  printf 'x86_pool_probe_receipt_validation=passed file=%s\n' "$receipt"
}

run_tool() {
  local binary=$1; shift
  env LD_LIBRARY_PATH="$TOOLROOT/usr/lib64:$TOOLROOT/usr/lib" "$TOOLROOT/$binary" "$@"
}

choose_port() {
  local candidate
  for candidate in $(seq 22000 22999 | shuf); do
    if ! ss -Hln "sport = :$candidate" 2>/dev/null | grep -q .; then PORT=$candidate; return; fi
  done
  die "no ephemeral SSH port available"
}

wait_ssh() {
  local key=$1 i
  for i in $(seq 1 120); do
    if timeout 3 ssh -i "$key" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 fedora@127.0.0.1 true 2>/dev/null; then return; fi
    kill -0 "$(cat "$RUNTIME/qemu.pid")" 2>/dev/null || die "QEMU exited before SSH became ready"
    sleep 1
  done
  die "guest SSH readiness timeout"
}

make_seed() {
  local public_key=$1
  mkdir "$RUNTIME/seed"
  printf '%s\n' 'instance-id: dnfast-fedora44' 'local-hostname: dnfast-builder' >"$RUNTIME/seed/meta-data"
  {
    printf '%s\n' '#cloud-config' 'users:' '  - name: fedora' '    groups: [wheel]' '    sudo: ALL=(ALL) NOPASSWD:ALL' '    ssh_authorized_keys:'
    printf '      - %s\n' "$public_key"
    printf '%s\n' 'ssh_pwauth: false'
  } >"$RUNTIME/seed/user-data"
  run_tool usr/bin/cloud-localds "$RUNTIME/seed.iso" "$RUNTIME/seed/user-data" "$RUNTIME/seed/meta-data"
}

find_one() {
  local pattern=$1 matches
  matches=$(find "$TOOLROOT" -type f -path "$pattern" -print)
  [[ $(printf '%s\n' "$matches" | sed '/^$/d' | wc -l) -eq 1 ]] || die "expected one tool artifact: $pattern"
  printf '%s\n' "$matches"
}

boot_guest() {
  local image="$WORK/$FEDORA44_IMAGE" firmware variables qemu key
  key="$RUNTIME/id_ed25519"; ssh-keygen -q -t ed25519 -N '' -f "$key"
  make_seed "$(cat "$key.pub")"
  run_tool usr/bin/qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$RUNTIME/overlay.qcow2"
  firmware=$(find_one '*/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw')
  variables=$(find_one '*/usr/share/edk2/aarch64/vars-template-pflash.raw')
  cp "$variables" "$RUNTIME/vars.raw"
  qemu=$(find_one '*/usr/bin/qemu-system-aarch64')
  choose_port
  env LD_LIBRARY_PATH="$TOOLROOT/usr/lib64:$TOOLROOT/usr/lib" "$qemu" \
    -machine virt,accel=kvm,gic-version=host -cpu host -smp 4 -m 4096 \
    -nodefaults -nographic -serial mon:stdio -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
    -drive "if=pflash,format=raw,file=$RUNTIME/vars.raw" \
    -drive "if=virtio,format=qcow2,file=$RUNTIME/overlay.qcow2" \
    -drive "if=virtio,format=raw,readonly=on,file=$RUNTIME/seed.iso" \
    -netdev "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:$PORT-:22" -device virtio-net-pci,netdev=n0 \
    -qmp "unix:$RUNTIME/qmp.sock,server=on,wait=off" >"$RUNTIME/serial.log" 2>&1 &
  echo $! >"$RUNTIME/qemu.pid"
  wait_ssh "$key"
}

guest() {
  if ((X86_POOL_PROBE)); then
    local -a pipeline_status
    if timeout 1800 ssh -i "$RUNTIME/id_ed25519" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 fedora@127.0.0.1 "$@" 2>&1 | tee -a "$X86_POOL_PROBE_STAGE_GUEST_LOG" | tee -a "$X86_POOL_PROBE_STAGE_RECEIPT" >/dev/null; then
      return
    fi
    pipeline_status=("${PIPESTATUS[@]}")
    ((pipeline_status[0] == 0)) || return "${pipeline_status[0]}"
    return 1
  fi
  timeout 1800 ssh -i "$RUNTIME/id_ed25519" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 fedora@127.0.0.1 "$@"
}

run_wrong_key_session_diagnostic() {
  local marker=/tmp/dnfast-wrong-key-diagnostic snapshot journal_status=0 complete_seen=0
  guest "set -e; marker='$marker'; rm -rf -- \"\$marker\"; install -d -m 0700 \"\$marker\"; date -Ins >\"\$marker/started\"; nohup bash -c 'set +e; cd /home/fedora/src; DNFAST_WRONG_KEY_PROVISION_ONLY=1 bash tools/test-executor-qemu.sh; status=\$?; printf \"%s\\n\" \"\$status\" >'$marker/status'; date -Ins >'$marker/completed'; sync; exit \"\$status\"' </dev/null >\"\$marker/stdout\" 2>\"\$marker/stderr\" & child=\$!; printf '%s\\n' \"\$child\" >\"\$marker/pid\"; printf 'wrong_key_diagnostic_launch_pid=%s\\n' \"\$child\""
  for _ in $(seq 1 240); do
    if snapshot=$(guest "marker='$marker'; printf 'wrong_key_diagnostic_poll_at='; date -Ins; for item in pid started status completed; do if [ -f \"\$marker/\$item\" ]; then printf 'wrong_key_diagnostic_%s=' \"\$item\"; cat \"\$marker/\$item\"; else printf 'wrong_key_diagnostic_%s=absent\\n' \"\$item\"; fi; done; if [ -f \"\$marker/pid\" ] && kill -0 \"\$(cat \"\$marker/pid\")\" 2>/dev/null; then printf 'wrong_key_diagnostic_process=running\\n'; else printf 'wrong_key_diagnostic_process=not-running\\n'; fi"); then
      printf '%s\n' "$snapshot"
      if grep -Fqx 'wrong_key_diagnostic_completed=absent' <<<"$snapshot"; then
        sleep 1
        continue
      fi
      complete_seen=1
      break
    else
      printf 'wrong_key_diagnostic_poll_ssh_status=%s\n' "$?" >&2
      sleep 1
    fi
  done
  if ((complete_seen == 0)); then
    printf 'wrong_key_diagnostic_complete=absent-after-poll\n' >&2
    journal_status=1
  else
    printf 'wrong_key_diagnostic_complete=observed\n'
  fi
  if ! guest "marker='$marker'; printf 'wrong_key_diagnostic_final_markers_begin\\n'; for item in pid started status completed stdout stderr; do printf 'wrong_key_diagnostic_file=%s\\n' \"\$item\"; if [ -f \"\$marker/\$item\" ]; then cat \"\$marker/\$item\"; else printf 'absent\\n'; fi; done; printf 'wrong_key_diagnostic_journal_begin\\n'; sudo journalctl -b --no-pager -n 300 || true; printf 'wrong_key_diagnostic_dmesg_begin\\n'; sudo dmesg -T | tail -n 300 || true; printf 'wrong_key_diagnostic_kernel_oom_begin\\n'; sudo journalctl -kb --no-pager | grep -Ei 'oom|out of memory|killed process|segfault|panic' || true"; then
    printf 'wrong_key_diagnostic_collection_ssh=failed\n' >&2
    journal_status=1
  fi
  return "$journal_status"
}

install_focused_executor_binaries() {
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0755 target/debug/dnfast-executor /usr/libexec/dnfast-executor; sudo install -o root -g root -m 0755 target/debug/dnfast /usr/bin/dnfast; printf 'executor_multirepo_fixed_binaries=installed\\n'"
}

assert_foreground_wrong_key_probe_forbidden() {
  guest "set -e; cd /home/fedora/src; set +e; DNFAST_MULTI_REPO_ONLY=1 bash tools/test-executor-qemu.sh >/tmp/dnfast-foreground-wrong-key.log 2>&1; status=\$?; set -e; test \"\$status\" -eq 64; grep -F 'DNFAST_MULTI_REPO_ONLY is forbidden: use host detached wrong-key orchestration' /tmp/dnfast-foreground-wrong-key.log; printf 'executor_multirepo_foreground_wrong_key=forbidden\\n'"
}

wrong_key_rejection_class() {
  local stdout=$1 stderr=$2
  if grep -F -x 'error: root-owned transaction inputs are invalid: RPM signer is not authorized by repository policy' "$stdout" "$stderr" >/dev/null 2>&1; then
    printf '%s\n' signer-policy
    return 0
  fi
  if grep -E -x 'warning: <dnfast-retained-fd>: Header OpenPGP V4 [^[:space:]]+ signature, key ID [[:xdigit:]]+: NOKEY' "$stdout" "$stderr" >/dev/null 2>&1 &&
    grep -F -x 'error: root-owned transaction inputs are invalid: native failure 7: rpm verification result 4' "$stdout" "$stderr" >/dev/null 2>&1; then
    printf '%s\n' isolated-keyring-nokey
    return 0
  fi
  return 1
}

assert_wrong_key_apply_rejected() {
  local marker=/tmp/dnfast-wrong-key-diagnostic classifier
  classifier=$(declare -f wrong_key_rejection_class)
  guest "set +e
$classifier
marker='$marker'; mkdir -p \"\$marker\"; plan=\$(sed -n 's/^wrong_key_provision_plan=//p' \"\$marker/stdout\"); plan_status=0; if [ -z \"\$plan\" ]; then plan_status=1; fi; before=\$(rpm -qa | sort | sha256sum | awk '{print \$1}'); before_status=\$?; if [ \"\$plan_status\" -eq 0 ]; then sudo /usr/bin/dnfast apply \"\$plan\" --assumeyes >\"\$marker/apply.stdout\" 2>\"\$marker/apply.stderr\"; apply_status=\$?; else apply_status=125; printf 'missing wrong-key provision plan\\n' >\"\$marker/apply.stderr\"; : >\"\$marker/apply.stdout\"; fi; after=\$(rpm -qa | sort | sha256sum | awk '{print \$1}'); after_status=\$?; expected_error_class=unrecognized; if expected_error_class=\$(wrong_key_rejection_class \"\$marker/apply.stdout\" \"\$marker/apply.stderr\"); then expected_error_match=yes; else expected_error_match=no; fi; inventory_state=unavailable; if [ \"\$before_status\" -eq 0 ] && [ \"\$after_status\" -eq 0 ]; then if [ \"\$before\" = \"\$after\" ]; then inventory_state=unchanged; else inventory_state=changed; fi; fi; staging_state=read-error; staging_entries=\$(sudo find /var/lib/dnfast/staging -mindepth 1 -print -quit 2>/dev/null); staging_status=\$?; if [ \"\$staging_status\" -eq 0 ]; then if [ -z \"\$staging_entries\" ]; then staging_state=empty; else staging_state=nonempty; fi; fi; classification=harness_assertion_bug; if [ \"\$apply_status\" -eq 0 ]; then classification=unexpected_acceptance; elif [ \"\$expected_error_match\" = yes ] && [ \"\$inventory_state\" = unchanged ] && [ \"\$staging_state\" = empty ]; then classification=expected_\${expected_error_class}_rejection; fi; printf '%s\\n' \"\$plan_status\" >\"\$marker/apply-plan-status\"; printf '%s\\n' \"\$apply_status\" >\"\$marker/apply-status\"; printf '%s\\n' \"\$before\" >\"\$marker/inventory-before\"; printf '%s\\n' \"\$after\" >\"\$marker/inventory-after\"; printf '%s\\n' \"\$expected_error_match\" >\"\$marker/expected-error-match\"; printf '%s\\n' \"\$expected_error_class\" >\"\$marker/expected-error-class\"; printf '%s\\n' \"\$inventory_state\" >\"\$marker/inventory-state\"; printf '%s\\n' \"\$staging_state\" >\"\$marker/staging-state\"; printf '%s\\n' \"\$classification\" >\"\$marker/classification\"; date -Ins >\"\$marker/apply-completed\"; for item in apply-plan-status apply-status inventory-before inventory-after expected-error-match expected-error-class inventory-state staging-state classification apply-completed; do printf 'wrong_key_apply_%s=' \"\$item\"; cat \"\$marker/\$item\"; done; printf 'wrong_key_apply_stdout_begin\\n'; cat \"\$marker/apply.stdout\"; printf 'wrong_key_apply_stderr_begin\\n'; cat \"\$marker/apply.stderr\"; printf 'wrong_key_apply_classification=%s\\n' \"\$classification\"; if [ \"\$classification\" = expected_signer-policy_rejection ] || [ \"\$classification\" = expected_isolated-keyring-nokey_rejection ]; then exit 0; fi; exit 1"
}

test_wrong_key_rejection_classification() {
  local temporary stdout stderr result
  temporary=$(mktemp -d)
  stdout="$temporary/stdout"
  stderr="$temporary/stderr"

  # Given: the isolated alternate-repository keyring lacks the package signer.
  # When: RPM rejects the retained artifact before identity attribution.
  # Then: only the explicit NOKEY/result-4 pair is accepted as that rejection.
  : >"$stdout"
  printf '%s\n' 'warning: <dnfast-retained-fd>: Header OpenPGP V4 EdDSA/SHA512 signature, key ID a26f55709e0ec213: NOKEY' 'error: root-owned transaction inputs are invalid: native failure 7: rpm verification result 4' >"$stderr"
  result=$(wrong_key_rejection_class "$stdout" "$stderr")
  test "$result" = isolated-keyring-nokey
  printf '%s\n' 'error: native failure 7: rpm verification result 4' >"$stderr"
  if wrong_key_rejection_class "$stdout" "$stderr"; then
    rm -rf -- "$temporary"
    die 'wrong-key classifier accepted result 4 without NOKEY'
  fi
  printf '%s\n' 'warning: <dnfast-retained-fd>: Header OpenPGP V4 EdDSA/SHA512 signature, key ID a26f55709e0ec213: NOKEY' 'error: root-owned transaction inputs are invalid: native failure 7: rpm verification result 5' >"$stderr"
  if wrong_key_rejection_class "$stdout" "$stderr"; then
    rm -rf -- "$temporary"
    die 'wrong-key classifier accepted a verification result other than 4'
  fi
  printf '%s\n' 'error: root-owned transaction inputs are invalid: RPM signer is not authorized by repository policy' >"$stderr"
  result=$(wrong_key_rejection_class "$stdout" "$stderr")
  test "$result" = signer-policy
  rm -rf -- "$temporary"
  printf 'wrong_key_apply_nokey_classification_contract=passed\n'
}

test_wrong_key_fresh_shell_payload_contract() {
  local temporary stdout stderr captured classifier command result status original_guest
  temporary=$(mktemp -d)
  stdout="$temporary/stdout"
  stderr="$temporary/stderr"
  : >"$stdout"
  printf '%s\n' 'warning: <dnfast-retained-fd>: Header OpenPGP V4 EdDSA/SHA512 signature, key ID a26f55709e0ec213: NOKEY' 'error: root-owned transaction inputs are invalid: native failure 7: rpm verification result 4' >"$stderr"
  original_guest=$(declare -f guest)
  guest() { printf '%s\n' "$1"; }
  captured=$(assert_wrong_key_apply_rejected)
  status=$?
  eval "$original_guest"
  test "$status" -eq 0
  classifier=${captured#*set +e; }
  classifier=${classifier%%marker=*}
  command="$classifier
wrong_key_rejection_class \"\$1\" \"\$2\""
  set +e
  result=$(env -i PATH="$PATH" bash --noprofile --norc -c "$command" dnfast-fresh-shell "$stdout" "$stderr")
  status=$?
  set -e
  test "$status" -eq 0 || die "fresh guest shell cannot classify the isolated-keyring NOKEY rejection"
  test "$result" = isolated-keyring-nokey
  printf '%s\n' 'error: native failure 7: rpm verification result 4' >"$stderr"
  if env -i PATH="$PATH" bash --noprofile --norc -c "$command" dnfast-fresh-shell "$stdout" "$stderr"; then
    rm -rf -- "$temporary"
    die 'fresh guest shell accepted result 4 without NOKEY'
  fi
  printf '%s\n' 'warning: <dnfast-retained-fd>: Header OpenPGP V4 EdDSA/SHA512 signature, key ID a26f55709e0ec213: NOKEY' 'error: root-owned transaction inputs are invalid: native failure 7: rpm verification result 5' >"$stderr"
  if env -i PATH="$PATH" bash --noprofile --norc -c "$command" dnfast-fresh-shell "$stdout" "$stderr"; then
    rm -rf -- "$temporary"
    die 'fresh guest shell accepted a verification result other than 4'
  fi
  printf '%s\n' 'warning: <dnfast-retained-fd>: Header OpenPGP V4 EdDSA/SHA512 signature, key ID a26f55709e0ec213: NOKEY' 'error: root-owned transaction inputs are invalid: native failure 7: rpm verification result 40' >"$stderr"
  if env -i PATH="$PATH" bash --noprofile --norc -c "$command" dnfast-fresh-shell "$stdout" "$stderr"; then
    rm -rf -- "$temporary"
    die 'fresh guest shell accepted result 40 as result 4'
  fi
  printf '%s\n' 'error: root-owned transaction inputs are invalid: RPM signer is not authorized by repository policy' >"$stderr"
  result=$(env -i PATH="$PATH" bash --noprofile --norc -c "$command" dnfast-fresh-shell "$stdout" "$stderr")
  test "$result" = signer-policy
  printf '%s\n' 'error: root-owned transaction inputs are invalid: RPM signer is not authorized by repository policy-ish' >"$stderr"
  if env -i PATH="$PATH" bash --noprofile --norc -c "$command" dnfast-fresh-shell "$stdout" "$stderr"; then
    rm -rf -- "$temporary"
    die 'fresh guest shell accepted a signer-policy suffix'
  fi
  rm -rf -- "$temporary"
  printf 'wrong_key_apply_fresh_shell_payload_contract=passed\n'
}

test_wrong_key_apply_marker_harvest() {
  local source output status original_guest
  source="$(declare -f wrong_key_rejection_class)$(declare -f assert_wrong_key_apply_rejected)"
  for marker in apply-status inventory-before inventory-after expected-error-match expected-error-class staging-state classification apply_stdout apply_stderr wrong_key_rejection_class isolated-keyring-nokey 'rpm verification result 4'; do
    grep -Fq "$marker" <<<"$source" || die "wrong-key apply marker is absent: $marker"
  done
  original_guest=$(declare -f guest)
  guest() {
    printf '%s\n' 'wrong_key_apply_apply-status=125' 'wrong_key_apply_inventory-before=before' 'wrong_key_apply_inventory-after=after' \
      'wrong_key_apply_expected-error-match=no' 'wrong_key_apply_expected-error-class=unrecognized' 'wrong_key_apply_staging-state=read-error' \
      'wrong_key_apply_classification=harness_assertion_bug' 'wrong_key_apply_stdout_begin' 'wrong_key_apply_stderr_begin'
    return 1
  }
  set +e
  output=$(assert_wrong_key_apply_rejected 2>&1)
  status=$?
  set -e
  eval "$original_guest"
  test "$status" -ne 0
  for marker in wrong_key_apply_apply-status wrong_key_apply_inventory-before wrong_key_apply_inventory-after wrong_key_apply_expected-error-match wrong_key_apply_expected-error-class wrong_key_apply_staging-state wrong_key_apply_classification wrong_key_apply_stdout_begin wrong_key_apply_stderr_begin; do
    grep -Fq "$marker" <<<"$output" || die "wrong-key apply failure marker was not harvested: $marker"
  done
  printf 'wrong_key_apply_marker_harvest_contract=passed\n'
}

copy_inputs() {
  timeout 600 cargo vendor --locked --versioned-dirs "$RUNTIME/vendor" >/dev/null 2>&1
  mkdir -p "$RUNTIME/.cargo"
  printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' '[source.vendored-sources]' 'directory = "/home/fedora/src/vendor"' '[net]' 'offline = true' >"$RUNTIME/.cargo/config.toml"
  tar --exclude=.cache --exclude=target --exclude=.omo/evidence/worker-t2-vm -C "$ROOT" -cf "$RUNTIME/source.tar" .
  tar -C "$RUNTIME" -rf "$RUNTIME/source.tar" vendor .cargo
  gzip "$RUNTIME/source.tar"
  timeout 300 scp -q -i "$RUNTIME/id_ed25519" -P "$PORT" -o ConnectTimeout=5 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$RUNTIME/source.tar.gz" "$WORK/fedora44-only.gpg" fedora@127.0.0.1:/tmp/
  tar -C "$WORK/rpms" -cf - . | guest 'mkdir -p /tmp/rpms && tar -C /tmp/rpms -xf -'
}

prepare_local_repo() {
  rm -rf "$WORK/rpms/repodata"
  run_tool usr/bin/createrepo_c --no-database --simple-md-filenames "$WORK/rpms" >/dev/null
}

build_guest() {
  local cflags='-std=c17 -Wall -Wextra -Werror -Wno-unused-parameter -DDNFAST_NATIVE_REAL' sources
  local packages
  ((SANITIZE)) && cflags="$cflags -fsanitize=address,undefined -fno-omit-frame-pointer"
  sources='native/src/common.c native/src/solver.c native/src/solver_state.c native/src/decisions.c native/src/actions.c native/src/installed.c native/src/inventory.c native/src/inventory_write.c native/src/transaction.c native/src/transaction_run.c native/src/transaction_result.c native/src/transaction_payload_fault.c native/src/keyring.c native/src/keyring_identity.c native/src/rpm_signature.c native/src/rpm_payload.c native/src/limits.c native/src/metadata_io.c native/src/modulemd.c native/src/rpm.c native/src/callbacks.c native/src/authority.c'
  packages='gcc-16.1.1-2.fc44.aarch64 libsolv-devel-0.7.39-1.fc44.aarch64 rpm-devel-6.0.1-2.fc44.aarch64 libmodulemd-devel-2.15.3-1.fc44.aarch64 pkgconf-pkg-config-2.5.1-1.fc44.aarch64 rust-1.96.1-1.fc44.aarch64 cargo-1.96.1-1.fc44.aarch64 createrepo_c-1.2.1-5.fc44.aarch64'
  if ((MULTI_REPO_ONLY || MULTI_REPO_WRONG_KEY_DIAGNOSTIC)); then
    # The focused fixture matrix needs only the CLI, executor, and provision
    # example. Building every workspace target exhausts the Fedora cloud
    # image before the actual two-repository assertion can run.
    guest "set -e; export DNFAST_NATIVE_REAL=1; mkdir -p /home/fedora/src; tar -C /home/fedora/src -xzf /tmp/source.tar.gz; cd /home/fedora/src; bash tools/install-bootstrap-rpms.sh /tmp/rpms/rpm-build-libs-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-sign-libs-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-build-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-sign-6.0.1-2.fc44.aarch64.rpm; sudo dnf5 --assumeyes --repofrompath=locked,file:///tmp/rpms --repo=locked --setopt=locked.gpgcheck=1 --setopt=locked.gpgkey=file:///tmp/fedora44-only.gpg --setopt=install_weak_deps=False install --allowerasing $packages >/tmp/dnf-install.log; RUSTFLAGS='-D warnings' cargo build --offline --locked -p dnfast-cli --bin dnfast; RUSTFLAGS='-D warnings' cargo build --offline --locked -p dnfast-executor --bin dnfast-executor --example provision"
    if ((MULTI_REPO_WRONG_KEY_DIAGNOSTIC)); then
      guest "cd /home/fedora/src && echo executor_multirepo_guest_harness=wrong-key-session-diagnostic && sha256sum tools/test-executor-qemu.sh"
      run_wrong_key_session_diagnostic
    else
      guest "cd /home/fedora/src && echo executor_multirepo_guest_harness=detached-wrong-key-then-happy && sha256sum tools/test-executor-qemu.sh"
      assert_foreground_wrong_key_probe_forbidden
      install_focused_executor_binaries
      run_wrong_key_session_diagnostic
      assert_wrong_key_apply_rejected
      guest "cd /home/fedora/src && DNFAST_MULTI_REPO_HAPPY_ONLY=1 bash tools/test-executor-qemu.sh"
    fi
    return
  fi
  if ((X86_POOL_PROBE)); then
    guest "set -e -o pipefail; export DNFAST_NATIVE_REAL=1; mkdir -p /home/fedora/src; tar -C /home/fedora/src -xzf /tmp/source.tar.gz; cd /home/fedora/src; bash tools/install-bootstrap-rpms.sh /tmp/rpms/rpm-build-libs-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-sign-libs-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-build-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-sign-6.0.1-2.fc44.aarch64.rpm; sudo dnf5 --assumeyes --repofrompath=locked,file:///tmp/rpms --repo=locked --setopt=locked.gpgcheck=1 --setopt=locked.gpgkey=file:///tmp/fedora44-only.gpg --setopt=install_weak_deps=False install --allowerasing $packages >/tmp/dnf-install.log; RUSTFLAGS='-D warnings' cargo test --offline --locked -p dnfast-native -p dnfast-native-sys -- --test-threads=1; echo x86_pool_probe_native_tests=passed; RUSTFLAGS='-D warnings' cargo build --offline --locked -p dnfast-native --example x86_pool_probe; echo x86_pool_probe_source_harness_sha256=\$(sha256sum tools/fedora44-native-build.sh | awk '{print \$1}'); echo x86_pool_probe_source_rpm_c_sha256=\$(sha256sum native/src/rpm.c | awk '{print \$1}'); echo x86_pool_probe_source_native_rs_sha256=\$(sha256sum crates/dnfast-native/src/lib.rs | awk '{print \$1}'); echo x86_pool_probe_binary_sha256=\$(sha256sum target/debug/examples/x86_pool_probe | awk '{print \$1}'); zstd -qdf fixtures/rpm/generated-build10/repos/main/repodata/primary.xml.zst -o /tmp/dnfast-x86-pool-probe-primary.xml; zstd -qdf fixtures/rpm/generated-build10/repos/main/repodata/filelists.xml.zst -o /tmp/dnfast-x86-pool-probe-filelists.xml; target/debug/examples/x86_pool_probe fixtures/rpm/generated-build10/repos/main/repodata/repomd.xml /tmp/dnfast-x86-pool-probe-primary.xml /tmp/dnfast-x86-pool-probe-filelists.xml | tee /tmp/dnfast-x86-pool-probe.raw; test \${PIPESTATUS[0]} -eq 0; grep -Fx 'native_pool_arch=x86_64 noarch_solve=passed' /tmp/dnfast-x86-pool-probe.raw; echo x86_pool_probe_result_sha256=\$(sha256sum /tmp/dnfast-x86-pool-probe.raw | awk '{print \$1}')"
    return
  fi
  guest "export DNFAST_NATIVE_REAL=1; mkdir -p /home/fedora/src && tar -C /home/fedora/src -xzf /tmp/source.tar.gz; sudo rpm --nodeps -i /tmp/rpms/rpm-build-libs-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-sign-libs-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-build-6.0.1-2.fc44.aarch64.rpm /tmp/rpms/rpm-sign-6.0.1-2.fc44.aarch64.rpm; cd /home/fedora/src && tools/make-collision-fixture.sh /tmp/dnfast-live-collision && sudo dnf5 --assumeyes --repofrompath=locked,file:///tmp/rpms --repo=locked --setopt=locked.gpgcheck=1 --setopt=locked.gpgkey=file:///tmp/fedora44-only.gpg --setopt=install_weak_deps=False install --allowerasing $packages >/tmp/dnf-install.log && gcc -std=c17 -Wall -Wextra -Werror tools/pty-executor-probe.c -lutil -o /tmp/dnfast-pty-executor-probe && /tmp/dnfast-pty-executor-probe >/tmp/dnfast-pty-probe-usage.log 2>&1 || test \$? -eq 2; grep -F 'usage:' /tmp/dnfast-pty-probe-usage.log && RUSTFLAGS='-D warnings' cargo build --offline --locked -p dnfast-executor --example provision && RUSTFLAGS='-D warnings' cargo build --offline --workspace --all-targets --all-features --locked && RUSTFLAGS='-D warnings' cargo test --offline --locked -p dnfast-native -p dnfast-native-sys -- --test-threads=1"
  guest "set -e; cd /home/fedora/src; gcc -std=c17 -Wall -Wextra -Werror tools/pty-fd3-target.c -o /tmp/dnfast-pty-fd3-target; /tmp/dnfast-pty-executor-probe /tmp/dnfast-pty-fd3-target /etc/hosts >/tmp/dnfast-pty-fd3.log; grep -F 'fd3_exec=present' /tmp/dnfast-pty-fd3.log; grep -Fx 'pty_exit=0' /tmp/dnfast-pty-fd3.log"
  if ((RECOVERY_ONLY)); then
    guest "cd /home/fedora/src && DNFAST_RECOVERY_ONLY=1 bash tools/test-executor-qemu.sh"
    return
  fi
  if ((EXECUTOR_PTY_ONLY)); then
    guest "cd /home/fedora/src && DNFAST_EXECUTOR_PTY_ONLY=1 bash tools/test-executor-qemu.sh"
    return
  fi
  guest "set -e; cd /home/fedora/src; df -h / /tmp; du -sh target vendor /tmp/rpms; rm -rf target/debug/incremental; df -h / /tmp; du -sh target vendor /tmp/rpms"
  guest "set -e; cd /home/fedora/src; DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native --example inventory | grep -E '^package=gpg-pubkey .* vendor= instance='"
  guest "set -o pipefail; cd /home/fedora/src; sha256sum crates/dnfast-executor/src/mount_root.rs crates/dnfast-executor/examples/mount_swap_probe.rs; if command -v strace >/dev/null; then sudo strace -f -o /tmp/mount-swap.strace -e trace=mount,umount2,chroot,chdir env DNFAST_NATIVE_REAL=1 cargo test --offline --locked -p dnfast-executor --features test-fixtures mount_root::tests::recursive_private_bind_replacement_is_rejected -- --exact --nocapture 2>&1 | tee /tmp/mount-swap.raw; else sudo env DNFAST_NATIVE_REAL=1 cargo test --offline --locked -p dnfast-executor --features test-fixtures mount_root::tests::recursive_private_bind_replacement_is_rejected -- --exact --nocapture 2>&1 | tee /tmp/mount-swap.raw; fi; status=\${PIPESTATUS[0]}; echo mount_swap_test_exit=\$status; test \$status -eq 0; grep -F 'test mount_root::tests::recursive_private_bind_replacement_is_rejected ... ok' /tmp/mount-swap.raw"
  guest "cd /home/fedora/src && gcc $cflags -Inative/include -Inative/src \$(pkg-config --cflags rpm) native/src/keyring_identity.c native/tests/keyring_packet_contract.c \$(pkg-config --libs rpm) -o /tmp/keyring-packet-contract && /tmp/keyring-packet-contract"
  guest "cd /home/fedora/src && gcc $cflags -Inative/include -Inative/src \$(pkg-config --cflags rpm) native/tests/rpm_signature_framing.c native/src/keyring_identity.c \$(pkg-config --libs rpm) -o /tmp/rpm-signature-framing && /tmp/rpm-signature-framing && gcc $cflags -Inative/include -Inative/src \$(pkg-config --cflags rpm) native/tests/rpm_payload_framing.c \$(pkg-config --libs rpm) -o /tmp/rpm-payload-framing && /tmp/rpm-payload-framing"
  guest "set -e -o pipefail; export DNFAST_NATIVE_REAL=1; cd /home/fedora/src; rpm -qp --qf '[%{OPENPGP}\\n]' fixtures/rpm/generated-build10/repos/main/dnfast-app-1.0-1.noarch.rpm; cargo run --offline --locked -q -p dnfast-native --example trust_probe -- fixtures/rpm/generated-build10/keys/allowed.asc fixtures/rpm/generated-build10/repos/main/dnfast-app-1.0-1.noarch.rpm | grep -F 'dnfast-app-0:1.0-1.noarch primary=2B017A94136265DB56C0CCD6DF21D1EED6503531 signing=B8240C48DBD3C6032011486E54FA9912778E332D'; for item in alternate-key corrupt unsigned; do if cargo run --offline --locked -q -p dnfast-native --example trust_probe -- fixtures/rpm/generated-build10/keys/allowed.asc fixtures/rpm/generated-build10/failures/\$item.rpm; then exit 91; fi; done; for item in expired-primary expired-subkey revoked-primary revoked-subkey; do if cargo run --offline --locked -q -p dnfast-native --example trust_probe -- fixtures/rpm/generated-build10/keys/\$item.asc fixtures/rpm/generated-build10/failures/\$item.rpm; then exit 92; fi; done"
  guest "cd /home/fedora/src && sudo env DNFAST_NATIVE_REAL=1 ./target/debug/examples/production_trust_probe fixtures/rpm/generated-build10/keys/allowed.asc fixtures/rpm/generated-build10/repos/main/dnfast-app-1.0-1.noarch.rpm 1bf14b77abfaa8dc115dc5526405ff7a99cb4b96356064e42609830023d82e19"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-transaction.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-transaction.rpm | tee /tmp/dnfast-transaction.log; rpm -q dnfast-noarch; sudo rpm -e dnfast-noarch; sudo rm -f /tmp/dnfast-transaction.rpm"
  guest "set -e; cd /home/fedora/src; sudo rpm -i fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example erase_probe -- fixtures/rpm/generated-build10/keys/allowed.asc dnfast-noarch; ! rpm -q dnfast-noarch"
  guest "set -e; cd /home/fedora/src; sudo rpm -i fixtures/rpm/generated-build10/repos/main/dnfast-upgrade-1.0-1.noarch.rpm; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-upgrade-2.0-1.noarch.rpm /tmp/dnfast-upgrade.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-upgrade.rpm upgrade; rpm -q --qf '%{VERSION}\n' dnfast-upgrade | grep -Fx 2.0; sudo rpm -e dnfast-upgrade; sudo rm -f /tmp/dnfast-upgrade.rpm"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-callback.rpm; for point in open rewind close; do sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-callback.rpm callback-\$point; done; sudo rm -f /tmp/dnfast-callback.rpm"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-payload.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-payload.rpm payload-failure | tee /tmp/dnfast-payload.log; ! rpm -q dnfast-noarch; sudo rm -f /tmp/dnfast-payload.rpm"
  guest "set -e; cd /home/fedora/src; rpm -qa | sort | sha256sum | awk '{print \$1}' >/tmp/start-panic.before; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-start-panic.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-start-panic.rpm start-panic | tee /tmp/dnfast-start-panic.log; grep -F 'transaction_start_panic=contained real_runs=0 phase=Preflight' /tmp/dnfast-start-panic.log; test \"\$(cat /tmp/start-panic.before)\" = \"\$(rpm -qa | sort | sha256sum | awk '{print \$1}')\"; ! test -e /usr/share/dnfast/noarch; sudo rm -f /tmp/dnfast-start-panic.rpm"
  guest "set -e; cd /home/fedora/src; sudo env DNFAST_NATIVE_REAL=1 CARGO_TARGET_DIR=/tmp/dnfast-journal-target cargo run --offline --locked -q -p dnfast-native --features test-fixtures --example checked_journal_probe -- fixtures/rpm/generated-build10/keys/allowed.asc fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm 732679a3651d3191b56948c25df53c2c79862dba1266db30806ec3026651834a; sudo rpm -e dnfast-noarch; sudo rm -rf /tmp/dnfast-journal-target"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-mutation.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-mutation.rpm mutation; sudo rm -f /tmp/dnfast-mutation.rpm"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-db-fault.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-db-fault.rpm db-failure; sudo rpm -e dnfast-noarch; sudo rm -f /tmp/dnfast-db-fault.rpm"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-preflight.rpm; for mode in check-failure order-failure; do sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-preflight.rpm \$mode; done; sudo rm -f /tmp/dnfast-preflight.rpm"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-unsatisfied-1.0-1.noarch.rpm /tmp/dnfast-conflict.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-conflict.rpm preflight-failure | tee /tmp/dnfast-conflict.log; ! rpm -q dnfast-unsatisfied; sudo rm -f /tmp/dnfast-conflict.rpm"
  guest "set -e; cd /home/fedora/src; sudo rpm --nosignature -i /tmp/dnfast-live-collision/provider.rpm; rpm -qa | sort | sha256sum | awk '{print \$1}' >/tmp/collision-inventory.before; sha256sum /usr/share/dnfast/live-collision | awk '{print \$1}' >/tmp/collision-file.before; sudo install -o root -g root -m 0600 /tmp/dnfast-live-collision/collision.rpm /tmp/dnfast-collision.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- /tmp/dnfast-live-collision/key.asc /tmp/dnfast-collision.rpm preflight-failure | tee /tmp/dnfast-live-collision.log; grep -F '/usr/share/dnfast/live-collision' /tmp/dnfast-live-collision.log; test \"\$(cat /tmp/collision-inventory.before)\" = \"\$(rpm -qa | sort | sha256sum | awk '{print \$1}')\"; test \"\$(cat /tmp/collision-file.before)\" = \"\$(sha256sum /usr/share/dnfast/live-collision | awk '{print \$1}')\"; sudo rpm -e dnfast-live-provider; sudo rm -rf /tmp/dnfast-live-collision /tmp/dnfast-collision.rpm"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-post-failure-1.0-1.noarch.rpm /tmp/dnfast-post.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-post.rpm real-failure | tee /tmp/dnfast-post.log; sudo rpm -e dnfast-post-failure 2>/dev/null || true; sudo rm -f /tmp/dnfast-post.rpm"
  guest "set -e; cd /home/fedora/src; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-pre-failure-1.0-1.noarch.rpm /tmp/dnfast-script.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-script.rpm real-failure; sudo rpm -e dnfast-pre-failure 2>/dev/null || true; sudo rm -f /tmp/dnfast-script.rpm"
  guest "set -e; cd /home/fedora/src; sudo rpm -i fixtures/rpm/generated-build10/repos/main/dnfast-trigger-failure-1.0-1.noarch.rpm fixtures/rpm/generated-build10/repos/main/dnfast-dep-1.0-1.noarch.rpm; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-app-1.0-1.noarch.rpm /tmp/dnfast-trigger-target.rpm; sudo env DNFAST_NATIVE_REAL=1 cargo run --offline --locked -q -p dnfast-native-sys --example transaction_probe -- fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-trigger-target.rpm real-failure; sudo rpm -e dnfast-app dnfast-dep dnfast-trigger-failure 2>/dev/null || true; sudo rm -f /tmp/dnfast-trigger-target.rpm"
  guest "set -e; cd /home/fedora/src; sha256sum crates/dnfast-executor/src/execute.rs target/debug/dnfast-executor target/debug/examples/provision; grep -F 'phase(\"test\"' crates/dnfast-executor/src/execute.rs; plan=\$(sudo env DNFAST_NATIVE_REAL=1 target/debug/examples/provision install); rpm -qa | sort | sha256sum | awk '{print \$1}' >/tmp/dnfast-executor-before; sudo env DNFAST_NATIVE_REAL=1 bash -c \"exec 3< '\$plan'; /home/fedora/src/target/debug/dnfast-executor --plan-fd 3 --assumeno\"; test \"\$(cat /tmp/dnfast-executor-before)\" = \"\$(rpm -qa | sort | sha256sum | awk '{print \$1}')\"; sudo env DNFAST_NATIVE_REAL=1 bash -c \"exec 3< '\$plan'; /home/fedora/src/target/debug/dnfast-executor --plan-fd 3 --assumeyes\"; rpm -q dnfast-noarch; plan=\$(sudo env DNFAST_NATIVE_REAL=1 target/debug/examples/provision remove dnfast-noarch); sudo env DNFAST_NATIVE_REAL=1 bash -c \"exec 3< '\$plan'; /home/fedora/src/target/debug/dnfast-executor --plan-fd 3 --assumeyes\"; ! rpm -q dnfast-noarch; sudo rpm -i fixtures/rpm/generated-build10/repos/main/dnfast-upgrade-1.0-1.noarch.rpm; plan=\$(sudo env DNFAST_NATIVE_REAL=1 target/debug/examples/provision upgrade dnfast-upgrade); sudo env DNFAST_NATIVE_REAL=1 bash -c \"exec 3< '\$plan'; /home/fedora/src/target/debug/dnfast-executor --plan-fd 3 --assumeyes\"; rpm -q --qf '%{VERSION}\\n' dnfast-upgrade | grep -Fx 2.0; sudo rpm -e dnfast-upgrade; plan=\$(sudo env DNFAST_NATIVE_REAL=1 target/debug/examples/provision install); rpm -qa | sort | sha256sum | awk '{print \$1}' >/tmp/dnfast-executor-tamper-before; digest=\$(sudo sha256sum \"\$plan\" | awk '{print \$1}'); sudo sh -c \"printf tampered > /var/lib/dnfast/inputs/\$digest/policy.json\"; ! sudo env DNFAST_NATIVE_REAL=1 bash -c \"exec 3< '\$plan'; /home/fedora/src/target/debug/dnfast-executor --plan-fd 3 --assumeyes\"; test \"\$(cat /tmp/dnfast-executor-tamper-before)\" = \"\$(rpm -qa | sort | sha256sum | awk '{print \$1}')\""
  guest "cd /home/fedora/src && bash tools/test-executor-qemu.sh"
  if ((INVENTORY_ONLY)); then
    guest "cd /home/fedora/src && DNFAST_NATIVE_REAL=1 CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' RUSTFLAGS='-C link-arg=-fsanitize=address -C link-arg=-fsanitize=undefined -C link-arg=-lasan -C link-arg=-lubsan' ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1 bash -x tools/test-rpm-inventory.sh"
    return
  fi
  if ((PROBE)); then
    guest "export DNFAST_NATIVE_REAL=1; cd /home/fedora/src && gcc -std=c17 -Wall -Wextra -Werror -Inative/include native/tests/header_contract.c -o /tmp/header-contract && /tmp/header-contract && gcc $cflags -Inative/include -Inative/src \$(pkg-config --cflags libsolv rpm modulemd-2.0) $sources native/tests/native_probe.c \$(pkg-config --libs libsolv rpm modulemd-2.0) -lsolvext -ldl -lpthread -o /tmp/native-probe && /tmp/native-probe abi1 && /tmp/native-probe happy && /tmp/native-probe interrupt && /tmp/native-probe misleading && /tmp/native-probe malformed && cargo run --offline --locked -p dnfast-native --example probe -- happy && cargo run --offline --locked -p dnfast-native --example probe -- interrupt && cargo run --offline --locked -p dnfast-native --example probe -- panic"
    guest "export DNFAST_NATIVE_REAL=1; cd /home/fedora/src && gcc -std=c17 -Wall -Wextra -Werror -fPIC -shared -DDNFAST_HIDE_RPMTSRUN native/tests/fake_native.c -o /tmp/libdnfast-hidden.so && DNFAST_LIBSOLV=/tmp/libdnfast-hidden.so DNFAST_LIBSOLVEXT=/tmp/libdnfast-hidden.so DNFAST_LIBRPM=/tmp/libdnfast-hidden.so DNFAST_LIBRPMIO=/tmp/libdnfast-hidden.so /tmp/native-probe unsupported"
    if ((SANITIZE)); then
      guest "export DNFAST_NATIVE_REAL=1; cd /home/fedora/src && printf '%s\\n' native_requested_spec_null_contract_lane=asan-ubsan && gcc $cflags -Inative/include -Inative/src \$(pkg-config --cflags libsolv rpm modulemd-2.0) $sources native/tests/requested_spec_null_contract.c \$(pkg-config --libs libsolv rpm modulemd-2.0) -lsolvext -ldl -lpthread -o /tmp/requested-spec-null-contract && ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 /tmp/requested-spec-null-contract"
      guest "cd /home/fedora/src && FEDORA44_TOOLROOT=/ CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' RUSTFLAGS='-C link-arg=-fsanitize=address -C link-arg=-fsanitize=undefined -C link-arg=-lasan -C link-arg=-lubsan' ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1 bash -x tools/test-native-solver.sh"
      guest "cd /home/fedora/src && FEDORA44_TOOLROOT=/ tools/audit-native-symbols.sh"
      guest "cd /home/fedora/src && /tmp/native-probe happy && gcc -shared -fPIC native/tests/fake_missing_queue.c -o /tmp/libsolv-missing-queue.so && DNFAST_LIBSOLV=/tmp/libsolv-missing-queue.so /tmp/native-probe missing_queue"
      guest "cd /home/fedora/src && DNFAST_NATIVE_REAL=1 CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' RUSTFLAGS='-C link-arg=-fsanitize=address -C link-arg=-fsanitize=undefined -C link-arg=-lasan -C link-arg=-lubsan' ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1 cargo run --offline --locked -p dnfast-native --example rpmdb"
      guest "cd /home/fedora/src && DNFAST_NATIVE_REAL=1 CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' RUSTFLAGS='-C link-arg=-fsanitize=address -C link-arg=-fsanitize=undefined -C link-arg=-lasan -C link-arg=-lubsan' ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1 bash tools/test-rpm-inventory.sh"
      guest "cd /home/fedora/src && DNFAST_NATIVE_REAL=1 CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' RUSTFLAGS='-C link-arg=-fsanitize=address -C link-arg=-fsanitize=undefined -C link-arg=-lasan -C link-arg=-lubsan' cargo build --offline --locked -p dnfast-native --example production_trust_probe && ldd target/debug/examples/production_trust_probe | tee /tmp/dnfast-production-ldd && grep -q libasan /tmp/dnfast-production-ldd && grep -q libubsan /tmp/dnfast-production-ldd && readelf -d target/debug/examples/production_trust_probe | tee /tmp/dnfast-production-readelf && grep -q 'Shared library.*libasan' /tmp/dnfast-production-readelf && grep -q 'Shared library.*libubsan' /tmp/dnfast-production-readelf && sudo env DNFAST_NATIVE_REAL=1 ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./target/debug/examples/production_trust_probe fixtures/rpm/generated-build10/keys/allowed.asc fixtures/rpm/generated-build10/repos/main/dnfast-app-1.0-1.noarch.rpm 1bf14b77abfaa8dc115dc5526405ff7a99cb4b96356064e42609830023d82e19"
      guest "cd /home/fedora/src && rm -rf /tmp/dnfast-t14-sanitizer && DNFAST_NATIVE_REAL=1 CARGO_TARGET_DIR=/tmp/dnfast-t14-sanitizer CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' RUSTFLAGS='-C link-arg=-fsanitize=address -C link-arg=-fsanitize=undefined -C link-arg=-lasan -C link-arg=-lubsan' cargo build --offline --locked -p dnfast-native-sys --example transaction_probe && sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-transaction.rpm && sudo env DNFAST_NATIVE_REAL=1 ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 /tmp/dnfast-t14-sanitizer/debug/examples/transaction_probe fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-transaction.rpm && sudo rpm -e dnfast-noarch && for point in open rewind close; do sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-transaction.rpm; sudo env DNFAST_NATIVE_REAL=1 ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 /tmp/dnfast-t14-sanitizer/debug/examples/transaction_probe fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-transaction.rpm callback-\$point; done; sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-transaction.rpm; sudo env DNFAST_NATIVE_REAL=1 ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 /tmp/dnfast-t14-sanitizer/debug/examples/transaction_probe fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-transaction.rpm payload-failure; sudo rm -f /tmp/dnfast-transaction.rpm && rm -rf /tmp/dnfast-t14-sanitizer"
      guest "cd /home/fedora/src && rm -rf /tmp/dnfast-start-panic-san && DNFAST_NATIVE_REAL=1 CARGO_TARGET_DIR=/tmp/dnfast-start-panic-san CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' RUSTFLAGS='-C link-arg=-fsanitize=address -C link-arg=-fsanitize=undefined -C link-arg=-lasan -C link-arg=-lubsan' cargo build --offline --locked -p dnfast-native-sys --example transaction_probe && echo final_guest_transaction_probe_sha256=\$(sha256sum /tmp/dnfast-start-panic-san/debug/examples/transaction_probe | awk '{print \$1}') && echo final_guest_harness_sha256=\$(sha256sum tools/fedora44-native-build.sh | awk '{print \$1}') && echo collision_fixture_source_sha256=\$(sha256sum tools/make-collision-fixture.sh | awk '{print \$1}') && echo todo2a_canonical_builder_sha256=\$(sha256sum tools/build-fixture-repo.sh | awk '{print \$1}') && echo rpm_fixture_guest_builder_sha256=\$(sha256sum fixtures/rpm/build-in-guest.sh | awk '{print \$1}') && sudo install -o root -g root -m 0600 fixtures/rpm/generated-build10/repos/main/dnfast-noarch-1.0-1.noarch.rpm /tmp/dnfast-start-panic-san.rpm && sudo env DNFAST_NATIVE_REAL=1 ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 /tmp/dnfast-start-panic-san/debug/examples/transaction_probe fixtures/rpm/generated-build10/keys/allowed.asc /tmp/dnfast-start-panic-san.rpm start-panic; sudo rm -rf /tmp/dnfast-start-panic-san /tmp/dnfast-start-panic-san.rpm"
    else
      guest "export DNFAST_NATIVE_REAL=1; cd /home/fedora/src && printf '%s\\n' native_requested_spec_null_contract_lane=normal && gcc $cflags -Inative/include -Inative/src \$(pkg-config --cflags libsolv rpm modulemd-2.0) $sources native/tests/requested_spec_null_contract.c \$(pkg-config --libs libsolv rpm modulemd-2.0) -lsolvext -ldl -lpthread -o /tmp/requested-spec-null-contract && /tmp/requested-spec-null-contract"
      guest "cd /home/fedora/src && FEDORA44_TOOLROOT=/ tools/test-native-solver.sh"
    fi
  fi
}

test_x86_pool_probe_publication() {
  local test_dir
  test_dir=$(mktemp -d "$ROOT/.x86-pool-probe-publication.XXXXXX")
  (
    trap 'rm -rf -- "$test_dir"' EXIT
    X86_POOL_PROBE=1
    X86_POOL_PROBE_RECEIPT="$test_dir/task-1-x86-pool-probe-qemu.log"
    X86_POOL_PROBE_GUEST_LOG="$test_dir/x86-pool-probe-guest.log"
    prepare_x86_pool_probe_receipt
    [[ ! -e $X86_POOL_PROBE_RECEIPT && ! -e $X86_POOL_PROBE_GUEST_LOG ]]
    printf 'native_pool_arch=x86_64 noarch_solve=passed\n' >"$X86_POOL_PROBE_STAGE_GUEST_LOG"
    {
      printf 'x86_pool_probe_native_tests=passed\n'
      printf 'native_pool_arch=x86_64 noarch_solve=passed\n'
      printf 'x86_pool_probe_source_harness_sha256=%064d\n' 0
      printf 'x86_pool_probe_source_rpm_c_sha256=%064d\n' 0
      printf 'x86_pool_probe_source_native_rs_sha256=%064d\n' 0
      printf 'x86_pool_probe_binary_sha256=%064d\n' 0
      printf 'x86_pool_probe_result_sha256=%064d\n' 0
    } >>"$X86_POOL_PROBE_STAGE_RECEIPT"
    printf 'premature canonical receipt\n' >"$X86_POOL_PROBE_RECEIPT"
    if publish_x86_pool_probe_receipt >"$test_dir/premature.out" 2>&1; then
      exit 1
    fi
    grep -Fqx 'fedora44-vm: x86 pool probe canonical artifacts unexpectedly exist before publication' "$test_dir/premature.out"
    [[ -s $X86_POOL_PROBE_RECEIPT && ! -e $X86_POOL_PROBE_GUEST_LOG ]]
    rm -f -- "$X86_POOL_PROBE_RECEIPT"
    publish_x86_pool_probe_receipt
    validate_x86_pool_probe_receipt "$X86_POOL_PROBE_RECEIPT" >/dev/null
    X86_POOL_PROBE_RECEIPT="$test_dir/failed/task-1-x86-pool-probe-qemu.log"
    X86_POOL_PROBE_GUEST_LOG="$test_dir/failed/x86-pool-probe-guest.log"
    prepare_x86_pool_probe_receipt
    if publish_x86_pool_probe_receipt 2>/dev/null; then
      exit 1
    fi
    [[ ! -e $X86_POOL_PROBE_RECEIPT && ! -e $X86_POOL_PROBE_GUEST_LOG ]]
  )
  printf 'x86_pool_probe_publication_contract=passed\n'
}

test_x86_pool_probe_lifecycle() {
  local test_dir=${DNFAST_X86_POOL_PROBE_LIFECYCLE_DIR:?DNFAST_X86_POOL_PROBE_LIFECYCLE_DIR is required}
  X86_POOL_PROBE_RECEIPT="$test_dir/task-1-x86-pool-probe-qemu.log"
  X86_POOL_PROBE_GUEST_LOG="$test_dir/x86-pool-probe-guest.log"
  prepare_x86_pool_probe_receipt
  printf 'native_pool_arch=x86_64 noarch_solve=passed\n' >"$X86_POOL_PROBE_STAGE_GUEST_LOG"
  {
    printf 'x86_pool_probe_native_tests=passed\n'
    printf 'native_pool_arch=x86_64 noarch_solve=passed\n'
    printf 'x86_pool_probe_source_harness_sha256=%064d\n' 0
    printf 'x86_pool_probe_source_rpm_c_sha256=%064d\n' 0
    printf 'x86_pool_probe_source_native_rs_sha256=%064d\n' 0
    printf 'x86_pool_probe_binary_sha256=%064d\n' 0
    printf 'x86_pool_probe_result_sha256=%064d\n' 0
  } >>"$X86_POOL_PROBE_STAGE_RECEIPT"
  complete_x86_pool_probe
  printf 'x86_pool_probe_lifecycle_contract=passed\n'
}

main_build() {
  if ((WRONG_KEY_APPLY_MARKER_TEST)); then
    test_wrong_key_rejection_classification
    test_wrong_key_fresh_shell_payload_contract
    test_wrong_key_apply_marker_harvest
    return
  fi
  if [[ -n $X86_POOL_PROBE_VALIDATE_RECEIPT ]]; then
    validate_x86_pool_probe_receipt "$X86_POOL_PROBE_VALIDATE_RECEIPT"
    return
  fi
  if ((X86_POOL_PROBE_PUBLICATION_TEST)); then
    test_x86_pool_probe_publication
    return
  fi
  if ((X86_POOL_PROBE_LIFECYCLE_TEST)); then
    test_x86_pool_probe_lifecycle
    return
  fi
  mkdir -p "$WORK"
  if ((X86_POOL_PROBE)); then
    [[ -x $TOOLROOT/usr/bin/qemu-system-aarch64 && -x $TOOLROOT/usr/bin/createrepo_c && -f $WORK/$FEDORA44_IMAGE ]] || die "--x86-pool-probe requires the existing verified Fedora 44 cache"
    prepare_x86_pool_probe_receipt
  else
    preflight
    download_closure "$WORK"
    if [[ ! -x $TOOLROOT/usr/bin/qemu-system-aarch64 || ! -x $TOOLROOT/usr/bin/createrepo_c ]]; then
      if [[ -d $TOOLROOT ]]; then find "$TOOLROOT" -type d ! -perm -u=w -exec chmod u+w {} +; fi
      rm -rf "$TOOLROOT"; extract_closure "$WORK" "$TOOLROOT"
    fi
  fi
  prepare_local_repo
  verify_image "$WORK"
  boot_guest
  copy_inputs
  build_guest
  guest 'sudo poweroff' >/dev/null 2>&1 || true
  if ((X86_POOL_PROBE)); then
    complete_x86_pool_probe
  fi
  echo "Fedora 44 native build and probe passed"
}

main_build
