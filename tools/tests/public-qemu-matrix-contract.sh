#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HARNESS="$ROOT/tools/public-qemu-matrix.sh"
DOCUMENTATION="$ROOT/docs/public-qemu-matrix.md"
PASS=0

ok() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then
    PASS=$((PASS + 1))
  else
    printf 'not ok - %s\n' "$name" >&2
    exit 1
  fi
}

contains() {
  grep -Fq -- "$2" "$1"
}

absent() {
  ! grep -Eqi -- "$2" "$1"
}

vendor_from_foreign_cwd() {
  local runtime
  runtime=$(mktemp -d)
  if ! (
    cd "$runtime"
    cargo vendor --manifest-path "$ROOT/Cargo.toml" --offline --locked \
      --versioned-dirs "$runtime/vendor" >/dev/null 2>&1
  ); then
    rm -rf -- "$runtime"
    return 1
  fi
  test -d "$runtime/vendor"
  rm -rf -- "$runtime"
}

config_bytes_are_safe() {
  local runtime main_config repo_config
  runtime=$(mktemp -d)
  main_config="$runtime/dnf.conf"
  repo_config="$runtime/matrix.repo"
  if ! bash -c '
    set -euo pipefail
    literal_dollar_single_quote=$(printf "\\044\047")
    literal_backslash_n=$(printf "\\\\n")
    source "$1"
    REPOSITORY_ID=matrix
    BASEURL=https://localhost:18443
    REPOSITORY_FINGERPRINT=0123456789ABCDEF0123456789ABCDEF01234567
    write_bootstrap_config_files "$2" "$3"

    grep -Fxq "[main]" "$2"
    grep -Fxq "reposdir=" "$2"
    grep -Fxq "reposdir=/etc/dnfast-public-repos" "$2"
    grep -Fxq "varsdir=" "$2"
    grep -Fxq "varsdir=/etc/dnfast-public-vars" "$2"
    od -An -tx1 -v "$2" | tr -s " " "\\n" | grep -Fxq "0a"
    ! LC_ALL=C grep -Fq "$literal_dollar_single_quote" "$2"
    ! LC_ALL=C grep -Fq "$literal_backslash_n" "$2"

    grep -Fxq "[matrix]" "$3"
    grep -Fxq "baseurl=https://localhost:18443" "$3"
    grep -Fxq "gpgkey=/etc/dnfast/keys/matrix/matrix.asc" "$3"
    grep -Fxq "dnfast_allowed_fingerprints=0123456789ABCDEF0123456789ABCDEF01234567" "$3"
    od -An -tx1 -v "$3" | tr -s " " "\\n" | grep -Fxq "0a"
    ! LC_ALL=C grep -Fq "$literal_dollar_single_quote" "$3"
    ! LC_ALL=C grep -Fq "$literal_backslash_n" "$3"
  ' bash "$HARNESS" "$main_config" "$repo_config"; then
    rm -rf -- "$runtime"
    return 1
  fi
  rm -rf -- "$runtime"
}

public_plan_derives_named_path_under_nounset() {
  local observed
  observed=$(mktemp)
  if ! bash -c '
    set -euo pipefail
    source "$1"
    REPOSITORY_ID=matrix
    OBSERVED=$2
    guest() { printf "%s\\n" "$1" >"$OBSERVED"; }
    plan=$(public_plan install dnfast-noarch nounset-regression)
    test "$plan" = "/home/fedora/dnfast-public-matrix/nounset-regression.plan"
    grep -Fq "nounset-regression.plan" "$2"
  ' bash "$HARNESS" "$observed"; then
    rm -f -- "$observed"
    return 1
  fi
  rm -f -- "$observed"
}

public_plan_failure_prevents_secondary_apply() {
  local runtime
  runtime=$(mktemp -d)
  if ! bash -c '
    set -euo pipefail
    runtime=$2
    events="$runtime/events"
    secondary_apply="$runtime/secondary-apply"
    source "$1"
    REPOSITORY_ID=matrix
    guest() {
      printf "%s\\n" "$1" >>"$events"
      if [[ $1 == *"/usr/bin/dnfast --json plan "* ]]; then
        return 47
      fi
      if [[ $1 == *"sudo /usr/bin/dnfast apply "* ]]; then
        : >"$secondary_apply"
        return 0
      fi
      return 1
    }

    if plan=$(public_plan install dnfast-noarch failed-plan); then
      public_apply_yes "$plan" failed-plan
    fi
    test ! -e "$secondary_apply"
    ! grep -Fq "sudo /usr/bin/dnfast apply " "$events"
  ' bash "$HARNESS" "$runtime"; then
    rm -rf -- "$runtime"
    return 1
  fi
  rm -rf -- "$runtime"
}

public_lifecycle_refreshes_before_the_next_plan() {
  local runtime
  runtime=$(mktemp -d)
  if ! bash -c '
    set -euo pipefail
    runtime=$2
    state="$runtime/snapshot-state"
    events="$runtime/events"
    source "$1"
    REPOSITORY_ID=matrix
    record() { :; }
    guest() {
      case $1 in
        *"/usr/bin/dnfast --json plan "*)
          printf "plan\\n" >>"$events"
          if [[ $(<"$state") != fresh ]]; then
            printf "stale-plan-rejected\\n" >>"$events"
            return 41
          fi
          ;;
        *"/usr/bin/dnfast"*apply*)
          printf "apply\\n" >>"$events"
          printf "stale\\n" >"$state"
          ;;
        *"sudo /usr/bin/dnfast repo refresh --repo matrix "*)
          printf "refresh\\n" >>"$events"
          test "$(<"$state")" = stale
          printf "fresh\\n" >"$state"
          ;;
        *) return 1 ;;
      esac
    }

    printf "stale\\n" >"$state"
    if public_plan install dnfast-noarch stale-before-refresh >/dev/null; then
      exit 1
    fi
    grep -Fxq "stale-plan-rejected" "$events"
    refresh_root_snapshot stale-recovery
    public_plan install dnfast-noarch after-refresh >/dev/null

    : >"$events"
    first_plan=$(public_plan install dnfast-noarch first)
    public_apply_yes "$first_plan" first
    second_plan=$(public_plan remove dnfast-noarch second)
    test "$second_plan" = "/home/fedora/dnfast-public-matrix/second.plan"
    test "$(cat "$events")" = "$(printf "plan\\napply\\nrefresh\\nplan")"

    : >"$events"
    public_apply_pty "$second_plan" y affirmative
    public_plan install dnfast-noarch after-affirmative-pty >/dev/null
    test "$(cat "$events")" = "$(printf "apply\\nrefresh\\nplan")"
  ' bash "$HARNESS" "$runtime"; then
    rm -rf -- "$runtime"
    return 1
  fi
  rm -rf -- "$runtime"
}

guest_log_failure_contract() {
  local runtime receipt fixture
  runtime=$(mktemp -d /tmp/dnfast-public-qemu.contract.XXXXXX)
  receipt=$(mktemp)
  fixture=$(mktemp -d)
  if ! bash -c '
    set -euo pipefail
    runtime=$2
    receipt=$3
    fixture=$4
    finish_receipt=$(mktemp)
    trap '\''rm -rf -- "$runtime" "$fixture" "$receipt" "$receipt.guest-logs" "$finish_receipt" "$finish_receipt.guest-logs"'\'' EXIT

    mkdir -p "$fixture/tmp" "$fixture/home/fedora/dnfast-public-matrix"
    printf "root refresh failed\n" >"$fixture/tmp/dnfast-public-build-install.log"
    printf "rpm query failed\n" >"$fixture/tmp/dnfast-public-inventory-digest.log"
    printf "managed files query failed\n" >"$fixture/tmp/dnfast-public-managed-files-digest.log"
    printf "apply failed\n" >"$fixture/home/fedora/dnfast-public-matrix/signed-install.apply.log"
    printf "Continue? [y/N]\ny\napply failed\n" >"$fixture/home/fedora/dnfast-public-matrix/public-pty-yes.pty.log"
    printf "plan body\n" >"$fixture/home/fedora/dnfast-public-matrix/signed-install.plan"
    printf "{\"status\":\"planned\"}\n" >"$fixture/home/fedora/dnfast-public-matrix/signed-install.plan.json"

    source "$1"
    RUNTIME=$runtime
    RECEIPT=$receipt
    PORT=2222
    : >"$RUNTIME/id_ed25519"

    record() { printf "%s\\n" "$1" >>"$RECEIPT"; }
    guest() { return 1; }
    if ! extract_guest_logs; then
      exit 1
    fi
    grep -Fxq "public_qemu_matrix_guest_logs_status=guest_archive_failed" "$RECEIPT"
    test ! -e "$RECEIPT.guest-logs"

    RECEIPT=$finish_receipt
    guest() { tar -C "$fixture" -czf - -- tmp/dnfast-public-build-install.log tmp/dnfast-public-inventory-digest.log tmp/dnfast-public-managed-files-digest.log home/fedora/dnfast-public-matrix/signed-install.apply.log home/fedora/dnfast-public-matrix/public-pty-yes.pty.log home/fedora/dnfast-public-matrix/signed-install.plan home/fedora/dnfast-public-matrix/signed-install.plan.json; }
    cleanup_runtime() {
      test -f "$RECEIPT.guest-logs/guest-logs.tar.gz"
      printf "cleanup_after_guest_logs\\n" >>"$RECEIPT"
      RUNTIME=
    }
    set +e
    ( (exit 37); finish )
    finish_status=$?
    set -e
    test "$finish_status" -eq 37
    archive="$RECEIPT.guest-logs/guest-logs.tar.gz"
    test -f "$archive"
    test "$(stat -c %a "$archive")" = 600
    test "$(tar -tzf "$archive" | LC_ALL=C sort)" = "$(printf "%s\\n" home/fedora/dnfast-public-matrix/public-pty-yes.pty.log home/fedora/dnfast-public-matrix/signed-install.apply.log home/fedora/dnfast-public-matrix/signed-install.plan home/fedora/dnfast-public-matrix/signed-install.plan.json tmp/dnfast-public-build-install.log tmp/dnfast-public-inventory-digest.log tmp/dnfast-public-managed-files-digest.log)"
    tar -xOzf "$archive" home/fedora/dnfast-public-matrix/public-pty-yes.pty.log | grep -Fx "Continue? [y/N]" >/dev/null
    digest=$(sha256sum "$archive" | cut -d " " -f1)
    grep -Fxq "public_qemu_matrix_guest_logs_status=captured" "$RECEIPT"
    grep -Fxq "public_qemu_matrix_guest_logs_sha256=$digest" "$RECEIPT"
    grep -Fxq "cleanup_after_guest_logs" "$RECEIPT"
  ' bash "$HARNESS" "$runtime" "$receipt" "$fixture"; then
    rm -rf -- "$runtime" "$receipt" "$receipt.guest-logs" "$fixture"
    return 1
  fi
}

guest_log_allowlist_is_secret_free() {
  local marker
  marker=$'guest_log_command=$(cat <<\'EOF\''
  if awk -v marker="$marker" '
    index($0, marker) { capture=1; next }
    capture && /^EOF$/ { exit }
    capture { print }
  ' "$HARNESS" | grep -Eq 'id_ed25519|ca-key\.pem|key\.pem|matrix\.asc'; then
    return 1
  fi
}

executor_references_are_packaging_or_preflight_only() {
  local line
  while IFS= read -r line; do
    case $line in
      *dnfast-executor*)
        [[ $line == *'DNFAST_NATIVE_REAL=1 cargo install --offline --locked --path crates/dnfast-executor --root $package_root'* ||
          $line == *'$package_root/bin/dnfast-executor /usr/libexec/dnfast-executor'* ||
          $line == *'for path in /usr/bin/dnfast /usr/libexec/dnfast-executor /usr/libexec/dnfastd;'* ]] || return 1
        ;;
    esac
  done <"$HARNESS"
  ! grep -Fq -- '--plan-fd' "$HARNESS"
}

public_pty_python_driver_has_exact_answers_and_direct_argv() {
  local observed
  observed=$(mktemp)
  if ! bash -c '
    set -euo pipefail
    source "$1"
    REPOSITORY_ID=matrix
    OBSERVED=$2
    record() { :; }
    guest() { printf "%s\\n" "$1" >>"$OBSERVED"; }
    refresh_root_snapshot() { printf "refresh:%s\\n" "$1" >>"$OBSERVED"; }

    public_apply_pty /home/fedora/dnfast-public-matrix/no.plan n public-pty-default-no
    public_apply_pty /home/fedora/dnfast-public-matrix/yes.plan y public-pty-yes

    no=$(sed -n "1p" "$OBSERVED")
    yes=$(sed -n "2p" "$OBSERVED")
    test "$(sed -n 3p "$OBSERVED")" = "refresh:public-pty-yes"
    for command in "$no" "$yes"; do
      [[ $command == *"/usr/bin/python3 -c"* ]]
      [[ $command == *"pty.spawn\\(sys.argv\\[2:\\]\\)"* ]]
      [[ $command == *"os.waitstatus_to_exitcode"* ]]
      [[ $command == *"-- sudo /usr/bin/dnfast apply "* ]]
      [[ $command == *".pty.log"* ]]
      [[ $command == *"2>&1"* ]]
      [[ $command != *"script -"* ]]
    done
    [[ $no == *" n | /usr/bin/python3 "* ]]
    [[ $yes == *" y | /usr/bin/python3 "* ]]
  ' bash "$HARNESS" "$observed"; then
    rm -f -- "$observed"
    return 1
  fi
  rm -f -- "$observed"
}

# Given the public QEMU surface. When it is inspected. Then it is an executable,
# separate harness rather than the legacy executor/provision matrix.
ok "public harness exists" test -x "$HARNESS"
ok "uses installed public CLI" contains "$HARNESS" '/usr/bin/dnfast'
ok "requires installed public CLI" contains "$HARNESS" 'require_installed_public_cli'
ok "packages actual public CLI" contains "$HARNESS" 'cargo install --offline --locked --path crates/dnfast-cli'
ok "packages public CLI with the real native backend" contains "$HARNESS" 'DNFAST_NATIVE_REAL=1 cargo install --offline --locked --path crates/dnfast-cli'
ok "installs package output at public path" contains "$HARNESS" '$package_root/bin/dnfast /usr/bin/dnfast'
ok "packages the fixed executor with the real native backend" contains "$HARNESS" 'DNFAST_NATIVE_REAL=1 cargo install --offline --locked --path crates/dnfast-executor'
ok "installs the fixed executor at its root-only path" contains "$HARNESS" '$package_root/bin/dnfast-executor /usr/libexec/dnfast-executor'
ok "installs the resident daemon at its root-only path" contains "$HARNESS" '$package_root/bin/dnfastd /usr/libexec/dnfastd'
ok "installs the resident daemon service" contains "$HARNESS" 'packaging/dnfastd.service /etc/systemd/system/dnfastd.service'
ok "preflights all installed program paths" contains "$HARNESS" 'for path in /usr/bin/dnfast /usr/libexec/dnfast-executor /usr/libexec/dnfastd;'
ok "requires regular non-symlink root-owned program files" contains "$HARNESS" 'test -f \"\$path\"; test ! -L \"\$path\"; test -x \"\$path\"; test \"\$(stat -c '\''%u:%g:%a:%h'\'' \"\$path\")\" = '\''0:0:755:1'\'''
ok "probes every installed program for native linkage" contains "$HARNESS" 'do ldd \"\$path\" | grep -F '\''libsolv.so.1'\''; ldd \"\$path\" | grep -F '\''librpm.so.10'\''; done'
ok "starts the resident daemon after snapshot bootstrap" contains "$HARNESS" 'systemctl enable --now dnfastd.service'
ok "checks the resident daemon protocol after startup" contains "$HARNESS" 'resident_daemon=available'
ok "checks public CLI help after packaging" contains "$HARNESS" '/usr/bin/dnfast --help >/tmp/dnfast-public-help.json'
ok "preflights the guest Python PTY standard library" contains "$HARNESS" "/usr/bin/python3 -c 'import os, pty, sys; assert os.waitstatus_to_exitcode'"
ok "passes each locked build package as a distinct DNF argument" contains "$HARNESS" "printf ' %q' \"\${packages[@]}\""
ok "uses one canonical source archive name for copy and guest extraction" contains "$HARNESS" 'archive="$RUNTIME/dnfast-public-source.tar.gz"'
ok "anchors cargo vendor to the source manifest" contains "$HARNESS" 'cargo vendor --manifest-path "$ROOT/Cargo.toml" --offline --locked --versioned-dirs "$RUNTIME/vendor"'
ok "vendors successfully outside the source working directory" vendor_from_foreign_cwd
ok "derives a canonical manifest from every archived source file" contains "$HARNESS" 'source_manifest_from_tree'
ok "binds the canonical source manifest digest into the receipt" contains "$HARNESS" 'public_qemu_matrix_source_manifest_sha256='
ok "copies the canonical source manifest with the archive" contains "$HARNESS" 'dnfast-public-source.manifest'
ok "verifies the guest extracted archive manifest against the host manifest" contains "$HARNESS" 'cmp -s /tmp/dnfast-public-source.manifest /tmp/dnfast-public-source.guest.manifest'
ok "does not claim HEAD alone identifies the archived source" absent "$HARNESS" 'git -C "$ROOT" rev-parse HEAD'
ok "stages the verified RPM repository before metadata generation" contains "$HARNESS" 'cp -a -- "$RPM_REPOSITORY/." "$staged_rpm_repository/"'
ok "runs createrepo only on the runtime repository copy" contains "$HARNESS" '"$CREATEREPO" --no-database --simple-md-filenames "$staged_rpm_repository"'
ok "bootstraps root snapshot through public CLI" contains "$HARNESS" 'sudo /usr/bin/dnfast repo refresh'
ok "preserves first public refresh diagnostics" contains "$HARNESS" 'cat /tmp/dnfast-public-refresh.json >&2'
ok "keeps dnf main config separate from the repository section" contains "$HARNESS" 'write_bootstrap_config_files'
ok "writes the main config through direct file transfer" contains "$HARNESS" 'dnfast-public-dnf.conf'
ok "writes the repository config through direct file transfer" contains "$HARNESS" 'dnfast-public-repository.repo'
ok "does not reparse bootstrap config shell quoting" absent "$HARNESS" "printf %s \$(printf '%q'"
ok "writes bootstrap configs as literal newline-delimited bytes" config_bytes_are_safe
ok "derives public plan path under Bash nounset" public_plan_derives_named_path_under_nounset
ok "stops before a secondary apply when public planning fails" public_plan_failure_prevents_secondary_apply
ok "rejects stale plans and refreshes before the next public plan" public_lifecycle_refreshes_before_the_next_plan
ok "bootstraps upgrade through an exact relation package spec" contains "$HARNESS" "public_plan install 'dnfast-upgrade = 1.0-1' signed-upgrade-install"
ok "does not bootstrap upgrade through an RPM filename" absent "$HARNESS" 'public_plan install dnfast-upgrade-1.0-1.noarch signed-upgrade-install'
ok "runs the public plan-to-transaction matrix" contains "$HARNESS" 'run_public_matrix'
ok "records only executed scenario passes" contains "$HARNESS" 'matrix_scenario=$1 status=passed'
ok "contains no pending assertion ledger" absent "$HARNESS" 'status=pending|assertions are intentionally pending'
ok "supports an explicit guest HTTPS fixture" contains "$HARNESS" '--guest-fixture'
ok "starts guest fixture before root refresh" contains "$HARNESS" 'start_guest_https_fixture'
ok "serves fixture with TLS" contains "$HARNESS" 'openssl s_server'

# Given a public matrix. When it is executed. Then no legacy test-only path is reachable.
ok "rejects provision example" absent "$HARNESS" 'provision'
ok "rejects cargo run" absent "$HARNESS" 'cargo[[:space:]]+run'
ok "allows executor only for packaging and preflight" executor_references_are_packaging_or_preflight_only
ok "rejects debug binary runtime" absent "$HARNESS" 'target/debug'
ok "rejects native test runtime hooks" absent "$HARNESS" 'DNFAST_(TEST|FIXTURE|PROVISION|MULTI_REPO|RECOVERY)'

# Given architecture selection. When the host cannot provide native KVM. Then it fails closed.
ok "requires x86 host for x86 matrix" contains "$HARNESS" 'x86_64 KVM host required'
ok "requires aarch64 host for aarch64 matrix" contains "$HARNESS" 'aarch64 KVM host required'
ok "uses KVM acceleration" contains "$HARNESS" 'accel=kvm'
ok "has no TCG fallback" absent "$HARNESS" 'accel=tcg|tcg'
ok "launches QEMU with the selected toolroot libraries" contains "$HARNESS" 'env LD_LIBRARY_PATH="$TOOL_LIBRARY_PATH" "$QEMU_SYSTEM"'
ok "sets the Fedora bashrc guard before nounset guest commands" contains "$HARNESS" 'BASHRCSOURCED=Y bash -euo pipefail'

# Given an executable public matrix. When it is assembled. Then its first
# transaction scenarios are driven through the installed public CLI.
for marker in \
  signed_install signed_upgrade signed_remove public_pty_default_no public_pty_yes \
  nonroot verifydb before_after_sorted staging_cleanup input_cleanup \
  qmp_cleanup pid_cleanup overlay_cleanup; do
  ok "named matrix scenario $marker" contains "$HARNESS" "$marker"
done
for stale_marker in \
  stale_snapshot stale_rpmdb policy_tamper key_tamper cache_tamper \
  current_pointer_tamper origin_tamper metadata_tamper artifact_tamper vendor_tamper \
  repository_tamper symlink_tamper hardlink_tamper same_plan_race different_plan_race \
  public_sigkill_recovery; do
  ok "does not advertise unexecuted scenario $stale_marker" absent "$HARNESS" "^[[:space:]]+$stale_marker([[:space:]]|$)"
done
ok "plans as the unprivileged public user" contains "$HARNESS" 'setpriv --reuid=fedora --regid=fedora --clear-groups /usr/bin/dnfast'
ok "applies only through installed public CLI" contains "$HARNESS" 'sudo /usr/bin/dnfast apply'
ok "runs default-No through the guest Python PTY standard library" contains "$HARNESS" '/usr/bin/python3 -c'
ok "uses direct argv for the public Python PTY child" contains "$HARNESS" 'pty.spawn(sys.argv[2:])'
ok "propagates the Python PTY child exit status" contains "$HARNESS" 'os.waitstatus_to_exitcode'
ok "has no script command dependency" absent "$HARNESS" '(^|[^[:alnum:]_])script([^[:alnum:]_]|$)'
ok "drives exact default-No and affirmative PTY answers" public_pty_python_driver_has_exact_answers_and_direct_argv
ok "checks default-No prompt" contains "$HARNESS" 'Continue? [y/N]'
ok "accepts only exact single-letter PTY confirmations" contains "$HARNESS" 'n|y) input=$answer'
ok "checks guest rpmdb" contains "$HARNESS" 'rpmdb --verifydb'
ok "checks staging is empty" contains "$HARNESS" 'assert_staging_empty'
ok "checks no unfinished input generation survives" contains "$HARNESS" 'assert_input_preparation_clean'

# Given a QEMU lifecycle. When cleanup runs. Then it handles only its own PID/runtime.
ok "runtime is private mktemp directory" contains "$HARNESS" 'mktemp -d'
ok "cleanup validates numeric owned pid" contains "$HARNESS" '[[ $pid =~ ^[0-9]+$ ]]'
ok "cleanup checks QMP" contains "$HARNESS" 'qmp.sock'
ok "cleanup records overlay" contains "$HARNESS" 'overlay.qcow2'
ok "preserves serial output on a failed run" contains "$HARNESS" 'public_qemu_matrix_serial_log='
ok "extracts owned guest logs before failure cleanup" contains "$HARNESS" 'extract_guest_logs'
ok "limits guest failure extraction to an explicit log allowlist" contains "$HARNESS" 'dnfast-public-build-install.log'
ok "retains fixed inventory digest stderr on failure" contains "$HARNESS" 'dnfast-public-inventory-digest.log'
ok "retains fixed managed-files digest stderr on failure" contains "$HARNESS" 'dnfast-public-managed-files-digest.log'
ok "creates private digest stderr logs" contains "$HARNESS" 'install -m 0600 /dev/null \"\$log\"'
ok "cleans successful inventory digest stderr log" contains "$HARNESS" 'rm -f /tmp/dnfast-public-inventory-digest.log /tmp/dnfast-public-managed-files-digest.log'
ok "retains owned public plans and JSON diagnostics" contains "$HARNESS" "-name '*.plan' -o -name '*.plan.json'"
ok "retains post-apply public refresh diagnostics" contains "$HARNESS" "-name '*.refresh.log'"
ok "retains public Python PTY transcripts after a failure" contains "$HARNESS" "-name '*.pty.log'"
ok "records guest log extraction status" contains "$HARNESS" 'public_qemu_matrix_guest_logs_status='
ok "records guest log archive digest" contains "$HARNESS" 'public_qemu_matrix_guest_logs_sha256='
ok "keeps host cleanup scoped to an owned runtime before guest log capture" contains "$HARNESS" '/tmp/dnfast-public-qemu.*'
ok "does not add host or fixture credentials to the guest log allowlist" guest_log_allowlist_is_secret_free
ok "guest log extraction failure does not mask the original failure" guest_log_failure_contract
ok "documents native x86 limitation" contains "$DOCUMENTATION" 'never emulates another architecture'
ok "documentation calls out installed public CLI" contains "$DOCUMENTATION" '/usr/bin/dnfast'

# Given the source-only contract. When parsed. Then its shell is syntactically valid.
ok "shell syntax" bash -n "$HARNESS"

printf 'ok %s public QEMU matrix contracts\n' "$PASS"
