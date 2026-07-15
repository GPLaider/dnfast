#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HARNESS=$(mktemp -d "${TMPDIR:-/tmp}/dnfast-bootstrap-test.XXXXXX")
trap 'rm -rf "$HARNESS"' EXIT
mkdir -p "$HARNESS/bin"

cat >"$HARNESS/bin/rpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_LOG"
case "${1-}" in
  --verifydb) [[ ${MOCK_CASE:?} != verifydb-failure ]]; exit ;;
  -qp)
    [[ ${3-} == '%{NAME}' ]] && { printf 'rpm-build-libs'; exit; }
    printf 'rpm-build-libs-0:6.0.1-2.fc44.aarch64'
    ;;
  -q)
    case ${MOCK_CASE:?} in
      exact) printf 'rpm-build-libs-0:6.0.1-2.fc44.aarch64' ;;
      absent-then-exact)
        count=$(grep -c '^[-]q ' "$MOCK_LOG" || true)
        if ((count == 1)); then exit 1; fi
        printf 'rpm-build-libs-0:6.0.1-2.fc44.aarch64'
        ;;
      mismatch) printf 'rpm-build-libs-0:6.0.0-1.fc44.aarch64' ;;
      query-failure) exit 2 ;;
      post-install-mismatch)
        count=$(grep -c '^[-]q ' "$MOCK_LOG" || true)
        if ((count == 1)); then exit 1; fi
        printf 'rpm-build-libs-0:6.0.0-1.fc44.aarch64'
        ;;
      *) exit 97 ;;
    esac
    ;;
  --nodeps) printf 'install\n' >>"$MOCK_LOG" ;;
  *) exit 98 ;;
esac
EOF
cat >"$HARNESS/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec "$@"
EOF
chmod +x "$HARNESS/bin/rpm" "$HARNESS/bin/sudo"

run_case() {
  local case_name=$1 expected_status=$2 expected_installs=$3 status log
  log="$HARNESS/$case_name.log"
  : >"$log"
  set +e
  PATH="$HARNESS/bin:$PATH" MOCK_CASE="$case_name" MOCK_LOG="$log" \
    bash "$ROOT/tools/install-bootstrap-rpms.sh" /tmp/rpm-build-libs.rpm >"$log.out" 2>&1
  status=$?
  set -e
  [[ $status == "$expected_status" ]] || { cat "$log.out" >&2; return 1; }
  [[ $(grep -c '^install$' "$log" || true) == "$expected_installs" ]] || { cat "$log" >&2; return 1; }
}

run_case exact 0 0
run_case absent-then-exact 0 1
run_case mismatch 1 0
run_case verifydb-failure 1 0
run_case query-failure 1 0
run_case post-install-mismatch 1 1
printf 'bootstrap_rpm_shell_cases=exact,absent,mismatch,verifydb,query,post-install:passed\n'
