# dnfast x86_64 실행 시작점

## 이번 작업의 목적

현재 전달본을 **Fedora 44 x86_64 KVM 호스트**에서 한 번도 수정하지
않고 실행하여, 최신 소스의 public transaction matrix 증거를 반환한다.

이번 단계에서는 DNF5 벤치마크를 실행하지 않는다. 매트릭스가 완전히
통과하고 영수증을 검토한 다음에만 `BENCHMARK_X86_PROTOCOL.md`로 넘어간다.
이번 전달본의 전체 후속 순서는 `NEXT_X86_HANDOFF.md`에 있다.

## 완료 조건

아래 두 가지 중 하나를 Ventoy에 반환하면 이번 실행은 완료다.

1. 성공: exit code, raw receipt, 호스트 정보, 모든 파일의 SHA-256.
2. 실패: preflight/matrix console log, exit code, 호스트 정보와 생성된
   모든 receipt/serial/guest-log 파일. Receipt 초기화 전 실패라면 receipt가
   없는 것이 정상이며, preflight 또는 matrix stderr가 원본 증거다.

실패해도 결과를 지우거나 같은 파일명으로 재시도하지 않는다. 첫 실패
증거를 먼저 반환해야 원인을 정확히 고칠 수 있다.

## 0. USB 밖에서 고정 bootstrap 전체 받기

**여기서 멈춘다. 이 USB의 문서에서 명령을 복사하거나 실행하지 않는다.**

작업 조정자가 USB와 다른 신뢰 채널로 다음 세 가지를 함께 보내야 한다.

1. `current-source-latest/START_HERE_X86.md`의 SHA-256
2. `current-source-latest/dnfast-x86-handoff-current.tar.gz`의 SHA-256
3. 두 값이 이미 채워진 고정 bootstrap 코드 블록 전체

해시만 받고 이 USB에서 검증 명령을 복사하면 순환 신뢰이므로 허용하지
않는다. USB 안의 `SOURCE-IDENTITY.txt`, `SHA256SUMS-CURRENT.txt`, 또는
`X86_OUT_OF_BAND_BOOTSTRAP_TEMPLATE.md`도 독립 신뢰 채널을 대신하지
못한다. 조정자가 보내는 메시지는 현재 저장소의
`X86_OUT_OF_BAND_BOOTSTRAP_TEMPLATE.md`를 바탕으로 하되, 최종 두 해시를
채운 **완전한 코드 블록**이어야 한다.

## 1. 최신 전달본 확인과 압축 해제

0단계에서 별도로 받은 bootstrap 전체를 신뢰된 Bash 셸에 붙여 넣는다.
그 bootstrap이 두 SHA-256 검증, `SHA256SUMS-CURRENT.txt` 확인, 고유한
`RUN_ROOT` 생성, 압축 해제, 바깥·추출 runbook 일치 확인을 모두 수행하고
`VENTOY`, `HANDOFF`, `RUN_ID`, `RUN_ROOT`, `CARGO_HOME`을 같은 셸에 남긴다.

성공 출력의 마지막 줄은 `AUTHENTICATED_NEXT=`로 시작하며 추출된
`START_HERE_X86.md` 절대경로를 가리킨다. 이제 USB에서 열었던 문서는
닫고, 그 **추출된 인증 문서**를 열어 같은 Bash 셸에서 2단계부터 5단계까지
진행한다. bootstrap이 0이 아니거나 필요한 변수가 없으면 중단한다.
기존 `run14` 결과나 `source-fixed-20260714` 소스는 사용하지 않는다.

## 2. x86 호스트 자산 경로 입력

다음 블록에서 `/absolute/path/...` 오른쪽 값만 x86 호스트의 실제 경로로
바꾼다. 상대 경로는 허용하지 않는다.

```bash
export MATRIX_QEMU_SYSTEM='/absolute/path/to/qemu-system-x86_64'
export MATRIX_QEMU_IMG='/absolute/path/to/qemu-img'
export MATRIX_CLOUD_LOCALDS='/absolute/path/to/cloud-localds'
export MATRIX_IMAGE='/absolute/path/to/Fedora-Cloud-Base-Generic-44.x86_64.qcow2'
export MATRIX_FIRMWARE='/absolute/path/to/OVMF_CODE.fd'
export MATRIX_VARIABLES='/absolute/path/to/OVMF_VARS.fd'
export MATRIX_RPM_REPOSITORY='/absolute/path/to/locked-rpms'
export MATRIX_CREATEREPO='/absolute/path/to/createrepo_c'
export MATRIX_BUILD_GPG_KEY='/absolute/path/to/fedora-build-key.asc'
export MATRIX_HOST_TOOLS_SHA256='/absolute/path/to/trusted-host-tools.sha256'
export MATRIX_GUEST_ASSETS_SHA256='/absolute/path/to/trusted-guest-assets.sha256'
export MATRIX_RPM_REPOSITORY_SHA256='/absolute/path/to/trusted-rpm-repository.sha256'
export MATRIX_BUILD_PACKAGES='gcc-16.1.1-2.fc44.x86_64 libsolv-devel-0.7.39-1.fc44.x86_64 rpm-devel-6.0.1-2.fc44.x86_64 pkgconf-pkg-config-2.5.1-1.fc44.x86_64 rust-1.96.1-1.fc44.x86_64 cargo-1.96.1-1.fc44.x86_64'
```

필요한 것은 Fedora 44 x86_64 cloud image, 서로 맞는 OVMF code/variables,
QEMU 도구, 그리고 위 NEVRA와 의존성을 전부 가진 서명된 잠금 RPM
저장소다. 이 자산들은 전달 압축에 포함되어 있지 않다. 이미지·firmware·
RPM 저장소·공개 build certificate는 신뢰된 획득 경로와 별도 보관한
digest/manifest로 확인한다. 같은 USB에서 새로 계산한 해시만으로 출처를
판단하지 않는다. `MATRIX_BUILD_GPG_KEY`에는 사설키가 아니라 공개
certificate만 지정한다.

세 trusted manifest는 이 USB 밖의 신뢰 채널에서 가져오며, 다음과 같은
정확한 명령·순서로 만든 출력이어야 한다.

```bash
sha256sum \
  "$MATRIX_QEMU_SYSTEM" "$MATRIX_QEMU_IMG" \
  "$MATRIX_CLOUD_LOCALDS" "$MATRIX_CREATEREPO" \
  > trusted-host-tools.sha256
sha256sum \
  "$MATRIX_IMAGE" "$MATRIX_FIRMWARE" "$MATRIX_VARIABLES" \
  "$MATRIX_BUILD_GPG_KEY" \
  > trusted-guest-assets.sha256
(cd "$MATRIX_RPM_REPOSITORY" && \
  find . -type f -print0 | sort -z | xargs -0 sha256sum) \
  > trusted-rpm-repository.sha256
```

위 예시는 manifest 형식을 정의하는 명령이다. 실행할 파일 자체를 처음
받은 뒤 같은 장소에서 manifest도 함께 새로 만들면 인증이 아니다. Fedora
서명 패키지·검증된 이미지 배포처·기존 잠금 저장소의 승인 기록에서 얻은
값과 대조된 manifest만 사용한다.

## 3. 사전 검사

아래 블록은 고유한 evidence 디렉터리를 먼저 만들고 모든 출력을 보존한다.
어느 검사든 실패하면 `PREFLIGHT_STATUS`가 0이 아니며 4단계는 자동으로
매트릭스를 실행하지 않는다.

```bash
export EVIDENCE_ROOT="/tmp/dnfast-x86-handoff-$RUN_ID"
[[ ! -e $EVIDENCE_ROOT ]]
/usr/bin/mkdir -m 0700 -- "$EVIDENCE_ROOT"
export PREFLIGHT_LOG="$EVIDENCE_ROOT/preflight.log"

CLEAN_ENV=(
  /usr/bin/env -i
  PATH=/usr/bin:/bin
  LC_ALL=C
  "HOME=$HOME"
  "CARGO_HOME=$CARGO_HOME"
  "VENTOY=$VENTOY"
  "HANDOFF=$HANDOFF"
  "RUN_ID=$RUN_ID"
  "RUN_ROOT=$RUN_ROOT"
  "EVIDENCE_ROOT=$EVIDENCE_ROOT"
  "MATRIX_QEMU_SYSTEM=$MATRIX_QEMU_SYSTEM"
  "MATRIX_QEMU_IMG=$MATRIX_QEMU_IMG"
  "MATRIX_CLOUD_LOCALDS=$MATRIX_CLOUD_LOCALDS"
  "MATRIX_IMAGE=$MATRIX_IMAGE"
  "MATRIX_FIRMWARE=$MATRIX_FIRMWARE"
  "MATRIX_VARIABLES=$MATRIX_VARIABLES"
  "MATRIX_RPM_REPOSITORY=$MATRIX_RPM_REPOSITORY"
  "MATRIX_CREATEREPO=$MATRIX_CREATEREPO"
  "MATRIX_BUILD_GPG_KEY=$MATRIX_BUILD_GPG_KEY"
  "MATRIX_HOST_TOOLS_SHA256=$MATRIX_HOST_TOOLS_SHA256"
  "MATRIX_GUEST_ASSETS_SHA256=$MATRIX_GUEST_ASSETS_SHA256"
  "MATRIX_RPM_REPOSITORY_SHA256=$MATRIX_RPM_REPOSITORY_SHA256"
  "MATRIX_BUILD_PACKAGES=$MATRIX_BUILD_PACKAGES"
)

set +e
"${CLEAN_ENV[@]}" /usr/bin/bash --noprofile --norc -euo pipefail -c '
  cd "$RUN_ROOT/dnfast"
  fail() { printf "preflight: %s\n" "$*" >&2; exit 1; }
  require_absolute() {
    local name=$1 value=${!1}
    case $value in
      /*) ;;
      *) fail "not an absolute path: $name=$value" ;;
    esac
  }
  require_trusted_manifest() {
    local name=$1 value=${!1} mode
    require_absolute "$name"
    test -f "$value" && test ! -L "$value" \
      || fail "trusted manifest is not a regular non-symlink: $name"
    case $value in
      "$VENTOY"/*|"$RUN_ROOT"/*) fail "trusted manifest is inside transferred media/tree: $name" ;;
    esac
    mode=$(stat -c "%a" "$value")
    (( (8#$mode & 022) == 0 )) || fail "trusted manifest is group/world writable: $name"
  }
  require_host_executable() {
    local name=$1 value=${!1} uid mode
    test -f "$value" && test ! -L "$value" && test -x "$value" \
      || fail "host executable is not a regular non-symlink: $name"
    uid=$(stat -c "%u" "$value")
    mode=$(stat -c "%a" "$value")
    test "$uid" = 0 || fail "host executable is not root-owned: $name"
    (( (8#$mode & 022) == 0 )) || fail "host executable is group/world writable: $name"
  }
  require_guest_asset() {
    local name=$1 value=${!1} mode
    test -f "$value" && test ! -L "$value" \
      || fail "guest asset is not a regular non-symlink: $name"
    mode=$(stat -c "%a" "$value")
    (( (8#$mode & 022) == 0 )) \
      || fail "guest asset is group/world writable: $name"
  }
  require_system_command() {
    local name=$1 path resolved uid mode
    path=$(command -v "$name") || fail "required host command missing: $name"
    resolved=$(/usr/bin/readlink -f -- "$path") \
      || fail "system command cannot be resolved: $name"
    case $resolved in /usr/bin/*) ;; *) fail "system command resolves outside /usr/bin: $name" ;; esac
    test -f "$resolved" && test -x "$resolved" \
      || fail "system command target is not a regular executable: $name"
    uid=$(stat -c "%u" "$resolved")
    mode=$(stat -c "%a" "$resolved")
    test "$uid" = 0 || fail "system command is not root-owned: $name"
    (( (8#$mode & 022) == 0 )) || fail "system command is group/world writable: $name"
    rpm -qf -- "$path" >/dev/null || fail "system command is not RPM-owned: $name"
    rpm -Vf -- "$path" >/dev/null || fail "system command package verification failed: $name"
    rpm -qf -- "$resolved" >/dev/null || fail "system command target is not RPM-owned: $name"
    rpm -Vf -- "$resolved" >/dev/null || fail "system command target package verification failed: $name"
  }

  for tool in rpm bash cargo ssh scp ssh-keygen timeout ss shuf tar gzip \
              sha256sum awk grep find sort xargs cmp stat readlink tr seq \
              sleep cp mv chmod mkdir rm basename dirname mktemp wc tee date \
              cat install env sync uname; do
    require_system_command "$tool"
  done
  host_arch=$(/usr/bin/uname -m)
  test "$host_arch" = x86_64 || fail "x86_64 host required, got $host_arch"
  test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm \
    || fail "readable/writable character device required: /dev/kvm"
  for name in MATRIX_QEMU_SYSTEM MATRIX_QEMU_IMG MATRIX_CLOUD_LOCALDS \
              MATRIX_IMAGE MATRIX_FIRMWARE MATRIX_VARIABLES \
              MATRIX_RPM_REPOSITORY MATRIX_CREATEREPO MATRIX_BUILD_GPG_KEY \
              MATRIX_HOST_TOOLS_SHA256 MATRIX_GUEST_ASSETS_SHA256 \
              MATRIX_RPM_REPOSITORY_SHA256; do
    require_absolute "$name"
  done
  build_key_name=${MATRIX_BUILD_GPG_KEY##*/}
  case $build_key_name in
    ""|*[!A-Za-z0-9._-]*) fail "unsafe MATRIX_BUILD_GPG_KEY basename" ;;
  esac
  for name in MATRIX_QEMU_SYSTEM MATRIX_QEMU_IMG MATRIX_CLOUD_LOCALDS MATRIX_CREATEREPO; do
    require_host_executable "$name"
  done
  for name in MATRIX_HOST_TOOLS_SHA256 MATRIX_GUEST_ASSETS_SHA256 \
              MATRIX_RPM_REPOSITORY_SHA256; do
    require_trusted_manifest "$name"
  done
  for name in MATRIX_IMAGE MATRIX_FIRMWARE MATRIX_VARIABLES MATRIX_BUILD_GPG_KEY; do
    require_guest_asset "$name"
  done
  test -d "$MATRIX_RPM_REPOSITORY" && test ! -L "$MATRIX_RPM_REPOSITORY" \
    || fail "RPM repository is not a directory non-symlink"
  repo_mode=$(stat -c "%a" "$MATRIX_RPM_REPOSITORY")
  (( (8#$repo_mode & 022) == 0 )) \
    || fail "RPM repository root is group/world writable"
  test -z "$(find "$MATRIX_RPM_REPOSITORY" -mindepth 1 \
    ! -type f ! -type d -print -quit)" \
    || fail "RPM repository contains a symlink or special entry"
  test -z "$(find "$MATRIX_RPM_REPOSITORY" -mindepth 1 \
    -perm /022 -print -quit)" \
    || fail "RPM repository contains a group/world-writable entry"

  sha256sum \
    "$MATRIX_QEMU_SYSTEM" "$MATRIX_QEMU_IMG" \
    "$MATRIX_CLOUD_LOCALDS" "$MATRIX_CREATEREPO" \
    > "$EVIDENCE_ROOT/observed-host-tools.sha256"
  cmp -- "$MATRIX_HOST_TOOLS_SHA256" "$EVIDENCE_ROOT/observed-host-tools.sha256" \
    || fail "host tool manifest mismatch"
  sha256sum \
    "$MATRIX_IMAGE" "$MATRIX_FIRMWARE" "$MATRIX_VARIABLES" \
    "$MATRIX_BUILD_GPG_KEY" \
    > "$EVIDENCE_ROOT/observed-guest-assets.sha256"
  cmp -- "$MATRIX_GUEST_ASSETS_SHA256" "$EVIDENCE_ROOT/observed-guest-assets.sha256" \
    || fail "guest asset manifest mismatch"
  (cd "$MATRIX_RPM_REPOSITORY" && \
    find . -type f -print0 | sort -z | xargs -0 sha256sum) \
    > "$EVIDENCE_ROOT/observed-rpm-repository.sha256"
  cmp -- "$MATRIX_RPM_REPOSITORY_SHA256" "$EVIDENCE_ROOT/observed-rpm-repository.sha256" \
    || fail "RPM repository manifest mismatch"

  tools/tests/public-qemu-matrix-contract.sh
  /usr/bin/bash -n tools/public-qemu-matrix.sh
  tools/public-qemu-matrix.sh --help
' 2>&1 | /usr/bin/tee "$PREFLIGHT_LOG"
export PREFLIGHT_STATUS=${PIPESTATUS[0]}
set -e
printf '%s\n' "$PREFLIGHT_STATUS" > "$EVIDENCE_ROOT/preflight.exit"
```

유효한 실행은 `uname -m=x86_64`, 실제 `/dev/kvm`, 그리고 harness의
`-machine q35,accel=kvm -cpu host` 경로뿐이다. TCG나 ARM 에뮬레이션은
결과로 인정하지 않는다.

## 4. 매트릭스 한 번 실행

아래 블록은 preflight가 통과한 경우에만 실행하고 stdout·stderr를 원래
순서대로 하나의 console log에 보존한다. `125`는 매트릭스 미실행을 뜻한다.

```bash
export RECEIPT="$EVIDENCE_ROOT/matrix.raw.log"
export MATRIX_CONSOLE_LOG="$EVIDENCE_ROOT/matrix.console.log"

{
  builtin printf '%q ' "$RUN_ROOT/dnfast/tools/public-qemu-matrix.sh" \
    --arch x86_64 \
    --baseurl https://localhost:18443 \
    --fingerprint 2B017A94136265DB56C0CCD6DF21D1EED6503531 \
    --guest-fixture \
    --receipt "$RECEIPT" \
    --run
  builtin printf '\n'
} > "$EVIDENCE_ROOT/exact-command.txt"

if (( PREFLIGHT_STATUS == 0 )); then
  set +e
  "${CLEAN_ENV[@]}" "$RUN_ROOT/dnfast/tools/public-qemu-matrix.sh" \
    --arch x86_64 \
    --baseurl https://localhost:18443 \
    --fingerprint 2B017A94136265DB56C0CCD6DF21D1EED6503531 \
    --guest-fixture \
    --receipt "$RECEIPT" \
    --run 2>&1 | /usr/bin/tee "$MATRIX_CONSOLE_LOG"
  export MATRIX_STATUS=${PIPESTATUS[0]}
  set -e
else
  export MATRIX_STATUS=125
  builtin printf 'matrix not run: preflight exit %s\n' "$PREFLIGHT_STATUS" \
    > "$MATRIX_CONSOLE_LOG"
fi
builtin printf '%s\n' "$MATRIX_STATUS" > "$EVIDENCE_ROOT/matrix.exit"
```

dnfast executor를 직접 실행하거나, harness·fixture·fingerprint를 바꾸거나,
실패 검사를 완화하지 않는다.

## 5. 결과를 Ventoy에 반환

성공과 실패 모두 아래 블록을 실행한다. Receipt가 생성되지 않은 조기
실패도 evidence 디렉터리 전체가 반환되므로 복사가 중단되지 않는다.

```bash
"${CLEAN_ENV[@]}" \
  "PREFLIGHT_STATUS=$PREFLIGHT_STATUS" \
  "MATRIX_STATUS=$MATRIX_STATUS" \
  /usr/bin/bash --noprofile --norc -euo pipefail -c '
if (( PREFLIGHT_STATUS == 0 )); then
  /usr/bin/cp -- "$MATRIX_HOST_TOOLS_SHA256" \
    "$EVIDENCE_ROOT/trusted-host-tools.sha256" \
    || builtin printf "trusted host-tools manifest copy failed\n" \
      >> "$EVIDENCE_ROOT/evidence-errors.log"
  /usr/bin/cp -- "$MATRIX_GUEST_ASSETS_SHA256" \
    "$EVIDENCE_ROOT/trusted-guest-assets.sha256" \
    || builtin printf "trusted guest-assets manifest copy failed\n" \
      >> "$EVIDENCE_ROOT/evidence-errors.log"
  /usr/bin/cp -- "$MATRIX_RPM_REPOSITORY_SHA256" \
    "$EVIDENCE_ROOT/trusted-rpm-repository.sha256" \
    || builtin printf "trusted RPM-repository manifest copy failed\n" \
      >> "$EVIDENCE_ROOT/evidence-errors.log"
fi

{
  /usr/bin/date -Is || builtin printf "date unavailable\n"
  /usr/bin/uname -a || builtin printf "uname unavailable\n"
  /usr/bin/cat /etc/os-release || builtin printf "/etc/os-release unavailable\n"
  /usr/bin/stat /dev/kvm || builtin printf "/dev/kvm unavailable\n"
  if (( PREFLIGHT_STATUS == 0 )); then
    "$MATRIX_QEMU_SYSTEM" --version \
      || builtin printf "qemu-system --version failed: %s\n" "$MATRIX_QEMU_SYSTEM"
  else
    builtin printf "qemu-system not executed because preflight failed: %s\n" \
      "$MATRIX_QEMU_SYSTEM"
  fi
  /usr/bin/sha256sum \
    "$RUN_ROOT/dnfast/tools/public-qemu-matrix.sh" \
    "$RUN_ROOT/dnfast/tools/tests/public-qemu-matrix-contract.sh" \
    || builtin printf "harness SHA-256 capture failed\n"
  /usr/bin/cat "$HANDOFF/SOURCE-IDENTITY.txt" \
    || builtin printf "SOURCE-IDENTITY.txt unavailable\n"
} > "$EVIDENCE_ROOT/HOST-AND-SOURCE.txt" 2>&1

/usr/bin/cp -- "$HANDOFF/SOURCE-IDENTITY.txt" "$EVIDENCE_ROOT/" \
  || builtin printf "SOURCE-IDENTITY.txt copy failed\n" \
    >> "$EVIDENCE_ROOT/evidence-errors.log"
/usr/bin/cp -- "$HANDOFF/SHA256SUMS-CURRENT.txt" \
  "$EVIDENCE_ROOT/HANDOFF-SHA256SUMS.txt" \
  || builtin printf "handoff checksum copy failed\n" \
    >> "$EVIDENCE_ROOT/evidence-errors.log"

RESULT_DIR="$VENTOY/dnfast-fedora44-x86-handoff/returned-current-x86-$RUN_ID"
[[ ! -e $RESULT_DIR ]]
/usr/bin/mkdir -m 0700 -- "$RESULT_DIR"
/usr/bin/cp -a -- "$EVIDENCE_ROOT/." "$RESULT_DIR/"

(builtin cd "$RESULT_DIR" && \
  /usr/bin/find . -type f ! -name SHA256SUMS.txt -print0 \
    | /usr/bin/sort -z \
    | /usr/bin/xargs -0 /usr/bin/sha256sum -- > SHA256SUMS.txt)
/usr/bin/sync
builtin printf "returned=%s preflight=%s matrix=%s\n" \
  "$RESULT_DIR" "$PREFLIGHT_STATUS" "$MATRIX_STATUS"
/usr/bin/sha256sum "$RESULT_DIR/SHA256SUMS.txt"
'
```

반환할 것은 생성된 `returned-current-x86-RUN_ID/` 디렉터리 전체다.
마지막에 출력된 `SHA256SUMS.txt`의 digest는 USB와 다른 신뢰 채널에도
기록한다. USB 내부 checksum만으로 결과 작성자를 인증할 수는 없다.
사설키, VM 원본 이미지, QEMU overlay, Cargo cache는 넣지 않는다.

## 성공 영수증의 필수 내용

exit code 0만으로 성공이 아니다. raw receipt에 다음이 모두 있어야 한다.

- `public_qemu_matrix_architecture=x86_64`
- `public_qemu_matrix_harness_sha256=<64 hex>`
- `public_qemu_matrix_source_manifest_sha256=<64 hex>`
- `public_qemu_matrix_guest_source_manifest=verified`
- `public_cli_sha256=<64 hex>`
- `root_snapshot_bootstrap=passed`
- `signed_install`, `signed_remove`, `public_pty_default_no`,
  `public_pty_yes`, `signed_upgrade`, `nonroot`, `verifydb`,
  `staging_cleanup`, `input_cleanup`, `before_after_sorted`의
  `matrix_scenario=... status=passed`
- `qmp_cleanup=completed`, `pid_cleanup=completed`,
  `overlay_cleanup=completed`

이 디렉터리를 현재 시스템으로 가져오면 여기서 영수증·해시·로그를
독립 검토한다. 검토 전에는 x86 지원 완료나 DNF5보다 빠르다는 주장을
하지 않는다.

상세 설계 근거와 회귀 경계는 `GROK_X86_HANDOFF.md`, 매트릭스 통과 뒤의
전체 작업 순서는 `NEXT_X86_HANDOFF.md`, 성능 측정 절차는
`BENCHMARK_X86_PROTOCOL.md`에 있다.
