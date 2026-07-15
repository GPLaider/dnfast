# dnfast x86_64 다음 작업

이 문서가 이번 전달본의 작업 순서다. `START_HERE_X86.md`의 매트릭스
절차를 먼저 수행하고, 성공한 뒤 아래 2단계와 3단계를 계속한다. 소스나
테스트를 고쳐서 통과시키지 말고, 실패 원본과 체크섬을 먼저 반환한다.

## 이미 확인된 사실

- 이전 전달 커밋 `8d990a194f48e7f41beedd880e96755212c054bc`는 Fedora
  44 x86_64 KVM public transaction matrix를 통과했다.
- 성공 영수증 SHA-256은
  `ab5afdd02362159aa6ed0f279bcfc8d4b0ca43f91acbc7e6e05dcf3e2c5cc5da`다.
- 첫 실행 실패 원인은 harness의 `cargo vendor`가 호출자의 현재 디렉터리에
  의존한 것이었다. 이번 소스는 `--manifest-path "$ROOT/Cargo.toml"`로
  고쳤으므로 소스 디렉터리 밖에서 실행해도 된다.
- 전체 real-native 테스트에서 빠졌던 두 증거 fixture도 이번 아카이브의
  `crates/dnfast-solver/tests/fixtures/evidence/`에 포함했다.
- 위 GREEN은 이전 커밋 증거다. 이번 전달 커밋의 최종 증거로 재사용하지
  않는다.

## 1. 이번 전달본 public matrix 재실행

USB 밖의 신뢰 채널로 받은 고정 bootstrap을 실행하고, 추출된
`START_HERE_X86.md`의 2단계부터 5단계까지 그대로 수행한다. 호출자의 현재
디렉터리를 소스 루트로 바꾸는 우회는 하지 않는다. 성공·실패 결과
`returned-current-x86-RUN_ID/`를 모두 보존한다.

성공이면 raw receipt에서 source manifest 검증, 모든 10개 scenario,
RPMDB 검증, QMP/PID/overlay cleanup을 확인한다. 실패이면 수정하기 전에
console, raw receipt, serial/guest log, exit code와 체크섬을 먼저 반환한다.

## 2. 제외 없는 real-native workspace 테스트

bootstrap으로 만든 같은 셸과 추출된 소스에서 실행한다. 먼저 x86 호스트에
매트릭스 guest와 같은 정확한 Fedora 44 build dependency가 설치·검증됐는지
확인한다. 이 검사를 통과하지 못하면 테스트를 실행하지 않고 결과를
실패로 반환한다.

```bash
HOST_BUILD_PACKAGES=(
  gcc-16.1.1-2.fc44.x86_64
  libsolv-devel-0.7.39-1.fc44.x86_64
  rpm-devel-6.0.1-2.fc44.x86_64
  pkgconf-pkg-config-2.5.1-1.fc44.x86_64
  rust-1.96.1-1.fc44.x86_64
  cargo-1.96.1-1.fc44.x86_64
)
HOST_NATIVE_PREFLIGHT_LOG="$EVIDENCE_ROOT/host-native-preflight.log"
HOST_NATIVE_PREFLIGHT_EXIT="$EVIDENCE_ROOT/host-native-preflight.exit"
set +e
(
  set -e
  rpm -q -- "${HOST_BUILD_PACKAGES[@]}"
  rpm -V -- "${HOST_BUILD_PACKAGES[@]}"
  pkg-config --exact-version=0.7.39 libsolv
  pkg-config --exact-version=6.0.1 rpm
) >"$HOST_NATIVE_PREFLIGHT_LOG" 2>&1
HOST_NATIVE_PREFLIGHT_STATUS=$?
set -e
printf '%s\n' "$HOST_NATIVE_PREFLIGHT_STATUS" >"$HOST_NATIVE_PREFLIGHT_EXIT"

cd "$RUN_ROOT/dnfast"
if (( HOST_NATIVE_PREFLIGHT_STATUS == 0 )); then
  set +e
  DNFAST_NATIVE_REAL=1 cargo test --offline --locked \
    --workspace --all-targets -- --test-threads=1 \
    >"$EVIDENCE_ROOT/workspace-real-native.log" 2>&1
  WORKSPACE_STATUS=$?
  set -e
else
  WORKSPACE_STATUS=125
  printf '%s\n' \
    'workspace test not run: host native dependency preflight failed' \
    >"$EVIDENCE_ROOT/workspace-real-native.log"
fi
printf '%s\n' "$WORKSPACE_STATUS" >"$EVIDENCE_ROOT/workspace-real-native.exit"
sha256sum \
  "$HOST_NATIVE_PREFLIGHT_LOG" \
  "$HOST_NATIVE_PREFLIGHT_EXIT" \
  "$EVIDENCE_ROOT/workspace-real-native.log" \
  "$EVIDENCE_ROOT/workspace-real-native.exit" \
  >"$EVIDENCE_ROOT/workspace-real-native.sha256"
```

테스트 제외, `--skip`, fixture 대체, `DNFAST_NATIVE_REAL` 제거는 금지한다.
두 fixture의 SHA-256은 다음과 같아야 한다.

```text
1e318cd020447bf765c096bd6b381359a1e45144b53165450331072114563ee2  task-8-native-causal-decisions.raw.log
b171221fe196809116ece6f9714a299b3e0342ee6bf7dfc4ed12507f9fbf359e  task-9-fedora44-inventory.raw.log
```

## 3. DNF5 비교 벤치마크

1단계와 2단계가 모두 0일 때만 `BENCHMARK_X86_PROTOCOL.md`를 실행한다.
고정된 signed rpm-md 저장소, x86_64 KVM, 독립 qcow2 overlay, 동일 요청과
동일 최종 NEVRA를 사용하고 각 비교 셀에서 도구별로 유효한 성공 표본을
최소 15개 확보한다.

프로토콜의 모든 측정 셀을 실행한다. 여기에는 cold/warm metadata refresh,
cold/warm solve/plan, **cold install**, metadata-warm install, fully-warm
install, remove가 포함된다. 어느 도구든 nonzero, 다른 transaction, 외부
endpoint 접속 또는 상태 불일치가 있으면 그 시도를 성공 표본에 포함하지
않되 버리지 말고 실패 또는 `not comparable`로 기록한다. 성공 표본 15개를
채우기 위해 추가한 시도도 모두 보존한다. 완전한 보고서 전에는 dnfast가
DNF5보다 빠르다는 주장을 하지 않는다.

## 반환물

Ventoy에 새 이름의 결과 디렉터리를 만들고 다음을 넣는다.

1. 1단계의 `returned-current-x86-RUN_ID/` 전체.
2. host-native preflight와 real-native workspace의 log, exit code, SHA-256 파일.
3. 벤치마크의 입력 환경, 호스트/게스트 정보, baseline digest, 모든 raw 시도
   및 셀·도구별 최소 15개 성공 표본, 각 도구의 plan/transaction, 네트워크
   로그, 요약 통계와 전체 SHA-256.
4. 사용한 Git commit, source manifest, harness, 설치된 두 CLI의 SHA-256.

반환 디렉터리 자체의 정렬된 `SHA256SUMS.txt`도 만들고 그 파일의 SHA-256을
USB 밖의 채널로 함께 보낸다. 기존 결과 디렉터리는 수정하거나 삭제하지
않는다.
