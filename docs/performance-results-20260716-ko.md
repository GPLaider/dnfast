# Fedora 44 x86_64 성능·안전성 검증 (2026-07-16)

## 결론

dnfast는 동일한 intent가 반복되는 resident hot path와 변경 없는 verified refresh에서
dnf5보다 명확히 빨랐다. 반면 서로 다른 intent의 첫 solve는 대체로 dnf5보다 느렸고,
전체 cold refresh는 인터넷 미러 편차가 커서 우위를 입증하지 못했다. 따라서 “모든
상황에서 dnf5보다 빠르다”는 결론은 내리지 않는다.

| 구간 | dnfast | dnf5 | 해석 |
|---|---:|---:|---|
| 동일 복합 intent, exact warm hit 5회 | 각 0.01 s | 1.13–1.18 s | dnfast 우세; tmpfs plan 출력 포함 |
| 변경 없는 verified refresh | 2.75 s | 5.51 s | dnfast 약 2.0배 빠름 |
| 서로 다른 cold intent | 1.71–2.05 s | 0.80–2.30 s | kernel-devel 외에는 dnf5 우세 |
| 전체 cold refresh | 116.98 s | 61.34 s | 해당 1회에서는 dnfast 열세; 미러 timeout/retry 포함 |
| 전체 cold refresh peak RSS | 268,388 KiB | 542,204 KiB | 해당 실행에서는 dnfast가 낮음 |

dnfast exact hit의 daemon 내부 시간은 약 3.8–8.2 ms였다. 클라이언트 peak RSS는 약
12.3 MiB였지만, Fedora/updates pool을 상주시킨 daemon은 별도 측정에서 RSS
824,000 KiB(약 805 MiB), HWM 913,456 KiB를 사용했다. `/var/tmp`에 내구성 있는 plan을
쓴 실행은 solve-cache hit인데도 fsync/storage
편차 때문에 0.06–1.37 s였으므로 solve 시간과 plan 저장 시간을 구분해야 한다.

## 공정성 및 조건

- 호스트는 Fedora 44 x86_64이며 Fedora, updates, fedora-cisco-openh264를 사용했다.
- dnfast는 `DNFAST_NATIVE_REAL=1`로 빌드해 libsolv/librpm에 직접 연결했다.
- 변경 없는 refresh는 양쪽 모두 네트워크에서 현재 repository 상태를 확인했다.
  dnfast는 fresh repomd의 정확한 SHA-256 일치와 immutable metadata/index 재해시 뒤에만
  기존 generation을 사용했다.
- dnf5 cold refresh에는 `--setopt=optional_metadata_types=comps,updateinfo,filelists
  --refresh makecache`를 사용해 적어도 dnfast가 요구하는 filelists를 강제했다. 그러나
  dnf5가 comps/updateinfo도 받으므로 바이트 수가 완전히 같지는 않다.
- solve 비교는 실제 설치를 하지 않았다. dnfast는 canonical plan을 만들었고, dnf5는
  의존성 계산과 transaction 요약 뒤 기본 No로 종료했다. dnf5의 exit 1은 이 의도적인
  취소이며 solve 실패가 아니다.
- cold refresh 1회 수치는 공개 미러의 순간 대역폭·timeout 영향을 크게 받는다. 코드
  변경 전후의 다른 성공 실행도 42.80 s와 116.98 s로 벌어졌으므로 네트워크 우열의
  통계적 증거로 사용하지 않는다.

## 안전성과 기능 검증

- native solver 회귀, 20회 결정성, 이미 설치된 패키지 install의 idempotence, upgrade,
  file provide, 크기 제한 및 실패 복구를 통과했다.
- 실제 Fedora 대형 primary/filelists 스트리밍 검증은 9.42 s, peak RSS 159,076 KiB로
  통과했다.
- 전체 release native workspace test는 3분 30.98초, peak RSS 875,556 KiB, exit 0이다.
- Fedora 44 x86_64 KVM에서 실제 native linkage, signed install/remove/upgrade, PTY
  default-No/yes, non-root 거부, `rpm --verifydb`, staging/input cleanup, 작업 전후 RPM
  inventory 동일성을 모두 통과했다.
- v4 planning snapshot은 같은 실제 metadata에서 약 120.5 MB에서 615,043 bytes로 줄었다.
  큰 payload는 root-owned SHA-256 blob으로 분리되고 읽을 때 size/hash/storage binding을
  다시 검증한다.
- absolute-path selector(`/usr/bin/htop`)는 primary-only daemon cache를 사용하지 않고
  filelists를 포함한 snapshot-bound planner로 안전하게 fallback해 올바른 plan을 만들었다.
- `history list/info`는 dnfast 자체 durable journal만 검증해 보여 준다.

## 남은 실제 제한

- groups/environments 및 modules는 아직 미지원이며 요청 시 fail closed한다.
- 서로 다른 첫 intent solve는 추가 최적화가 필요하다.
- resident daemon의 824,000 KiB RSS working set은 낮춰야 한다.
- cold refresh의 공정한 우열은 로컬 고정 mirror와 반복 표본으로 별도 측정해야 한다.

전체 원시 로그와 최종 SHA-256 manifest는 외부 handoff의
`evidence-fast-goal-20260716`에 보존한다.
