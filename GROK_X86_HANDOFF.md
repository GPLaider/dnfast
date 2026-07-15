# dnfast: Grok x86_64 Fedora 44 KVM handoff

## Start here

The operator action list is now in [`START_HERE_X86.md`](START_HERE_X86.md).
First obtain the complete fixed bootstrap block plus both SHA-256 values over
an independent channel.  That block performs sections 0 and 1; then open the
authenticated extracted runbook and follow sections 2 through 5 without
substituting the older
run14 source or evidence.  This document is the detailed contract and
regression reference; it is not the primary copy-and-paste runbook.

## Scope and truthfulness

This handoff continues validation on a **native x86_64 Fedora 44 KVM host**.
It is a source handoff, not a release qualification.  The previous handoff
commit passed the native public transaction matrix; the current commit must be
rerun because it changes the harness and packages required test evidence.

## Current source status

The product-code baseline is commit `14a6df1`, which ports inventory-only
post-transaction republish.  Handoff commit
`8d990a194f48e7f41beedd880e96755212c054bc` passed every native x86_64 public
matrix scenario.  Its raw receipt SHA-256 is
`ab5afdd02362159aa6ed0f279bcfc8d4b0ca43f91acbc7e6e05dcf3e2c5cc5da`.
The current handoff fixes caller-CWD dependence in `cargo vendor` and moves two
test evidence fixtures into the source archive.  These changes require one
fresh current-commit matrix and an unskipped real-native workspace test.

The public matrix refuses to start unless `uname -m` is exactly `x86_64` and
`/dev/kvm` is a readable, writable character device.  Its QEMU command uses
`-machine q35,accel=kvm -cpu host`; **TCG, emulation, a cross-architecture
guest, and a host-side dnfast transaction are not valid substitutes**.

Use only the public surface during matrix validation:

- installed `/usr/bin/dnfast`, including `dnfast repo refresh`, public plan,
  and public apply;
- fixed `/usr/libexec/dnfast-executor` reached only by root `dnfast apply`;
- no direct executor invocation, provisioning example, debug binary, test
  hook, `DNFAST_TEST_*`, fixture-only public-path shortcut, `sudo` spawning
  by dnfast, or TCG fallback.

The harness itself uses guest `sudo` solely to set up the disposable VM and
then invokes the installed CLI.  That is intentional and not a dnfast
privilege-escalation path.

## Required x86_64 host inputs

Prepare these outside the Git worktree.  All paths below must be absolute.

1. Fedora 44 x86_64 host with hardware virtualization enabled, `/dev/kvm`
   read/write access, `qemu-system-x86_64`, `qemu-img`, and `cloud-localds`.
2. A Fedora Cloud Base Generic 44 **x86_64** qcow2 image, matching OVMF code
   and writable-copy source variables files.
3. A local, signed, locked RPM repository containing the exact Fedora 44
   guest build RPMs **and all of their dnf dependencies**, plus an accessible
   public GPG certificate for that repository.  `createrepo_c` rewrites its
   metadata before the guest consumes it.
4. The repository must provide the exact native ABI build set below.  Keep
   the package values synchronized with the locked repository if Fedora
   updates them; do not relax the native ABI gate to compensate.

```bash
export MATRIX_QEMU_SYSTEM=/absolute/path/to/qemu-system-x86_64
export MATRIX_QEMU_IMG=/absolute/path/to/qemu-img
export MATRIX_CLOUD_LOCALDS=/absolute/path/to/cloud-localds
export MATRIX_IMAGE=/absolute/path/to/Fedora-Cloud-Base-Generic-44.x86_64.qcow2
export MATRIX_FIRMWARE=/absolute/path/to/OVMF_CODE.fd
export MATRIX_VARIABLES=/absolute/path/to/OVMF_VARS.fd
export MATRIX_RPM_REPOSITORY=/absolute/path/to/locked-rpms
export MATRIX_CREATEREPO=/absolute/path/to/createrepo_c
export MATRIX_BUILD_GPG_KEY=/absolute/path/to/fedora-build-key.asc
export MATRIX_HOST_TOOLS_SHA256=/absolute/path/to/trusted-host-tools.sha256
export MATRIX_GUEST_ASSETS_SHA256=/absolute/path/to/trusted-guest-assets.sha256
export MATRIX_RPM_REPOSITORY_SHA256=/absolute/path/to/trusted-rpm-repository.sha256
export MATRIX_BUILD_PACKAGES='gcc-16.1.1-2.fc44.x86_64 libsolv-devel-0.7.39-1.fc44.x86_64 rpm-devel-6.0.1-2.fc44.x86_64 nettle-devel-3.10.1-3.fc44.x86_64 clang-22.1.8-1.fc44.x86_64 pkgconf-pkg-config-2.5.1-1.fc44.x86_64 rust-1.96.1-1.fc44.x86_64 cargo-1.96.1-1.fc44.x86_64'
```

The three SHA-256 manifests are trust inputs, not reports generated from the
same transferred media immediately before execution.  Obtain them through an
independent trusted channel and use the canonical ordering specified in
`START_HERE_X86.md`.  Preflight rejects non-root-owned, symlinked, or
group/world-writable host executables and any asset set that differs from
those manifests.

The guest build is deliberately real-native:
`DNFAST_NATIVE_REAL=1 cargo install --offline --locked ...`.  It must link to
Fedora 44 `libsolv.so.1` and `librpm.so.10`; the harness checks that linkage
for both installed binaries.  Do not add a synthetic/stub native mode.

## Transferred archive

The USB archive contains sibling `dnfast/` source and
`cargo-home/registry/` directories.  After extraction from the archive root,
set the portable Cargo home before any public-matrix command so the harness's
host `cargo vendor --offline --locked` operation uses the transferred cache:

```bash
export CARGO_HOME="$PWD/cargo-home"
cd dnfast
```

The archive does **not** contain native x86_64 VM assets.  The x86 Fedora 44
image, OVMF code/variables, QEMU binaries, `cloud-localds`, locked native RPM
repository, `createrepo_c`, and its build GPG key remain external requirements
and must be supplied through the `MATRIX_*` variables above.

## Exact public matrix command

From the transferred repository root, after exporting the inputs above:

```bash
tools/tests/public-qemu-matrix-contract.sh
bash -n tools/public-qemu-matrix.sh
tools/public-qemu-matrix.sh --help

tools/public-qemu-matrix.sh \
  --arch x86_64 \
  --baseurl https://localhost:18443 \
  --fingerprint 2B017A94136265DB56C0CCD6DF21D1EED6503531 \
  --guest-fixture \
  --receipt "$RECEIPT" \
  --run
```

`START_HERE_X86.md` creates `RECEIPT` under a fresh per-run evidence directory
and captures host preflight plus a synchronous combined matrix console log.
Do not replace it with a fixed or previously used receipt path.

`--guest-fixture` is the checked-in disposable HTTPS rpm-md fixture.  Its
certificate defaults to
`fixtures/rpm/generated-build10/keys/allowed.asc`; do not replace it with an
untracked private key.  The guest runs the HTTPS endpoint itself on loopback
while QEMU user networking is restricted.

The receipt and, on failure, bounded guest-log archive are intentionally
outside the repository.  Preserve them before retrying.  A successful receipt
must record all matrix scenarios, source/harness/binary hashes, `verifydb`,
cleanup, and before/after restoration; an exit zero alone is insufficient.

After a complete x86_64 public-matrix receipt is independently reviewed, use
[`BENCHMARK_X86_PROTOCOL.md`](BENCHMARK_X86_PROTOCOL.md) for the separate x86
benchmark procedure.  Do not substitute benchmark output for the transaction
matrix, or run the benchmark before the public matrix has passed.

## Source integrity and matrix boundary

Before compiling, the harness archives the current source plus vendored
dependencies, derives a sorted `path<TAB>sha256` manifest, copies both to the
guest, re-derives the guest manifest, byte-compares it, and records the
manifest SHA-256 in the receipt.  The guest build must not be treated as
evidence if `public_qemu_matrix_guest_source_manifest=verified` is absent.

The harness builds and installs only from that verified archive, then confirms
root-owned non-symlink `0755` `/usr/bin/dnfast` and
`/usr/libexec/dnfast-executor` files and their native dynamic linkage.  Do not
bypass these checks or execute the executor directly to turn a RED matrix
green.

The public scenarios are signed install, signed remove, default-No PTY,
affirmative PTY, signed upgrade and cleanup, non-root apply rejection,
`rpmdb --verifydb`, staging/input cleanup, and sorted inventory plus managed
filesystem restoration.  A scenario belongs in the receipt only after its
guest assertion succeeds.

## Prior native evidence

The latest comparable native aarch64 Fedora 44 KVM public matrix completed
successfully.  All public scenarios passed, including the transaction,
approval, non-root rejection, rpmdb, restoration, and cleanup assertions.
The receipt records completed QMP, PID, and overlay cleanup.

| Item | Exact observed value |
| --- | --- |
| receipt | `/tmp/dnfast-public-matrix-aarch64.run15.raw.log` |
| receipt SHA-256 | `8d8255b40beba177a4bb3a12e3eb2551cb8ea26b0c60e5beb07a16a947b88ca7` |
| installed public CLI SHA-256 | `3b9398b4cdc8bbf59bd02c7ce8264812a6b157ae77642076370b5d0aa9e8863a` |
| source-manifest SHA-256 | `fe7c4a874cb279029d1896157109fbc874cafef506a1b62c3cdcdbad510c833f` |

The aarch64 run remains useful cross-architecture evidence.  In addition, the
previous x86 handoff commit completed a Fedora 44 x86_64 KVM matrix with all
required scenarios and cleanup fields.  It does not replace a current-commit
rerun.

## Recently fixed behavior to preserve

The following changes were already exercised by source contracts and/or the
aarch64 progression.  Treat them as regression boundaries, not optional
cleanup:

- Fedora repository type accepts only documented rpm-md aliases (`rpm`,
  `rpm-md`, `repomd`, `rpmmd`, `yum`, `YUM`); invalid types and URL-shaped
  values reject before network access.
- `metadata_expire` has strict typed handling (including documented integer
  forms and `never`), while unsupported float/exponent forms reject; `countme`
  accepts only inert `0` or `1` and must never influence request telemetry.
- Root planning derives `releasever` and `basearch` only through anchored,
  environment-cleared `/usr/bin/rpm` system-variable handling.
- Stock Fedora GPG-key aliases under `/etc/pki/rpm-gpg` are allowed only by
  bounded, root-owned, no-follow alias resolution; repository-local key
  symlinks and unsafe external paths remain rejected.
- Cache-directory validation permits the normal root directory link count
  while retaining ownership, mode, and regular-file/link safety checks.
- The public guest compile explicitly sets `DNFAST_NATIVE_REAL=1`; the old
  stub-native ABI failure is not a valid test result.
- Public source provenance is manifest-bound host-to-guest before compilation.
- DNF config list semantics are explicit: `reposdir=` and `varsdir=` reset
  stock lists before appending the matrix directories.  The harness writes
  byte-exact newline config files rather than shell-escaped literal `\\n` text.
- Matrix failure capture retains bounded, mode-0600 guest logs, including
  build/refresh/digest logs and public plan/apply/PTY artifacts, while still
  preserving the original failure exit and QEMU cleanup.
- Apply-side root anchoring no longer tries to `fsync` an `O_PATH` directory
  descriptor; directory durability must use an FD that supports `fsync`.

## Continue on native x86_64

1. Run the three preflight commands and then the exact x86_64 public matrix
   command above without changing its KVM/public-CLI boundary.
2. Preserve the fresh receipt, serial log, and any bounded guest-log archive;
   report source, harness, and installed-CLI hashes with the result.
3. Claim native x86_64 transaction support only after every public scenario
   and cleanup assertion is recorded in a fresh receipt and independently
   reviewed.  Then run the unskipped real-native workspace suite and the
   15-repetition benchmark in [`NEXT_X86_HANDOFF.md`](NEXT_X86_HANDOFF.md).

## Report back template

```text
host: uname -m=<...>; Fedora=<...>; /dev/kvm=<mode/owner>; KVM used=yes/no
command: <exact public-qemu-matrix command>
preflight: contract=<pass/fail>; bash-n=<pass/fail>; help=<pass/fail>
source: git commit=<if any>; dirty paths=<list>; manifest SHA-256=<...>
matrix: exit=<...>; receipt=<path>; receipt SHA-256=<...>; harness SHA-256=<...>
receipt milestones: source_verified=<...>; snapshot_bootstrap=<...>; scenarios=<exact list>
failure or pass: <first failure verbatim, or every recorded scenario>
retained logs: serial=<path/SHA>; guest archive=<path/SHA>; cleanup=<three fields>
follow-up work (if any): diagnosis=<...>; tests=<...>; patch=<files>; result=<...>
claims: native x86 public transaction pass=<yes only with complete fresh receipt and independent review>
```

Do not include private keys, secrets, generated QEMU overlays, caches, or
unreviewed full guest images in a commit or transfer report.
