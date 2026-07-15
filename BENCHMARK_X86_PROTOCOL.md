# dnfast x86_64 Fedora 44 benchmark protocol

## Purpose and claim boundary

This document defines a reproducible comparison between the installed public
`/usr/bin/dnfast` CLI and the installed Fedora 44 `dnf5` CLI.  It measures
metadata refresh, dependency solve/plan, install, and remove performance on a
native x86_64 Fedora 44 KVM guest.

It is a measurement protocol, not a performance claim.  **Do not claim that
dnfast is faster, equivalent, or slower until a complete report produced by
this protocol is available.**  A successful functional matrix, a solver-pool
probe, a build time, or an aarch64 result is not benchmark evidence.

## Non-negotiable validity conditions

Every reported sample must satisfy all of the following.

1. The host and guest are both `x86_64`, KVM is in use, and the QEMU command
   contains `-machine q35,accel=kvm -cpu host`.  TCG, emulation, Rosetta,
   nested software fallback, and cross-architecture execution invalidate the
   entire run.
2. The guest is Fedora 44.  Record `uname -a`, `/etc/os-release`, kernel,
   microcode, CPU model/count, RAM, storage backend, QEMU version, `dnf5
   --version`, `dnfast --version`, source manifest SHA-256, and the exact
   package NEVRAs for `dnfast`, `libsolv`, `rpm`, and `dnf5`.
3. Both tools use the same immutable, signed rpm-md repository generation,
   the same public certificate/fingerprint, the same mirror URL, and the
   same package universe.  Record the `repomd.xml` SHA-256, repository
   signing fingerprint, and all requested package NEVRAs.
4. Each measured invocation starts from an independently created guest disk
   overlay whose RPMDB and managed filesystem match the recorded baseline.
   Never benchmark against the host RPMDB, a reused mutable guest, or a
   production repository.
5. Setup, guest boot, source compilation, package installation, repository
   creation, key import, DNS setup, and the first command used only to create
   a warm cache are outside the timer.  Do not call any of those costs a
   refresh, solve, or transaction result.
6. A command that exits nonzero, changes an unexpected package/filesystem
   state, contacts another endpoint, has a signature failure, or lacks its
   measurement files is a failed sample, not an outlier to discard.

## Fixed test inputs

Use the checked-in signed fixture only when it supplies the desired package
set; otherwise create one locked signed repo once, record its manifest and
keep it unchanged for the entire experiment.  Serve it from one guest-local
HTTPS origin, for example `https://127.0.0.1:18443/repos/main`.  The fixture
server access log is the network accounting authority.

Choose one package set before measuring and record exact NEVRAs in
`bench-inputs.env`:

```bash
export BENCH_REPO_URL='https://127.0.0.1:18443/repos/main'
export BENCH_REPO_ID='bench'
export BENCH_FINGERPRINT='replace-with-recorded-public-fingerprint'
export BENCH_INSTALL_NEVRAS='replace-with-one-or-more-exact-nevras'
export BENCH_REMOVE_NAMES='replace-with-the-names-installed-by-the-install-case'
export BENCH_PLAN_SPECS='replace-with-the-identical-install-intent'
export BENCH_REPETITIONS=15
```

`BENCH_INSTALL_NEVRAS` must resolve to the same final installed NEVRA set for
both tools.  `BENCH_PLAN_SPECS` must represent the same request for both
tools, including any relation selector.  If either resolver produces a
different transaction, retain both plans and mark the cell `not comparable`;
do not compare elapsed times.

Create and hash these three read-only baselines before the first sample:

| Baseline | RPMDB / filesystem state | Use |
| --- | --- | --- |
| `B0` | neither benchmark package installed; no benchmark metadata or artifact cache | cold refresh, cold solve/plan, cold install |
| `B1` | same packages as `B0`; each tool's own cache was primed once, unmeasured | warm refresh, warm solve/plan, metadata-warm install |
| `B2` | exactly the recorded install transaction applied; no unrelated changes | remove |

`B1` is not a shared cache directory: dnfast and DNF5 have different cache
layouts.  It is two independently produced, tool-owned caches created from
the same `B0`, repository generation, URL, certificate, and requested
operation.  The prime command and its cache directory digest must be
recorded.  Cache contents are never copied from one tool to the other.

For a warm install comparison, define the artifact condition explicitly:

- **metadata-warm install:** metadata is primed; RPM artifacts are absent for
  both tools, so package transfer is measured.
- **fully-warm install:** metadata and the exact RPM payloads are primed by
  one unmeasured operation for each tool.  Report this as a separate cell;
  never combine it with metadata-warm results.

## Guest layout and isolation

Build a clean Fedora 44 x86_64 base guest containing the two installed public
CLIs, `/usr/bin/time`, `perf`, `rpm`, `sha256sum`, and the local HTTPS fixture
server.  Then create a qcow2 overlay per trial from the appropriate baseline:

```bash
qemu-img create -f qcow2 -F qcow2 -b /absolute/baselines/B0.qcow2 \
  /absolute/runs/run-001.dnfast.cold-refresh.qcow2
```

Inside every overlay, use only these owned locations (adjust the paths only
before the first trial and record them):

```text
/var/lib/dnfast-bench/dnfast-cache
/var/lib/dnfast-bench/dnf-cache
/var/lib/dnfast-bench/dnf-persist
/var/lib/dnfast-bench/logs
/var/lib/dnfast-bench/plans
/var/lib/dnfast-bench/fixture-access.log
```

Configure the guest's root-owned dnfast configuration once per baseline so
`dnfast repo refresh` and plan/apply read only its designated dnfast cache and
the benchmark repository.  Configure DNF5 on every invocation with its
designated `cachedir` and `persistdir`, disable every non-benchmark repo, and
use the same releasever/basearch as dnfast.  Neither tool may use a caller
home cache or another enabled Fedora mirror.

Before and after every sample, save:

```bash
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort
rpmdb --verifydb
find /usr /etc /var -xdev -type f -printf '%p\t%s\t%T@\n' | LC_ALL=C sort
```

The expected before/after relationship is `B0 -> B0` for refresh and
solve/plan, `B0 -> B2` for install, and `B2 -> B0` for remove (apart from the
recorded benchmark cache/log paths).  `rpmdb --verifydb` must succeed after
every transaction.

## Command templates

Run commands as root inside the disposable guest.  Paths and repository
configuration are illustrative placeholders; replace them only in the
recorded experiment manifest.  Emit structured CLI output where supported so
the selected transaction can be retained.

```bash
# Common DNF5 options.  Do not add a second repository.
DNF5=(dnf5 --assumeyes --repo="$BENCH_REPO_ID" \
  --setopt="cachedir=/var/lib/dnfast-bench/dnf-cache" \
  --setopt="persistdir=/var/lib/dnfast-bench/dnf-persist" \
  --setopt="install_weak_deps=False")

# dnfast refresh / plan / public mutations.
dnfast --json repo refresh --repo "$BENCH_REPO_ID"
dnfast --json plan install --repo "$BENCH_REPO_ID" \
  --output /var/lib/dnfast-bench/plans/dnfast-install.plan $BENCH_PLAN_SPECS
dnfast --json install --repo "$BENCH_REPO_ID" --assumeyes $BENCH_INSTALL_NEVRAS
dnfast --json remove --repo "$BENCH_REPO_ID" --assumeyes $BENCH_REMOVE_NAMES

# DNF5 equivalents.  The plan operation must not mutate the RPMDB.
"${DNF5[@]}" makecache --refresh
"${DNF5[@]}" --assumeno install $BENCH_PLAN_SPECS
"${DNF5[@]}" install $BENCH_INSTALL_NEVRAS
"${DNF5[@]}" remove $BENCH_REMOVE_NAMES
```

For every timed command, use the same wrapper.  The wrapper starts after the
fixture server is ready and stops before integrity collection begins:

```bash
label='run-001.dnfast.cold-refresh'
log=/var/lib/dnfast-bench/logs
start_requests=$(wc -l < /var/lib/dnfast-bench/fixture-access.log)
start_bytes=$(awk '{sum += $NF} END {print sum + 0}' /var/lib/dnfast-bench/fixture-access.log)

/usr/bin/time -v -o "$log/$label.time" \
  perf stat -x, -o "$log/$label.perf.csv" \
  -- <EXACT-COMMAND> >"$log/$label.stdout" 2>"$log/$label.stderr"
status=$?

end_requests=$(wc -l < /var/lib/dnfast-bench/fixture-access.log)
end_bytes=$(awk '{sum += $NF} END {print sum + 0}' /var/lib/dnfast-bench/fixture-access.log)
printf '%s\t%s\t%s\t%s\n' "$label" "$status" \
  "$((end_requests - start_requests))" "$((end_bytes - start_bytes))" \
  >> "$log/network.tsv"
exit "$status"
```

The fixture access-log format must have response bytes as its last numeric
field.  If it does not, change the server format before measuring, not during
the run.  Record the exact command line and SHA-256 of every stdout, stderr,
`time`, `perf`, network, plan, and transaction log file.

## Measured cells and expected observations

For each row, collect at least `BENCH_REPETITIONS=15` successful samples per
tool.  Execute a randomized, interleaved order (for example, a pre-generated
seeded permutation of tool × cell × repetition) rather than all dnfast runs
followed by all DNF5 runs.  Preserve the seed and complete order.

| Cell | Baseline | dnfast command | DNF5 command | Required observation |
| --- | --- | --- | --- | --- |
| cold refresh | `B0` | `repo refresh` | `makecache --refresh` | verified signed metadata; endpoint requests/bytes captured |
| warm refresh | `B1` | `repo refresh` | `makecache` | cache reuse evidenced; classify any request/byte transfer |
| cold solve/plan | `B0` | `repo refresh && plan install` in one timed cell | `--assumeno install` | no RPMDB/filesystem mutation; comparable final NEVRA set; metadata acquisition included |
| warm solve/plan | `B1` | `plan install` | `--assumeno install` | no network metadata fetch unless explicitly reported; no mutation |
| cold install | `B0` | `repo refresh && install --assumeyes` in one timed cell | `install` | same installed NEVRA set; metadata and payload bytes captured |
| metadata-warm install | `B1` | `install --assumeyes` | `install` | same installed NEVRA set; artifact bytes separately reported |
| fully-warm install | fully-warm derivative of `B1` | `install --assumeyes` | `install` | same installed NEVRA set; zero payload transfer expected |
| remove | `B2` | `remove --assumeyes` | `remove` | same removal result; `rpmdb --verifydb` succeeds |

For dnfast plan/apply flows that require a plan file, retain the plan and use
the public `dnfast apply` command in the transaction cell.  Do not invoke
`/usr/libexec/dnfast-executor` directly.  For DNF5, `--assumeno` is the
non-mutating solve/plan analogue; retain its resolved transaction output.

## Metrics and cache evidence

For each sample record these values without rounding the raw values:

| Category | Source | Required fields |
| --- | --- | --- |
| wall/user/system CPU | `/usr/bin/time -v` | elapsed seconds, user seconds, system seconds, exit status |
| memory | `/usr/bin/time -v` | Maximum resident set size (KiB) |
| CPU counters | `perf stat -x,` | task-clock, cycles, instructions, context switches, page faults; record unavailable counters as unavailable, not zero |
| network | fixture access log delta | request count, response bytes, request paths, status codes |
| cache | cache manifest + access log | cache directory SHA-256 manifest before/after; metadata and payload hit/miss classification |
| correctness | retained outputs and RPMDB checks | selected NEVRAs, signature success, `verifydb`, before/after state hashes |

A warm cache hit is valid only when the expected cache object/manifest is
present before the command and the fixture-log delta supports the claimed
scope.  For warm refresh and warm solve/plan, a zero metadata request/byte
delta is a full metadata hit.  For metadata-warm install, metadata may be a
hit while RPM payload transfer is a miss; label it exactly that way.  A cache
directory merely existing, or a client line saying "cached", is insufficient
evidence on its own.

## Result publication

Keep raw files in a result directory outside the source tree, with a manifest:

```text
results/<run-id>/
  environment.txt
  inputs.env
  order.txt
  repomd.sha256
  samples.tsv
  raw/<label>.{time,perf.csv,stdout,stderr,network.tsv,plan,transaction.log}
  SHA256SUMS
  REPORT.md
```

`samples.tsv` contains one row per attempted sample, including failures:

```text
run_id	seed	tool	cell	iteration	baseline	status	wall_s	user_s	sys_s	max_rss_kib	requests	response_bytes	cache_class	selected_nevras_sha256	raw_sha256
```

Report median, p05, p95, minimum, maximum, and all individual values for each
valid comparable cell.  Do not silently omit slow values.  Failed or
non-comparable samples remain in the report, separate from the summary.

Use this table in `REPORT.md`:

| Cell | Tool | n attempted / valid | Median wall s (p05–p95) | Median max RSS KiB | Median user+sys s | Median requests / bytes | Cache class | Correctness result | Claim |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| cold refresh | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| cold refresh | dnf5 |  |  |  |  |  |  |  | pending measured evidence |
| warm refresh | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| warm refresh | dnf5 |  |  |  |  |  |  |  | pending measured evidence |
| cold solve/plan | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| cold solve/plan | dnf5 |  |  |  |  |  |  |  | pending measured evidence |
| warm solve/plan | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| warm solve/plan | dnf5 |  |  |  |  |  |  |  | pending measured evidence |
| cold install | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| cold install | dnf5 |  |  |  |  |  |  |  | pending measured evidence |
| metadata-warm install | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| metadata-warm install | dnf5 |  |  |  |  |  |  |  | pending measured evidence |
| fully-warm install | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| fully-warm install | dnf5 |  |  |  |  |  |  |  | pending measured evidence |
| remove | dnfast |  |  |  |  |  |  |  | pending measured evidence |
| remove | dnf5 |  |  |  |  |  |  |  | pending measured evidence |

Only state a speed difference for a cell when the row has matching final
NEVRA/correctness evidence, 15 valid samples per tool, retained raw artifacts,
and all validity conditions above.  Scope every statement to the exact cell,
repository generation, Fedora build, hardware, and cache condition measured.
