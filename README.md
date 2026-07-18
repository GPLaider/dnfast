# dnfast

`dnfast` is an independent Fedora RPM package manager. It reads rpm-md repositories, resolves
transactions directly with libsolv, downloads and verifies selected RPMs, and executes approved
transactions directly with librpm. It does not invoke DNF or DNF5 to solve or apply transactions.

The implemented command surface is deliberately smaller than DNF5:

```bash
dnfast doctor
dnfast repo list
sudo dnfast repo refresh --repo fedora
sudo dnfast repo makecache --repo fedora
sudo dnfast search bash
dnfast group list
dnfast group info development-tools
sudo dnfast group install development-tools --assumeno
dnfast module list
sudo dnfast plan install bash --output /var/lib/dnfast/bash-plan.json
sudo dnfast apply /var/lib/dnfast/bash-plan.json --assumeyes
sudo dnfast install bash --assumeyes
sudo dnfast remove bash --assumeyes
sudo dnfast upgrade --assumeyes
sudo dnfast history list
sudo dnfast history info 018f1f2e-7b3c-7abc-8def-0123456789ab
sudo dnfast daemon status
sudo dnfast daemon warm --repo fedora
```

`repo refresh` and package-changing commands require root. `plan` writes a solved, reviewable,
canonical plan to the mandatory absolute `--output` path. Plans are bound to the exact RPMDB,
metadata, repository policy, package digests, and trust material and expire after five minutes.
The convenience mutation commands normally use the root-only `dnfastd` service. The daemon keeps
one libsolv pool resident, returns the exact solved action set for approval, and accepts an
approval token only on the same connection and unchanged RPMDB/repository generation. If the
socket is absent because the installed systemd service is stopped, the root CLI requests one
non-blocking activation through the fixed root-owned `/usr/bin/systemctl` path and reconnects to
the same token-bound protocol. If systemd or the service is unavailable, the CLI retains the
fixed-executor path as a safe compatibility fallback; protocol and integrity failures never fall
back. Root `plan` also uses the resident solve when the service is available.

Install `dnfastd` at `/usr/libexec/dnfastd`, install
[`packaging/dnfastd.service`](packaging/dnfastd.service) as a system service, and enable it before
benchmarking the resident path. `dnfast daemon status` reports protocol readiness, while
`dnfast daemon warm` loads the exact selected repository generation outside a timed mutation.

The daemon caches only an exact canonical intent for the unchanged planning generation and RPMDB
cookie. Its libsolv pool stays primary-only. During refresh, verified filelists are streamed into
a checksum-bound compact path-to-package index (256 logical buckets stored in 16 physical shards).
An absolute-path selector reads only its one physical shard, maps the path to package ordinals,
and adds one native `ONE_OF` selector to the resident solve. The solve never opens full filelists,
and the plan preserves the user's original absolute-path intent.

`repo makecache` obeys the trusted `metadata_expire` policy. Both `makecache` and explicit
`refresh` still fetch current `repomd.xml`; reuse is allowed only when its exact digest matches the
published generation and every immutable metadata/index object has been rehashed successfully.
`history list` and `history info` report dnfast's verified durable transaction journal; they do not
import or claim compatibility with DNF5 history.

Checksum-bound comps group/environment list, info, and install are implemented. Group install
selects mandatory/default packages, conditionals whose requirements are selected or installed,
and optional packages/groups only with `--with-optional`. Module commands expose an explicit
fail-closed boundary: repositories without module metadata list no streams, while the presence of
modulemd is rejected because this build does not yet interpret module stream policy safely.
Plugin, COPR, system-upgrade, offline, group removal, autoremove, downgrade, reinstall,
distro-sync, and advisory commands are not implemented and fail closed.
`dnfast` does not claim DNF5 policy or state compatibility.

## Native build and test

The real native path requires the Fedora libsolv, librpm, Nettle, and Clang development packages
(`libsolv-devel rpm-devel nettle-devel clang`). Clang is used by the locked Nettle bindings
build; runtime metadata-signature verification uses Sequoia OpenPGP. Build and test explicitly so
a missing native or cryptographic toolchain cannot be mistaken for a successful product build:

```bash
DNFAST_NATIVE_REAL=1 cargo build --offline --locked --workspace --all-targets
DNFAST_NATIVE_REAL=1 cargo test --offline --locked --workspace --all-targets -- --test-threads=1
```

## Workspace

- `dnfast-core`: canonical transaction intent, inventory, policy, and integrity types
- `dnfast-repo`: strict `.repo` and `dnf.conf` loading with explicit trust policy
- `dnfast-metadata`: bounded rpm-md parsing and checksum verification
- `dnfast-cache`: immutable metadata and RPM artifact caches
- `dnfast-refresh`: HTTPS-only repository refresh orchestration
- `dnfast-planning`: root-published RPMDB/repository snapshots
- `dnfast-native-sys`: narrow C ABI over libsolv and librpm
- `dnfast-native`: safe native solver, inventory, trust, and transaction state
- `dnfast-solver`: explained canonical plan construction and validation
- `dnfast-state`: durable transaction journal and reconciliation state
- `dnfast-executor`: resident root service, fixed fallback, plan preparation, and librpm executor
- `dnfast-cli`: supported user command surface and JSON response contract

Read [architecture](docs/architecture.md) and [safety](docs/safety.md) before changing solver,
metadata transport, cache, trust, or RPM transaction code.
