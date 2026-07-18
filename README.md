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
sudo dnfast group remove development-tools --assumeno
dnfast module list
sudo dnfast module install nodejs:22/default --assumeno
sudo dnfast plan install bash --output /var/lib/dnfast/bash-plan.json
sudo dnfast apply /var/lib/dnfast/bash-plan.json --assumeyes
sudo dnfast install bash --assumeyes
sudo dnfast remove bash --assumeyes
sudo dnfast upgrade --assumeyes
sudo dnfast history list --source all
sudo dnfast history info 018f1f2e-7b3c-7abc-8def-0123456789ab
sudo dnfast history info dnf5:10
sudo dnfast daemon status
sudo dnfast daemon warm --repo fedora
```

`repo refresh` and package-changing commands require root. `plan` writes a solved, reviewable,
canonical plan to the mandatory absolute `--output` path. Plans are bound to the exact RPMDB,
metadata, repository policy, package digests, and trust material and expire after five minutes.
The convenience mutation commands and root `plan` are daemonless by default. Each command opens
the generation-bound immutable `.solv` cache through `mmap`, builds one libsolv pool, and releases
it after the result. A Btrfs-protected RPMDB generation receipt can reuse the exact published
inventory and installed `.solv` input without a redundant librpm walk; any WAL, file-generation,
ABI, architecture, cookie, inventory, or receipt mismatch takes the full verification path.
Approved local mutations pass a sealed plan, a sealed compact manifest, and retained verified RPM
artifact descriptors to the fixed executor. Repository XML, filelists, provider tables, and
relation evidence are neither copied nor decompressed again at that boundary.

`dnfastd` remains an explicit opt-in for controlled workloads that prefer a resident solver pool;
ordinary commands neither enable nor start it. Install it at `/usr/libexec/dnfastd` with
[`packaging/dnfastd.service`](packaging/dnfastd.service), then explicitly start the service before
using `dnfast daemon warm`. `dnfast daemon status` only reports protocol readiness.

The daemon caches only an exact canonical intent for the unchanged planning generation and RPMDB
cookie. Its libsolv pool stays primary-only. During refresh, verified filelists are streamed into
a checksum-bound compact path-to-package index with 256 independently authenticated bucket shards.
An absolute-path selector reads only its one shard, maps the path to package ordinals,
and adds one native `ONE_OF` selector to the resident solve. The solve never opens full filelists,
and the plan preserves the user's original absolute-path intent.

`repo makecache` obeys the trusted `metadata_expire` policy. Both `makecache` and explicit
`refresh` still fetch current `repomd.xml`; same-generation reuse additionally requires exact root
configuration, trust/authentication evidence, generation identity, policy/architecture, and the
current index schema. Payload bytes remain content addressed and are verified when opened; a
mismatch or corrupt binding fails closed and rebuilds off-path.
`history list/info` reports dnfast's verified durable journal and can also read the fixed,
root-owned DNF5 SQLite v1.1 history database through `--source dnf5|all` and `dnf5:ID`. The DNF5
view is bounded and read-only; dnfast does not import or mutate DNF5 state.

Checksum-bound comps group/environment list, info, install, and remove are implemented. Group install
selects mandatory/default packages, conditionals whose requirements are selected or installed,
and optional packages/groups only with `--with-optional`. A root-private durable schema-v2 record
separates group membership references from packages actually introduced by group transactions,
so group remove never deletes a pre-existing user package or one still referenced by another
installed group. Module list/info and
enable/reset/disable consume checksum-bound modulemd and exclude artifacts from inactive streams;
repositories without module metadata list no streams. `module install NAME[:STREAM]/PROFILE`
installs a profile only from the active/default stream; an explicitly inactive stream must first
be enabled.
Plugin, COPR, system-upgrade, offline, autoremove, downgrade, reinstall,
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
- `dnfast-dnf5-history`: bounded read-only DNF5 SQLite history view
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
