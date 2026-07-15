# dnfast

`dnfast` is an independent Fedora RPM package manager. It reads rpm-md repositories, resolves
transactions directly with libsolv, downloads and verifies selected RPMs, and executes approved
transactions directly with librpm. It does not invoke DNF or DNF5 to solve or apply transactions.

The implemented command surface is deliberately smaller than DNF5:

```bash
dnfast doctor
dnfast repo list
sudo dnfast repo refresh --repo fedora
sudo dnfast search bash
sudo dnfast plan install bash --output /var/lib/dnfast/bash-plan.json
sudo dnfast apply /var/lib/dnfast/bash-plan.json --assumeyes
sudo dnfast install bash --assumeyes
sudo dnfast remove bash --assumeyes
sudo dnfast upgrade --assumeyes
sudo dnfast daemon status
sudo dnfast daemon warm --repo fedora
```

`repo refresh` and package-changing commands require root. `plan` writes a solved, reviewable,
canonical plan to the mandatory absolute `--output` path. Plans are bound to the exact RPMDB,
metadata, repository policy, package digests, and trust material and expire after five minutes.
The convenience mutation commands normally use the root-only `dnfastd` service. The daemon keeps
one libsolv pool resident, returns the exact solved action set for approval, and accepts an
approval token only on the same connection and unchanged RPMDB/repository generation. If the
socket is genuinely absent or refusing connections, the CLI retains the fixed-executor path as a
safe compatibility fallback; protocol and integrity failures never fall back. Root `plan` also
uses the resident solve when the service is available.

Install `dnfastd` at `/usr/libexec/dnfastd`, install
[`packaging/dnfastd.service`](packaging/dnfastd.service) as a system service, and enable it before
benchmarking the resident path. `dnfast daemon status` reports protocol readiness, while
`dnfast daemon warm` loads the exact selected repository generation outside a timed mutation.

Group, environment, module, plugin, COPR, system-upgrade, offline, autoremove, downgrade,
reinstall, distro-sync, advisory, and history commands are not implemented and fail closed.
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
