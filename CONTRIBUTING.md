# Contributing to dnfast

`dnfast` changes the system RPM database as root. Correctness, preserved evidence, and fail-closed
behavior take priority over performance or feature breadth.

Before changing repository parsing, metadata verification, solver inputs, cache publication, trust,
or RPM transactions, read [`docs/architecture.md`](docs/architecture.md) and
[`docs/safety.md`](docs/safety.md).

## Development baseline

The currently verified native baseline is Fedora 44 x86_64 with libsolv 0.7.39, RPM 6.0.1, and
libmodulemd 2.15.2 or newer. Install the native development packages described in the README, then
run:

```bash
cargo fmt --all -- --check
DNFAST_NATIVE_REAL=1 cargo check --locked --workspace --all-targets
DNFAST_NATIVE_REAL=1 cargo clippy --locked --workspace --all-targets -- -D warnings
DNFAST_NATIVE_REAL=1 cargo test --locked --workspace --all-targets -- --test-threads=1
```

Do not discard failing logs. Report skipped or ignored tests explicitly and keep benchmark inputs,
execution order, raw measurements, and integrity receipts with performance changes.

## Contributions and provenance

The repository history begins from the imported source described in
[`IMPORT_PROVENANCE.md`](IMPORT_PROVENANCE.md); it is not an upstream lineage reconstruction. Only
submit work that you have the right to license under `GPL-2.0-or-later`.

Disclose substantial AI assistance with an `Assisted-by:` trailer. The human contributor remains
responsible for the complete change, its licensing, its tests, and its safety properties.
